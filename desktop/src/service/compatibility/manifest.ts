import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import type { BundleReport } from '../../shared/contracts';
import { FoundationError } from './errors';
import { parseJsonBytes } from './json';
import { loadSchemaRegistry, MAX_SCHEMA_BYTES } from './schema';

const MAX_MANIFEST_BYTES = 1024 * 1024;
const STATES = new Set(['observed', 'imported', 'static_passed', 'hall_passed', 'flows_passed', 'quarantined']);
const IDENTITY_FIELDS = ['platform', 'channel', 'architecture', 'app_version', 'resource_version'] as const;
const IDENTITY_PLACEHOLDERS = new Set([
    'unknown', 'unverified', 'n/a', 'na', 'not applicable', 'none', 'null',
    'unset', 'not set', 'not_set', 'not-set', 'tbd', 'todo'
]);
const REQUIRED_ROLES = [
    'schema', 'protocol_overlay', 'runtime_lock', 'content', 'seed', 'login_plan',
    'client_exe', 'client_sdk', 'client_index', 'client_scripts'
] as const;
const TUPLE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ROLE_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const SHA256 = /^[0-9a-fA-F]{64}$/;
const RESERVED_WINDOWS_NAMES = new Set([
    'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
    ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
    ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`)
]);

interface ArtifactEntry {
    readonly role: string;
    readonly root: 'server' | 'client';
    readonly path: string;
    readonly sha256: string;
}

interface HashResult {
    readonly sha256: string;
    readonly bytes?: Buffer;
    readonly byteLength: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function manifestInvalid(detail: string): FoundationError {
    return new FoundationError('MANIFEST_INVALID', detail);
}

function errorCode(error: unknown): string | undefined {
    return isRecord(error) && typeof error.code === 'string' ? error.code : undefined;
}

function pathIsWithin(root: string, candidate: string): boolean {
    const relative = path.relative(root, candidate);
    return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function ensureWithin(root: string, candidate: string, code: string, label: string): void {
    const relative = path.relative(root, candidate);
    if (!pathIsWithin(root, candidate)) {
        throw new FoundationError(code, `${label} resolves outside its allowed root`);
    }
    if (!relative) {
        throw new FoundationError(code, `${label} must name a file below its allowed root`);
    }
}

function safePathComponents(value: unknown): string[] {
    if (typeof value !== 'string' || !value || value.includes('\0')) {
        throw new FoundationError('ARTIFACT_PATH_UNSAFE', 'artifact path must be a non-empty relative path');
    }
    if (value.startsWith('/') || value.startsWith('\\') || path.win32.isAbsolute(value)
        || /^[A-Za-z]:/.test(value) || value.includes(':')) {
        throw new FoundationError('ARTIFACT_PATH_UNSAFE', `absolute, UNC, drive, and ADS paths are forbidden: ${JSON.stringify(value)}`);
    }

    const components = value.split(/[\\/]/);
    if (components.some(component => !component || component === '.' || component === '..')) {
        throw new FoundationError('ARTIFACT_PATH_UNSAFE', `empty or traversal path components are forbidden: ${JSON.stringify(value)}`);
    }
    for (const component of components) {
        if (/[\x00-\x1f<>"|?*]/.test(component) || component.endsWith('.') || component.endsWith(' ')) {
            throw new FoundationError('ARTIFACT_PATH_UNSAFE', `invalid Windows path component in ${JSON.stringify(value)}`);
        }
        const deviceName = component.split('.', 1)[0].toUpperCase();
        if (RESERVED_WINDOWS_NAMES.has(deviceName)) {
            throw new FoundationError('ARTIFACT_PATH_UNSAFE', `reserved Windows device name in ${JSON.stringify(value)}`);
        }
    }
    return components;
}

function parseIdentity(value: unknown, state: string): { complete: boolean; missing: string[] } {
    if (!isRecord(value)) {
        throw manifestInvalid('identity must be an object');
    }
    const missing: string[] = [];
    for (const field of IDENTITY_FIELDS) {
        const current = value[field];
        if (current === undefined || current === null || (typeof current === 'string'
            && (!current.trim() || IDENTITY_PLACEHOLDERS.has(current.trim().toLowerCase())))) {
            missing.push(field);
        } else if (typeof current !== 'string') {
            throw manifestInvalid(`identity.${field} must be a string or null`);
        }
    }
    if (state !== 'observed' && missing.length) {
        throw manifestInvalid(`identity is incomplete for state ${JSON.stringify(state)}: ${missing.join(', ')}`);
    }
    return { complete: missing.length === 0, missing };
}

function parseArtifact(value: unknown, index: number, seenRoles: Set<string>): ArtifactEntry {
    const label = `artifacts[${index}]`;
    if (!isRecord(value)) {
        throw manifestInvalid(`${label} must be an object`);
    }
    const { role, root, path: artifactPath, sha256 } = value;
    if (typeof role !== 'string' || !ROLE_NAME.test(role)) {
        throw manifestInvalid(`${label}.role must be a safe role identifier`);
    }
    if (seenRoles.has(role)) {
        throw manifestInvalid(`duplicate artifact role ${JSON.stringify(role)}`);
    }
    seenRoles.add(role);

    if (root !== 'server' && root !== 'client') {
        throw manifestInvalid(`${label}.root must be 'server' or 'client'`);
    }
    const expectedRoot = role.startsWith('client_') ? 'client' : 'server';
    if (root !== expectedRoot) {
        throw manifestInvalid(`${label} role ${JSON.stringify(role)} must use the ${expectedRoot} root`);
    }
    const components = safePathComponents(artifactPath);
    if (typeof sha256 !== 'string' || !SHA256.test(sha256)) {
        throw manifestInvalid(`${label}.sha256 must contain 64 hexadecimal characters`);
    }
    return Object.freeze({ role, root, path: components.join('/'), sha256: sha256.toLowerCase() });
}

async function resolveBundleRoot(directory: string): Promise<string> {
    if (typeof directory !== 'string' || !directory.trim() || directory.includes('\0') || directory.length > 4096) {
        throw manifestInvalid('bundle directory must be a non-empty path of at most 4096 characters');
    }
    try {
        const resolved = await realpath(path.resolve(directory));
        const details = await stat(resolved);
        if (!details.isDirectory()) {
            throw manifestInvalid('bundle path is not a directory');
        }
        return resolved;
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        if (errorCode(error) === 'ENOENT') {
            throw new FoundationError('BUNDLE_MISSING', 'bundle directory does not exist');
        }
        throw new FoundationError('BUNDLE_READ_FAILED', `cannot resolve bundle directory: ${messageOf(error)}`);
    }
}

async function resolveManifest(bundleRoot: string): Promise<string> {
    const manifestPath = path.resolve(bundleRoot, 'manifest.json');
    let resolved: string;
    try {
        resolved = await realpath(manifestPath);
    } catch (error) {
        if (errorCode(error) === 'ENOENT') {
            throw new FoundationError('MANIFEST_MISSING', 'manifest.json was not found in the bundle directory');
        }
        throw new FoundationError('MANIFEST_READ_FAILED', `cannot resolve manifest.json: ${messageOf(error)}`);
    }
    ensureWithin(bundleRoot, resolved, 'MANIFEST_PATH_UNSAFE', 'manifest.json');
    return resolved;
}

async function readManifestBytes(filePath: string): Promise<Buffer> {
    try {
        const details = await stat(filePath);
        if (!details.isFile()) {
            throw new FoundationError('MANIFEST_INVALID', 'manifest.json is not a regular file');
        }
        if (details.size > MAX_MANIFEST_BYTES) {
            throw new FoundationError('MANIFEST_INVALID', `manifest.json exceeds the ${MAX_MANIFEST_BYTES}-byte limit`);
        }

        const chunks: Buffer[] = [];
        let byteLength = 0;
        for await (const rawChunk of createReadStream(filePath, { highWaterMark: 64 * 1024 })) {
            const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
            byteLength += chunk.byteLength;
            if (byteLength > MAX_MANIFEST_BYTES) {
                throw new FoundationError('MANIFEST_INVALID', `manifest.json exceeds the ${MAX_MANIFEST_BYTES}-byte limit`);
            }
            chunks.push(chunk);
        }
        return Buffer.concat(chunks, byteLength);
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        if (errorCode(error) === 'ENOENT') {
            throw new FoundationError('MANIFEST_MISSING', 'manifest.json is missing');
        }
        throw new FoundationError('MANIFEST_READ_FAILED', `cannot read manifest.json: ${messageOf(error)}`);
    }
}

async function resolveArtifactPath(
    bundleRoot: string,
    entry: ArtifactEntry
): Promise<string> {
    const configuredRoot = path.resolve(bundleRoot, entry.root);
    let resolvedRoot: string;
    try {
        resolvedRoot = await realpath(configuredRoot);
    } catch (error) {
        if (errorCode(error) === 'ENOENT') {
            throw new FoundationError('ARTIFACT_ROOT_MISSING', `${entry.root} artifact root is missing`);
        }
        throw new FoundationError('ARTIFACT_ROOT_READ_FAILED', `cannot resolve ${entry.root} root: ${messageOf(error)}`);
    }
    ensureWithin(bundleRoot, resolvedRoot, 'ARTIFACT_ROOT_UNSAFE', `${entry.root} artifact root`);
    try {
        if (!(await stat(resolvedRoot)).isDirectory()) {
            throw new FoundationError('ARTIFACT_ROOT_INVALID', `${entry.root} artifact root is not a directory`);
        }
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        throw new FoundationError('ARTIFACT_ROOT_READ_FAILED', `cannot inspect ${entry.root} root: ${messageOf(error)}`);
    }

    const candidate = path.resolve(resolvedRoot, ...entry.path.split('/'));
    let resolvedCandidate: string;
    try {
        resolvedCandidate = await realpath(candidate);
    } catch (error) {
        if (errorCode(error) === 'ENOENT') {
            throw new FoundationError('ARTIFACT_MISSING', `${entry.role} artifact is missing`);
        }
        throw new FoundationError('ARTIFACT_READ_FAILED', `cannot resolve ${entry.role} artifact: ${messageOf(error)}`);
    }
    ensureWithin(resolvedRoot, resolvedCandidate, 'ARTIFACT_PATH_UNSAFE', `${entry.role} artifact`);
    try {
        if (!(await stat(resolvedCandidate)).isFile()) {
            throw new FoundationError('ARTIFACT_NOT_FILE', `${entry.role} artifact is not a regular file`);
        }
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        throw new FoundationError('ARTIFACT_READ_FAILED', `cannot inspect ${entry.role} artifact: ${messageOf(error)}`);
    }
    return resolvedCandidate;
}

async function hashFile(filePath: string, captureLimit?: number): Promise<HashResult> {
    const digest = createHash('sha256');
    const chunks: Buffer[] = [];
    let byteLength = 0;
    try {
        for await (const rawChunk of createReadStream(filePath)) {
            const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
            byteLength += chunk.byteLength;
            if (captureLimit !== undefined && byteLength > captureLimit) {
                throw new FoundationError('SCHEMA_INVALID', `schema exceeds the ${captureLimit}-byte limit`);
            }
            digest.update(chunk);
            if (captureLimit !== undefined) {
                chunks.push(chunk);
            }
        }
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        throw new FoundationError('ARTIFACT_READ_FAILED', `cannot hash artifact: ${messageOf(error)}`);
    }
    return {
        sha256: digest.digest('hex'),
        byteLength,
        ...(captureLimit === undefined ? {} : { bytes: Buffer.concat(chunks, byteLength) })
    };
}

function messageOf(error: unknown): string {
    return error instanceof Error ? error.message : 'unknown filesystem error';
}

interface ParsedManifest {
    readonly tuple_id: string;
    readonly state: string;
    readonly identity: unknown;
    readonly capabilities: { readonly hall: 'unverified' | 'passed' };
    readonly artifacts: unknown[];
}

function parseManifest(bytes: Buffer): ParsedManifest {
    const value = parseJsonBytes(bytes, 'MANIFEST_INVALID', 'manifest');
    if (!isRecord(value)) {
        throw manifestInvalid('manifest root must be an object');
    }
    if (typeof value.manifest_version !== 'number' || !Number.isInteger(value.manifest_version)
        || value.manifest_version !== 1) {
        throw manifestInvalid('manifest_version must be integer 1');
    }
    const tupleId = value.tuple_id;
    if (typeof tupleId !== 'string' || !TUPLE_ID.test(tupleId)) {
        throw manifestInvalid('tuple_id must be a safe identifier of at most 64 characters');
    }
    const state = value.state;
    if (typeof state !== 'string' || !STATES.has(state)) {
        throw manifestInvalid('state is not a supported manifest v1 state');
    }
    const capabilities = value.capabilities;
    if (!isRecord(capabilities)
        || (capabilities.hall !== 'unverified' && capabilities.hall !== 'passed')) {
        throw manifestInvalid("capabilities.hall must be 'unverified' or 'passed'");
    }
    const artifacts = value.artifacts;
    if (!Array.isArray(artifacts)) {
        throw manifestInvalid('artifacts must be an array');
    }
    return {
        tuple_id: tupleId,
        state,
        identity: value.identity,
        capabilities: { hall: capabilities.hall },
        artifacts
    };
}

export async function inspectBundle(directory: string): Promise<BundleReport> {
    const bundleRoot = await resolveBundleRoot(directory);
    const manifestPath = await resolveManifest(bundleRoot);
    const manifestBytes = await readManifestBytes(manifestPath);
    const manifest = parseManifest(manifestBytes);
    const tupleId = manifest.tuple_id as string;
    const state = manifest.state as string;
    const identity = parseIdentity(manifest.identity, state);
    const capabilities = manifest.capabilities as Record<string, unknown>;
    const hallCapability = capabilities.hall as 'unverified' | 'passed';

    const seenRoles = new Set<string>();
    const entries = manifest.artifacts.map((artifact, index) => parseArtifact(artifact, index, seenRoles));
    const verifiedRoles = new Set<string>();
    let artifactsVerified = 0;
    let schema: BundleReport['schema'] = null;

    for (const entry of entries) {
        const absolutePath = await resolveArtifactPath(bundleRoot, entry);
        const isSchema = entry.role === 'schema';
        const hash = await hashFile(absolutePath, isSchema ? MAX_SCHEMA_BYTES : undefined);
        if (hash.sha256 !== entry.sha256) {
            throw new FoundationError(
                'ARTIFACT_HASH_MISMATCH',
                `${entry.role} SHA-256 mismatch: expected ${entry.sha256}, got ${hash.sha256}`
            );
        }
        verifiedRoles.add(entry.role);
        artifactsVerified += 1;

        if (isSchema) {
            const registry = loadSchemaRegistry(hash.bytes as Buffer);
            schema = {
                sha256: registry.sha256,
                messages: registry.messageCount,
                fields: registry.fieldCount
            };
        }
    }

    const missingRoles = REQUIRED_ROLES.filter(role => !verifiedRoles.has(role));
    const manifestComplete = state !== 'observed'
        && state !== 'quarantined'
        && identity.complete
        && missingRoles.length === 0;
    const declaredHallPassed = (state === 'hall_passed' || state === 'flows_passed')
        && hallCapability === 'passed';
    const issues: string[] = [];
    if (identity.missing.length) {
        issues.push(`identity unknown or incomplete: ${identity.missing.join(', ')}`);
    }
    if (missingRoles.length) {
        issues.push(`runtime closure is incomplete: ${missingRoles.join(', ')}`);
    }
    if (state === 'observed') {
        issues.push('observed bundles are diagnostic only');
    } else if (state === 'quarantined') {
        issues.push('bundle is quarantined');
    } else if (state !== 'hall_passed' && state !== 'flows_passed') {
        issues.push(`state ${JSON.stringify(state)} has no declared hall pass`);
    }
    if (hallCapability !== 'passed') {
        issues.push('hall capability is unverified');
    }

    return {
        tupleId,
        state,
        artifactsVerified,
        manifestComplete,
        declaredHallPassed,
        businessReady: false,
        issues,
        schema
    };
}
