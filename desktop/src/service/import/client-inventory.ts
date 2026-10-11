import { constants, type BigIntStats } from 'node:fs';
import { createHash, type Hash } from 'node:crypto';
import { open, lstat, realpath, readdir } from 'node:fs/promises';
import path from 'node:path';
import type {
    ClientAssetHashCandidate,
    ClientInventory,
    ClientInventoryFile,
    ClientInventoryIdentity
} from '../../shared/client-contracts';
import { FoundationError } from '../compatibility/errors';
import { parseJsonBytes } from '../compatibility/json';

export type {
    ClientAssetHashCandidate,
    ClientInventory,
    ClientInventoryFile,
    ClientInventoryIdentity
} from '../../shared/client-contracts';

const MAX_INDEX_BYTES = 32 * 1024 * 1024;
const MAX_INDEX_ENTRIES = 250_000;
const MAX_ASSET_BYTES = 64 * 1024 ** 3;
const MAX_KEY_FILE_BYTES = 64 * 1024 ** 3;
const MAX_CANDIDATE_HEADER_BYTES = 1024 * 1024;
const MAX_CANDIDATE_COUNT = 64;
const MAX_CANDIDATE_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_ROOT_PATH_CHARS = 4096;
const MAX_LOGICAL_PATH_CHARS = 1024;
const MAX_PATH_COMPONENT_CHARS = 255;
const MAX_VERSION_NAME_CHARS = 128;
const MAX_JSON_DEPTH = 256;
const UINT32_MAX = 2_147_483_647;

const CORE_FILES = ['AetherGazer.exe', 'GameAssembly.dll', 'UnityPlayer.dll'] as const;
const INDEX_RELATIVE_PATH = 'AetherGazer_Data/StreamingAssets/Windows/AssetHash_Info.bytes';
const WINDOWS_RELATIVE_PATH = 'AetherGazer_Data/StreamingAssets/Windows';
const WINDOWS_DEVICE_NAMES = new Set([
    'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
    ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
    ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
    'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³'
]);

interface AssetHashEntry {
    readonly logicalName: string;
    readonly md5: string;
    readonly size: number;
}

interface ParsedClientIndex {
    readonly identity: ClientInventoryIdentity;
    readonly entries: readonly AssetHashEntry[];
    readonly scripts: AssetHashEntry & { readonly logicalName: 'scripts64' | 'scripts64.ys' };
}

interface SafeFileLocation {
    readonly absolutePath: string;
    readonly canonicalPath: string;
    readonly details: BigIntStats;
}

interface FileFingerprint extends ClientInventoryFile {
    readonly md5?: string;
    readonly bytes?: Buffer;
    readonly prefix?: Buffer;
}

interface IndexCandidateFilename {
    readonly appVersion: number;
    readonly buildCode: number;
    readonly md5: string;
}

function inventoryError(code: string, detail: string): FoundationError {
    return new FoundationError(code, detail);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string | undefined {
    return isRecord(error) && typeof error.code === 'string' ? error.code : undefined;
}

function messageOf(error: unknown): string {
    return error instanceof Error ? error.message : 'unknown filesystem error';
}

function pathIsWithin(root: string, candidate: string): boolean {
    const relative = path.relative(root, candidate);
    return relative !== ''
        && relative !== '..'
        && !relative.startsWith(`..${path.sep}`)
        && !path.isAbsolute(relative);
}

function ensureWithin(root: string, candidate: string, label: string): void {
    if (!pathIsWithin(root, candidate)) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} resolves outside the selected client root`);
    }
}

function isDeviceNamespace(value: string): boolean {
    const normalized = value.replaceAll('/', '\\');
    return normalized.startsWith('\\\\?\\')
        || normalized.startsWith('\\\\.\\')
        || normalized.startsWith('\\??\\')
        || /^\\Device\\/i.test(normalized);
}

function validateWindowsComponent(component: string, label: string): void {
    if (!component || component.length > MAX_PATH_COMPONENT_CHARS || component === '.' || component === '..') {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} contains an empty, traversal, or oversized path component`);
    }
    if (/[\x00-\x1f<>:"|?*]/.test(component) || component.endsWith('.') || component.endsWith(' ')) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} contains an invalid Windows path component`);
    }
    const deviceName = component.split('.', 1)[0].toUpperCase();
    if (WINDOWS_DEVICE_NAMES.has(deviceName)) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} contains a reserved Windows device name`);
    }
}

function safeRelativeComponents(value: string, label: string): string[] {
    if (!value || value.length > MAX_LOGICAL_PATH_CHARS || value.includes('\0')) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} must be a bounded relative path`);
    }
    if (value.startsWith('/') || value.startsWith('\\') || value.includes(':')
        || path.isAbsolute(value) || path.win32.isAbsolute(value) || isDeviceNamespace(value)) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} cannot be absolute, a device path, or an ADS path`);
    }

    const components = value.split(/[\\/]/);
    if (components.length > 64) {
        throw inventoryError('CLIENT_PATH_UNSAFE', `${label} has too many path components`);
    }
    for (const component of components) {
        validateWindowsComponent(component, label);
    }
    return components;
}

function reportPath(root: string, absolutePath: string): string {
    return path.relative(root, absolutePath).split(path.sep).join('/');
}

function isSameCanonicalPath(left: string, right: string): boolean {
    const normalizedLeft = path.resolve(left);
    const normalizedRight = path.resolve(right);
    return process.platform === 'win32'
        ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
        : normalizedLeft === normalizedRight;
}

function sameStatSnapshot(left: BigIntStats, right: BigIntStats): boolean {
    // mtime and ctime are used only to detect changes during hashing, never to pick a version.
    return left.dev === right.dev
        && left.ino === right.ino
        && left.mode === right.mode
        && left.nlink === right.nlink
        && left.size === right.size
        && left.mtimeNs === right.mtimeNs
        && left.ctimeNs === right.ctimeNs
        && left.birthtimeNs === right.birthtimeNs;
}

function sameIdentity(left: ClientInventoryIdentity, right: ClientInventoryIdentity): boolean {
    return left.buildCode === right.buildCode
        && left.appVersion === right.appVersion
        && left.channel === right.channel
        && left.versionName === right.versionName;
}

function validateIdentityValue(value: unknown, label: string): ClientInventoryIdentity {
    if (!isRecord(value)) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} must be a JSON object`);
    }
    const buildCode = value.buildCode;
    const appVersion = value.appVersion;
    const channel = value.channel;
    const versionName = value.versionName;

    for (const [field, current] of [
        ['buildCode', buildCode],
        ['appVersion', appVersion],
        ['channel', channel]
    ] as const) {
        if (typeof current !== 'number' || !Number.isSafeInteger(current) || current < 0 || current > UINT32_MAX) {
            throw inventoryError('CLIENT_INDEX_INVALID', `${label}.${field} must be a bounded non-negative integer`);
        }
    }
    if (typeof versionName !== 'string' || !versionName.trim()
        || versionName.length > MAX_VERSION_NAME_CHARS || /[\x00-\x1f]/.test(versionName)) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label}.versionName must be a bounded non-empty string`);
    }

    return Object.freeze({
        buildCode: buildCode as number,
        appVersion: appVersion as number,
        channel: channel as number,
        versionName
    });
}

function parseAssetHashEntry(value: unknown, index: number): AssetHashEntry {
    const label = `AssetHash_Info.bytes assetHashList[${index}]`;
    if (typeof value !== 'string' || value.length > MAX_LOGICAL_PATH_CHARS + 64) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} must be a bounded string`);
    }
    const firstSeparator = value.indexOf('|');
    const secondSeparator = firstSeparator >= 0 ? value.indexOf('|', firstSeparator + 1) : -1;
    if (firstSeparator < 1 || secondSeparator <= firstSeparator + 1
        || value.indexOf('|', secondSeparator + 1) !== -1) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} must use logicalName|md5|size format`);
    }

    const logicalName = value.slice(0, firstSeparator);
    safeRelativeComponents(logicalName, `${label} logical name`);
    const md5 = value.slice(firstSeparator + 1, secondSeparator);
    if (!/^[0-9a-fA-F]{32}$/.test(md5)) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} md5 must contain 32 hexadecimal characters`);
    }

    const sizeText = value.slice(secondSeparator + 1);
    if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} size must be a decimal integer`);
    }
    let size: bigint;
    try {
        size = BigInt(sizeText);
    } catch {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} size is invalid`);
    }
    if (size < 1n || size > BigInt(MAX_ASSET_BYTES)) {
        throw inventoryError('CLIENT_INDEX_INVALID', `${label} size must be between 1 and ${MAX_ASSET_BYTES}`);
    }

    return Object.freeze({ logicalName, md5: md5.toLowerCase(), size: Number(size) });
}

function parseClientIndex(bytes: Buffer): ParsedClientIndex {
    const document = parseJsonBytes(bytes, 'CLIENT_INDEX_INVALID', 'AssetHash_Info.bytes');
    if (!isRecord(document)) {
        throw inventoryError('CLIENT_INDEX_INVALID', 'AssetHash_Info.bytes root must be a JSON object');
    }
    const identity = validateIdentityValue(document, 'AssetHash_Info.bytes');
    const rawEntries = document.assetHashList;
    if (!Array.isArray(rawEntries)) {
        throw inventoryError('CLIENT_INDEX_INVALID', 'AssetHash_Info.bytes assetHashList must be an array');
    }
    if (rawEntries.length === 0 || rawEntries.length > MAX_INDEX_ENTRIES) {
        throw inventoryError('CLIENT_INDEX_INVALID', `AssetHash_Info.bytes assetHashList must contain 1-${MAX_INDEX_ENTRIES} entries`);
    }

    const names = new Set<string>();
    const entries = rawEntries.map((entry, index) => {
        const parsed = parseAssetHashEntry(entry, index);
        const normalizedName = parsed.logicalName.replaceAll('\\', '/').toLowerCase();
        if (names.has(normalizedName)) {
            throw inventoryError('CLIENT_INDEX_INVALID', `duplicate logical asset name ${JSON.stringify(parsed.logicalName)}`);
        }
        names.add(normalizedName);
        return parsed;
    });

    const scriptsEntries = entries.filter(entry => entry.logicalName === 'scripts64' || entry.logicalName === 'scripts64.ys');
    if (scriptsEntries.length !== 1) {
        throw inventoryError(
            'CLIENT_INDEX_INVALID',
            `AssetHash_Info.bytes must define exactly one scripts64 or scripts64.ys entry; found ${scriptsEntries.length}`
        );
    }
    const scripts = scriptsEntries[0];
    if (!scripts) {
        throw inventoryError('CLIENT_INDEX_INVALID', 'scripts64 index entry is missing');
    }

    return {
        identity,
        entries: Object.freeze(entries),
        scripts: scripts as ParsedClientIndex['scripts']
    };
}

async function resolveClientRoot(root: string): Promise<string> {
    if (typeof root !== 'string' || !root.trim() || root.includes('\0') || root.length > MAX_ROOT_PATH_CHARS) {
        throw inventoryError('CLIENT_ROOT_INVALID', `client root must be a non-empty path of at most ${MAX_ROOT_PATH_CHARS} characters`);
    }
    if (isDeviceNamespace(root)) {
        throw inventoryError('CLIENT_ROOT_INVALID', 'Windows device namespace paths are not supported as client roots');
    }

    let canonicalRoot: string;
    try {
        canonicalRoot = await realpath(path.resolve(root));
    } catch (error) {
        if (errorCode(error) === 'ENOENT') {
            throw inventoryError('CLIENT_ROOT_MISSING', 'client root does not exist');
        }
        throw inventoryError('CLIENT_ROOT_READ_FAILED', `cannot resolve client root: ${messageOf(error)}`);
    }
    try {
        const details = await lstat(canonicalRoot, { bigint: true });
        if (details.isSymbolicLink() || !details.isDirectory()) {
            throw inventoryError('CLIENT_ROOT_INVALID', 'client root must resolve to a regular directory');
        }
        return canonicalRoot;
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        throw inventoryError('CLIENT_ROOT_READ_FAILED', `cannot inspect client root: ${messageOf(error)}`);
    }
}

async function inspectSafeFile(root: string, relativePath: string): Promise<SafeFileLocation> {
    const components = safeRelativeComponents(relativePath, 'client file path');
    let current = root;

    try {
        for (let index = 0; index < components.length; index += 1) {
            const component = components[index];
            if (!component) {
                throw inventoryError('CLIENT_PATH_UNSAFE', 'client file path has an empty component');
            }
            current = path.resolve(current, component);
            ensureWithin(root, current, relativePath);
            const details = await lstat(current, { bigint: true });
            if (details.isSymbolicLink()) {
                throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} traverses a symbolic link or reparse point`);
            }
            const isFinal = index === components.length - 1;
            if (isFinal ? !details.isFile() : !details.isDirectory()) {
                throw inventoryError(
                    isFinal ? 'CLIENT_FILE_INVALID' : 'CLIENT_PATH_UNSAFE',
                    isFinal ? `${relativePath} is not a regular file` : `${relativePath} traverses a non-directory component`
                );
            }
            if (isFinal && details.nlink > 1n) {
                throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} is a hard-linked file`);
            }
            const resolved = await realpath(current);
            ensureWithin(root, resolved, relativePath);
            if (isFinal) {
                return { absolutePath: current, canonicalPath: resolved, details };
            }
        }
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        if (errorCode(error) === 'ENOENT') {
            throw inventoryError('CLIENT_FILE_MISSING', `${relativePath} is missing`);
        }
        if (['ELOOP', 'EMLINK'].includes(errorCode(error) ?? '')) {
            throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} resolves through a link`);
        }
        throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot inspect ${relativePath}: ${messageOf(error)}`);
    }

    throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} does not resolve to a file`);
}

async function inspectSafeDirectory(root: string, relativePath: string): Promise<{
    readonly absolutePath: string;
    readonly canonicalPath: string;
    readonly details: BigIntStats;
}> {
    const components = safeRelativeComponents(relativePath, 'client directory path');
    let current = root;

    try {
        for (let index = 0; index < components.length; index += 1) {
            const component = components[index];
            if (!component) {
                throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} contains an empty component`);
            }
            current = path.resolve(current, component);
            ensureWithin(root, current, relativePath);
            const details = await lstat(current, { bigint: true });
            if (details.isSymbolicLink() || !details.isDirectory()) {
                throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} contains a link or non-directory component`);
            }
            const resolved = await realpath(current);
            ensureWithin(root, resolved, relativePath);
            if (index === components.length - 1) {
                return { absolutePath: current, canonicalPath: resolved, details };
            }
        }
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        if (errorCode(error) === 'ENOENT') {
            throw inventoryError('CLIENT_FILE_MISSING', `${relativePath} is missing`);
        }
        if (['ELOOP', 'EMLINK'].includes(errorCode(error) ?? '')) {
            throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} resolves through a link`);
        }
        throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot inspect ${relativePath}: ${messageOf(error)}`);
    }

    throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} does not resolve to a directory`);
}

function updateCapture(
    captureChunks: Buffer[],
    chunk: Buffer,
    capturedBytes: number,
    captureAll: boolean,
    capturePrefixBytes?: number
): number {
    if (captureAll) {
        captureChunks.push(chunk);
        return capturedBytes + chunk.byteLength;
    }
    if (capturePrefixBytes === undefined || capturedBytes >= capturePrefixBytes) {
        return capturedBytes;
    }
    const remaining = capturePrefixBytes - capturedBytes;
    captureChunks.push(chunk.subarray(0, Math.min(chunk.byteLength, remaining)));
    return capturedBytes + Math.min(chunk.byteLength, remaining);
}

async function fingerprintFile(
    root: string,
    relativePath: string,
    options: {
        readonly maxBytes: number;
        readonly includeMd5?: boolean;
        readonly captureAll?: boolean;
        readonly capturePrefixBytes?: number;
        readonly expectedSize?: number;
    }
): Promise<FileFingerprint> {
    const location = await inspectSafeFile(root, relativePath);
    if (location.details.size > BigInt(options.maxBytes)) {
        throw inventoryError('CLIENT_FILE_TOO_LARGE', `${relativePath} exceeds the ${options.maxBytes}-byte limit`);
    }
    if (options.expectedSize !== undefined && location.details.size !== BigInt(options.expectedSize)) {
        throw inventoryError('CLIENT_RESOURCE_SIZE_MISMATCH', `${relativePath} size does not match AssetHash_Info.bytes`);
    }

    const noFollow = process.platform === 'win32'
        ? 0
        : ((constants as unknown as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0);
    let handle;
    try {
        handle = await open(location.absolutePath, constants.O_RDONLY | noFollow);
    } catch (error) {
        if (['ELOOP', 'EMLINK'].includes(errorCode(error) ?? '')) {
            throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} resolves through a link`);
        }
        if (errorCode(error) === 'ENOENT') {
            throw inventoryError('CLIENT_FILE_MISSING', `${relativePath} is missing`);
        }
        throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot open ${relativePath}: ${messageOf(error)}`);
    }

    try {
        const before = await handle.stat({ bigint: true });
        if (!before.isFile() || before.nlink > 1n || !sameStatSnapshot(location.details, before)) {
            throw inventoryError('CLIENT_PATH_UNSAFE', `${relativePath} changed or became linked before hashing`);
        }
        if (before.size > BigInt(options.maxBytes)) {
            throw inventoryError('CLIENT_FILE_TOO_LARGE', `${relativePath} exceeds the ${options.maxBytes}-byte limit`);
        }
        if (options.expectedSize !== undefined && before.size !== BigInt(options.expectedSize)) {
            throw inventoryError('CLIENT_RESOURCE_SIZE_MISMATCH', `${relativePath} size does not match AssetHash_Info.bytes`);
        }

        const sha256: Hash = createHash('sha256');
        const md5: Hash | undefined = options.includeMd5 ? createHash('md5') : undefined;
        const captureChunks: Buffer[] = [];
        let capturedBytes = 0;
        let byteLength = 0;
        const stream = handle.createReadStream({ autoClose: false, highWaterMark: 64 * 1024 });
        try {
            for await (const rawChunk of stream) {
                const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
                byteLength += chunk.byteLength;
                if (byteLength > options.maxBytes) {
                    throw inventoryError('CLIENT_FILE_TOO_LARGE', `${relativePath} exceeds the ${options.maxBytes}-byte limit`);
                }
                sha256.update(chunk);
                md5?.update(chunk);
                capturedBytes = updateCapture(
                    captureChunks,
                    chunk,
                    capturedBytes,
                    options.captureAll ?? false,
                    options.capturePrefixBytes
                );
            }
        } catch (error) {
            stream.destroy();
            if (error instanceof FoundationError) {
                throw error;
            }
            throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot hash ${relativePath}: ${messageOf(error)}`);
        }

        const afterHandle = await handle.stat({ bigint: true });
        const afterLocation = await inspectSafeFile(root, relativePath);
        if (!sameStatSnapshot(before, afterHandle)
            || !sameStatSnapshot(before, afterLocation.details)
            || !isSameCanonicalPath(location.canonicalPath, afterLocation.canonicalPath)
            || byteLength !== Number(before.size)) {
            throw inventoryError('CLIENT_FILE_CHANGED', `${relativePath} changed while it was being hashed`);
        }

        return {
            path: relativePath,
            size: byteLength,
            sha256: sha256.digest('hex'),
            ...(md5 ? { md5: md5.digest('hex') } : {}),
            ...(options.captureAll ? { bytes: Buffer.concat(captureChunks, capturedBytes) } : {}),
            ...(options.capturePrefixBytes !== undefined ? { prefix: Buffer.concat(captureChunks, capturedBytes) } : {})
        };
    } catch (error) {
        if (error instanceof FoundationError) {
            throw error;
        }
        throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot fingerprint ${relativePath}: ${messageOf(error)}`);
    } finally {
        await handle.close().catch(() => undefined);
    }
}

class JsonHeaderReader {
    private cursor = 0;

    constructor(private readonly text: string) {}

    readIndexIdentity(): ClientInventoryIdentity {
        this.skipWhitespace();
        this.expect('{', 'index header must begin with an object');
        const rootKeys = new Set<string>();
        const identityFields: Record<string, unknown> = {};

        while (true) {
            this.skipWhitespace();
            if (this.peek() === '}') {
                throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header is missing assetHashList');
            }
            const key = this.readString();
            if (rootKeys.has(key)) {
                throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header has duplicate property ${JSON.stringify(key)}`);
            }
            rootKeys.add(key);
            this.skipWhitespace();
            this.expect(':', 'index header property must be followed by a colon');
            this.skipWhitespace();

            if (key === 'assetHashList') {
                this.expect('[', 'index header assetHashList must be an array');
                return validateCandidateIdentity(identityFields);
            }

            const valueStart = this.cursor;
            this.skipValue(0);
            if (key === 'buildCode' || key === 'appVersion' || key === 'channel' || key === 'versionName') {
                try {
                    identityFields[key] = JSON.parse(this.text.slice(valueStart, this.cursor)) as unknown;
                } catch (error) {
                    throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header ${key} is invalid: ${messageOf(error)}`);
                }
            }

            this.skipWhitespace();
            const separator = this.peek();
            if (separator === ',') {
                this.cursor += 1;
                continue;
            }
            if (separator === '}') {
                throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header is missing assetHashList');
            }
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header has invalid object syntax');
        }
    }

    private skipValue(depth: number): void {
        if (depth > MAX_JSON_DEPTH) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header nesting exceeds ${MAX_JSON_DEPTH}`);
        }
        this.skipWhitespace();
        const current = this.peek();
        if (current === '"') {
            this.readString();
            return;
        }
        if (current === '{') {
            this.cursor += 1;
            this.skipWhitespace();
            if (this.peek() === '}') {
                this.cursor += 1;
                return;
            }
            const keys = new Set<string>();
            while (true) {
                this.skipWhitespace();
                const key = this.readString();
                if (keys.has(key)) {
                    throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header has duplicate nested property ${JSON.stringify(key)}`);
                }
                keys.add(key);
                this.skipWhitespace();
                this.expect(':', 'index header object property must be followed by a colon');
                this.skipValue(depth + 1);
                this.skipWhitespace();
                const separator = this.peek();
                if (separator === '}') {
                    this.cursor += 1;
                    return;
                }
                this.expect(',', 'index header object has invalid syntax');
            }
        }
        if (current === '[') {
            this.cursor += 1;
            this.skipWhitespace();
            if (this.peek() === ']') {
                this.cursor += 1;
                return;
            }
            while (true) {
                this.skipValue(depth + 1);
                this.skipWhitespace();
                if (this.peek() === ']') {
                    this.cursor += 1;
                    return;
                }
                this.expect(',', 'index header array has invalid syntax');
            }
        }

        const scalarStart = this.cursor;
        const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(this.text.slice(this.cursor));
        if (!match) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header has an invalid JSON value');
        }
        this.cursor += match[0].length;
        try {
            JSON.parse(this.text.slice(scalarStart, this.cursor));
        } catch (error) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header scalar is invalid: ${messageOf(error)}`);
        }
    }

    private readString(): string {
        if (this.peek() !== '"') {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header expected a JSON string');
        }
        const start = this.cursor;
        this.cursor += 1;
        while (this.cursor < this.text.length) {
            const character = this.text[this.cursor];
            this.cursor += 1;
            if (character === '\\') {
                if (this.cursor >= this.text.length) {
                    break;
                }
                this.cursor += 1;
            } else if (character === '"') {
                try {
                    return JSON.parse(this.text.slice(start, this.cursor)) as string;
                } catch (error) {
                    throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index header string is invalid: ${messageOf(error)}`);
                }
            }
        }
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index header contains an unterminated string');
    }

    private skipWhitespace(): void {
        while (this.cursor < this.text.length && /[\t\n\r ]/.test(this.text[this.cursor] ?? '')) {
            this.cursor += 1;
        }
    }

    private peek(): string | undefined {
        return this.text[this.cursor];
    }

    private expect(character: string, detail: string): void {
        if (this.peek() !== character) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', detail);
        }
        this.cursor += 1;
    }
}

function validateCandidateIdentity(value: unknown): ClientInventoryIdentity {
    if (!isRecord(value)) {
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', 'index identity header must be an object');
    }
    try {
        return validateIdentityValue(value, 'index candidate');
    } catch (error) {
        if (error instanceof FoundationError) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', error.detail);
        }
        throw error;
    }
}

function parseCandidateHeader(prefix: Buffer): ClientInventoryIdentity {
    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(prefix, { stream: true });
    } catch (error) {
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `index candidate header is not valid UTF-8: ${messageOf(error)}`);
    }
    return new JsonHeaderReader(text).readIndexIdentity();
}

function parseCandidateFilename(name: string): IndexCandidateFilename {
    const match = /^assethash_(0|[1-9][0-9]{0,9})_(0|[1-9][0-9]{0,9})_([0-9a-f]{32})\.bytes$/i.exec(name);
    if (!match) {
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `${name} does not match assethash_<appVersion>_<buildCode>_<md5>.bytes`);
    }
    const appVersion = Number(match[1]);
    const buildCode = Number(match[2]);
    if (!Number.isSafeInteger(appVersion) || appVersion > UINT32_MAX
        || !Number.isSafeInteger(buildCode) || buildCode > UINT32_MAX) {
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `${name} contains an out-of-range identity`);
    }
    return { appVersion, buildCode, md5: (match[3] ?? '').toLowerCase() };
}

function isAssetHashCandidateName(name: string): boolean {
    const normalized = name.toLowerCase();
    return normalized.startsWith('assethash_')
        && normalized.endsWith('.bytes')
        && name.split('_').length >= 4;
}

async function inspectIndexCandidates(
    root: string,
    windowsDirectory: { readonly absolutePath: string; readonly canonicalPath: string; readonly details: BigIntStats },
    canonicalIdentity: ClientInventoryIdentity,
    canonicalIndex: FileFingerprint
): Promise<{ readonly candidates: readonly ClientAssetHashCandidate[]; readonly issues: readonly string[] }> {
    let entries;
    try {
        entries = await readdir(windowsDirectory.absolutePath, { withFileTypes: true });
    } catch (error) {
        throw inventoryError('CLIENT_FILE_READ_FAILED', `cannot list ${WINDOWS_RELATIVE_PATH}: ${messageOf(error)}`);
    }
    const names = entries.filter(entry => isAssetHashCandidateName(entry.name));
    if (names.length > MAX_CANDIDATE_COUNT) {
        throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `found more than ${MAX_CANDIDATE_COUNT} assethash candidates`);
    }
    names.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    const normalizedNames = new Set<string>();
    for (const entry of names) {
        const normalizedName = entry.name.toLowerCase();
        if (normalizedNames.has(normalizedName)) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `duplicate Windows assethash filename ${JSON.stringify(entry.name)}`);
        }
        normalizedNames.add(normalizedName);
    }

    const candidates: ClientAssetHashCandidate[] = [];
    const issues: string[] = [];
    let totalBytes = 0;
    for (const entry of names) {
        if (entry.isSymbolicLink() || !entry.isFile()) {
            throw inventoryError('CLIENT_PATH_UNSAFE', `${entry.name} is not a regular assethash file`);
        }
        const filename = parseCandidateFilename(entry.name);
        const relativePath = `${WINDOWS_RELATIVE_PATH}/${entry.name}`;
        const remainingBytes = MAX_CANDIDATE_TOTAL_BYTES - totalBytes;
        const fingerprint = await fingerprintFile(root, relativePath, {
            maxBytes: Math.min(MAX_INDEX_BYTES, remainingBytes),
            includeMd5: true,
            capturePrefixBytes: MAX_CANDIDATE_HEADER_BYTES
        });
        totalBytes += fingerprint.size;
        if (totalBytes > MAX_CANDIDATE_TOTAL_BYTES) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `assethash candidates exceed the ${MAX_CANDIDATE_TOTAL_BYTES}-byte scan limit`);
        }
        if (!fingerprint.md5 || fingerprint.md5 !== filename.md5) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `${entry.name} filename md5 does not match its content`);
        }

        const contentMatch = fingerprint.sha256 === canonicalIndex.sha256
            && fingerprint.size === canonicalIndex.size;
        const identity = contentMatch
            ? canonicalIdentity
            : parseCandidateHeader(fingerprint.prefix ?? Buffer.alloc(0));
        if (identity.appVersion !== filename.appVersion || identity.buildCode !== filename.buildCode) {
            throw inventoryError('CLIENT_INDEX_CANDIDATE_INVALID', `${entry.name} filename identity does not match its JSON header`);
        }
        const identityMatch = sameIdentity(identity, canonicalIdentity);
        candidates.push(Object.freeze({
            path: relativePath,
            size: fingerprint.size,
            sha256: fingerprint.sha256,
            md5: fingerprint.md5,
            identity,
            filenameAppVersion: filename.appVersion,
            filenameBuildCode: filename.buildCode,
            identityMatch,
            canonicalMatch: contentMatch && identityMatch
        }));
    }

    const canonicalMatches = candidates.filter(candidate => candidate.canonicalMatch);
    if (canonicalMatches.length === 0) {
        issues.push('No assethash candidate matches AssetHash_Info.bytes by SHA-256 and declared identity; canonical index selection is unresolved.');
    }
    if (candidates.length === 0) {
        issues.push('No assethash_<appVersion>_<buildCode>_<md5>.bytes candidates were found in the fixed Windows resource directory.');
    }

    const otherVersions = candidates.filter(candidate => !candidate.identityMatch);
    if (otherVersions.length > 0) {
        const labels = otherVersions.map(candidate => `${path.posix.basename(candidate.path)} (${candidate.identity.appVersion}/${candidate.identity.buildCode})`);
        issues.push(`Other assethash version candidates are present: ${labels.join(', ')}. Candidate selection uses content hash and identity, never modification time.`);
    }
    const sameIdentityDifferentContent = candidates.filter(candidate => candidate.identityMatch && !candidate.canonicalMatch);
    if (sameIdentityDifferentContent.length > 0) {
        const labels = sameIdentityDifferentContent.map(candidate => path.posix.basename(candidate.path));
        issues.push(`Candidates declare the canonical identity but have different content hashes: ${labels.join(', ')}. This identity conflict requires review.`);
    }

    const afterDirectory = await inspectSafeDirectory(root, WINDOWS_RELATIVE_PATH);
    if (!sameStatSnapshot(windowsDirectory.details, afterDirectory.details)
        || !isSameCanonicalPath(windowsDirectory.canonicalPath, afterDirectory.canonicalPath)) {
        throw inventoryError('CLIENT_FILE_CHANGED', `${WINDOWS_RELATIVE_PATH} changed while assethash candidates were scanned`);
    }

    return { candidates: Object.freeze(candidates), issues: Object.freeze(issues) };
}

/**
 * Fingerprint the supported client inputs without modifying or executing them.
 * The result is G0 observation evidence only; it does not establish runtime readiness.
 */
export async function inventoryClient(root: string): Promise<ClientInventory> {
    const canonicalRoot = await resolveClientRoot(root);
    const coreFiles: ClientInventoryFile[] = [];
    for (const relativePath of CORE_FILES) {
        const fingerprint = await fingerprintFile(canonicalRoot, relativePath, { maxBytes: MAX_KEY_FILE_BYTES });
        coreFiles.push({ path: relativePath, size: fingerprint.size, sha256: fingerprint.sha256 });
    }

    const indexFingerprint = await fingerprintFile(canonicalRoot, INDEX_RELATIVE_PATH, {
        maxBytes: MAX_INDEX_BYTES,
        captureAll: true
    });
    const indexBytes = indexFingerprint.bytes;
    if (!indexBytes) {
        throw inventoryError('CLIENT_INDEX_INVALID', 'AssetHash_Info.bytes could not be read');
    }
    const parsedIndex = parseClientIndex(indexBytes);

    const windowsDirectory = await inspectSafeDirectory(canonicalRoot, WINDOWS_RELATIVE_PATH);
    const indexCandidates = await inspectIndexCandidates(
        canonicalRoot,
        windowsDirectory,
        parsedIndex.identity,
        indexFingerprint
    );

    const scriptEntry = parsedIndex.scripts;
    const scriptRelativePath = `${WINDOWS_RELATIVE_PATH}/${scriptEntry.md5[0]}/${scriptEntry.md5[1]}/${scriptEntry.md5}.ys`;
    const scriptsFingerprint = await fingerprintFile(canonicalRoot, scriptRelativePath, {
        maxBytes: MAX_KEY_FILE_BYTES,
        includeMd5: true,
        expectedSize: scriptEntry.size
    });
    if (!scriptsFingerprint.md5 || scriptsFingerprint.md5 !== scriptEntry.md5) {
        throw inventoryError('CLIENT_RESOURCE_HASH_MISMATCH', 'scripts64 content MD5 does not match AssetHash_Info.bytes');
    }

    const keyFiles: ClientInventoryFile[] = [
        ...coreFiles,
        { path: INDEX_RELATIVE_PATH, size: indexFingerprint.size, sha256: indexFingerprint.sha256 },
        ...indexCandidates.candidates.map(candidate => ({ path: candidate.path, size: candidate.size, sha256: candidate.sha256 })),
        { path: scriptRelativePath, size: scriptsFingerprint.size, sha256: scriptsFingerprint.sha256 }
    ];

    const limitations = Object.freeze([
        'The index identity is an observed declaration and has not been verified against a running client.',
        'This scan fingerprints fixed core files, index candidates, and scripts64; full resource closure is unverified.',
        'Client launchability and local hall readiness are unverified; this is G0 fingerprint evidence only.',
        'GameAssembly.dll is fingerprinted only; SDK identity remains unverified.',
        'The scan is read-only and does not clone files or inspect credentials or databases.'
    ]);
    const issues = Object.freeze([
        'businessReady is false because this inventory is observed G0 evidence only.',
        ...indexCandidates.issues,
        ...limitations
    ]);

    return Object.freeze({
        root: canonicalRoot,
        state: 'observed',
        gate: 'G0',
        businessReady: false,
        identity: parsedIndex.identity,
        index: Object.freeze({
            path: INDEX_RELATIVE_PATH,
            size: indexFingerprint.size,
            sha256: indexFingerprint.sha256,
            entryCount: parsedIndex.entries.length,
            scriptsLogicalName: scriptEntry.logicalName
        }),
        keyFiles: Object.freeze(keyFiles),
        scripts: Object.freeze({
            path: scriptRelativePath,
            size: scriptsFingerprint.size,
            sha256: scriptsFingerprint.sha256,
            logicalName: scriptEntry.logicalName,
            expectedMd5: scriptEntry.md5,
            md5: scriptsFingerprint.md5
        }),
        indexCandidates: indexCandidates.candidates,
        issues,
        limitations
    });
}
