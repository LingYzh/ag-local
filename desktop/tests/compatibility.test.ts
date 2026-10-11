import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FoundationError, inspectBundle } from '../src/service/compatibility';
import { loadSchemaRegistry } from '../src/service/compatibility/schema';

const REQUIRED_ROLES = [
    'schema', 'protocol_overlay', 'runtime_lock', 'content', 'seed', 'login_plan',
    'client_exe', 'client_sdk', 'client_index', 'client_scripts'
] as const;

const temporaryDirectories: string[] = [];

async function createBundle(): Promise<string> {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ap-compat-'));
    temporaryDirectories.push(directory);
    await mkdir(path.join(directory, 'server'));
    await mkdir(path.join(directory, 'client'));
    return directory;
}

function sha256(bytes: Buffer): string {
    return createHash('sha256').update(bytes).digest('hex');
}

function manifestBase(state = 'observed'): Record<string, unknown> {
    return {
        manifest_version: 1,
        tuple_id: 'tuple-2026-10-a',
        state,
        identity: {
            platform: 'windows',
            channel: 'global',
            architecture: 'x64',
            app_version: '1.2.3',
            resource_version: 'r7'
        },
        capabilities: { hall: 'unverified' },
        artifacts: []
    };
}

async function writeManifest(directory: string, manifest: Record<string, unknown>): Promise<void> {
    await writeFile(path.join(directory, 'manifest.json'), JSON.stringify(manifest), 'utf8');
}

async function addArtifact(
    directory: string,
    role: string,
    options: { root?: 'server' | 'client'; relativePath?: string; bytes?: Buffer } = {}
): Promise<Record<string, string>> {
    const root = options.root ?? (role.startsWith('client_') ? 'client' : 'server');
    const relativePath = options.relativePath ?? `${role}.bin`;
    const bytes = options.bytes ?? Buffer.from(`payload:${role}`);
    const target = path.join(directory, root, ...relativePath.split(/[\\/]/));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes);
    return { role, root, path: relativePath, sha256: sha256(bytes) };
}

afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe('inspectBundle', () => {
    it('keeps observed and incomplete bundles diagnostic only', async () => {
        const directory = await createBundle();
        const manifest = manifestBase();
        manifest.identity = {
            platform: 'unknown',
            channel: 'unverified',
            architecture: 'x64',
            app_version: '1.2.3',
            resource_version: 'r7'
        };
        await writeManifest(directory, manifest);

        const report = await inspectBundle(directory);

        expect(report.tupleId).toBe('tuple-2026-10-a');
        expect(report.artifactsVerified).toBe(0);
        expect(report.manifestComplete).toBe(false);
        expect(report.declaredHallPassed).toBe(false);
        expect(report.businessReady).toBe(false);
        expect(report.issues.join(' ')).toContain('diagnostic only');
        expect(report.issues.join(' ')).toContain('identity unknown');
        expect(report.issues.join(' ')).toContain('platform, channel');
    });

    it('rejects placeholder identity values outside observed state', async () => {
        const directory = await createBundle();
        const manifest = manifestBase('imported');
        manifest.identity = {
            platform: 'windows',
            channel: 'global',
            architecture: 'x64',
            app_version: '1.2.3',
            resource_version: 'unknown'
        };
        await writeManifest(directory, manifest);

        await expect(inspectBundle(directory)).rejects.toMatchObject({
            code: 'MANIFEST_INVALID',
            detail: expect.stringContaining('resource_version')
        });
    });

    it('reports a fully hash-verified closure while keeping businessReady false', async () => {
        const directory = await createBundle();
        const schema = Buffer.from(JSON.stringify({
            messages: [{ name: '.pkg.Empty', fields: [] }]
        }));
        const artifacts: Record<string, string>[] = [];
        for (const role of REQUIRED_ROLES) {
            artifacts.push(await addArtifact(directory, role, role === 'schema' ? { bytes: schema } : {}));
        }
        const manifest = manifestBase('hall_passed');
        manifest.capabilities = { hall: 'passed' };
        manifest.artifacts = artifacts;
        await writeManifest(directory, manifest);

        const report = await inspectBundle(directory);

        expect(report.artifactsVerified).toBe(REQUIRED_ROLES.length);
        expect(report.manifestComplete).toBe(true);
        expect(report.declaredHallPassed).toBe(true);
        expect(report.businessReady).toBe(false);
        expect(report.schema).toEqual({ sha256: sha256(schema), messages: 1, fields: 0 });
    });

    it('keeps an imported tuple incomplete when required roles are missing', async () => {
        const directory = await createBundle();
        const manifest = manifestBase('imported');
        manifest.artifacts = [await addArtifact(directory, 'schema', {
            bytes: Buffer.from(JSON.stringify({ messages: [{ name: 'Empty', fields: [] }] }))
        })];
        await writeManifest(directory, manifest);

        const report = await inspectBundle(directory);

        expect(report.artifactsVerified).toBe(1);
        expect(report.manifestComplete).toBe(false);
        expect(report.schema?.messages).toBe(1);
        expect(report.issues.join(' ')).toContain('runtime closure is incomplete');
    });

    it('rejects a bad artifact hash with a stable error code', async () => {
        const directory = await createBundle();
        const artifact = await addArtifact(directory, 'schema', {
            bytes: Buffer.from(JSON.stringify({ messages: [{ name: 'Empty', fields: [] }] }))
        });
        artifact.sha256 = '0'.repeat(64);
        const manifest = manifestBase();
        manifest.artifacts = [artifact];
        await writeManifest(directory, manifest);

        await expect(inspectBundle(directory)).rejects.toMatchObject<Partial<FoundationError>>({
            code: 'ARTIFACT_HASH_MISMATCH'
        });
    });

    it.each(['../outside.bin', 'C:\\outside.bin', '\\\\server\\share\\file.bin', 'dir\\..\\file.bin', 'file.txt:stream', 'CON.txt', 'trailing.']) (
        'rejects unsafe artifact path %s', async relativePath => {
            const directory = await createBundle();
            const artifact = await addArtifact(directory, 'schema', {
                relativePath: 'placeholder.bin',
                bytes: Buffer.from(JSON.stringify({ messages: [{ name: 'Empty', fields: [] }] }))
            });
            artifact.path = relativePath;
            const manifest = manifestBase();
            manifest.artifacts = [artifact];
            await writeManifest(directory, manifest);

            await expect(inspectBundle(directory)).rejects.toMatchObject({ code: 'ARTIFACT_PATH_UNSAFE' });
        }
    );

    it('rejects symlinks that resolve outside the artifact root', async context => {
        const directory = await createBundle();
        const outsideDirectory = await mkdtemp(path.join(os.tmpdir(), 'ap-compat-outside-'));
        temporaryDirectories.push(outsideDirectory);
        const outsideFile = path.join(outsideDirectory, 'schema.json');
        const schema = Buffer.from(JSON.stringify({ messages: [{ name: 'Empty', fields: [] }] }));
        await writeFile(outsideFile, schema);
        try {
            await symlink(outsideFile, path.join(directory, 'server', 'linked-schema.json'), 'file');
        } catch (error) {
            const code = typeof error === 'object' && error !== null && 'code' in error
                ? String((error as { code: unknown }).code)
                : '';
            if (process.platform === 'win32' && ['EPERM', 'EACCES', 'UNKNOWN'].includes(code)) {
                context.skip('symlink creation is unavailable on this Windows host');
            }
            throw error;
        }

        const manifest = manifestBase();
        manifest.artifacts = [{
            role: 'schema', root: 'server', path: 'linked-schema.json', sha256: sha256(schema)
        }];
        await writeManifest(directory, manifest);

        await expect(inspectBundle(directory)).rejects.toMatchObject({ code: 'ARTIFACT_PATH_UNSAFE' });
    });

    it('rejects directory junction escape without requiring file symlink privileges', async () => {
        const directory = await createBundle();
        const outside = await mkdtemp(path.join(os.tmpdir(), 'ap-compat-outside-'));
        temporaryDirectories.push(outside);
        const schema = Buffer.from(JSON.stringify({ messages: [{ name: 'Empty', fields: [] }] }));
        await writeFile(path.join(outside, 'schema.json'), schema);
        await symlink(outside, path.join(directory, 'server', 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
        const manifest = manifestBase();
        manifest.artifacts = [{ role: 'schema', root: 'server', path: 'escape/schema.json', sha256: sha256(schema) }];
        await writeManifest(directory, manifest);
        await expect(inspectBundle(directory)).rejects.toMatchObject({ code: 'ARTIFACT_PATH_UNSAFE' });
    });
});

describe('schema registry validation', () => {
    async function inspectSchema(bytes: Buffer): Promise<Awaited<ReturnType<typeof inspectBundle>>> {
        const directory = await createBundle();
        const manifest = manifestBase();
        manifest.artifacts = [await addArtifact(directory, 'schema', { bytes })];
        await writeManifest(directory, manifest);
        return inspectBundle(directory);
    }

    it('rejects normalized message-name conflicts', async () => {
        const bytes = Buffer.from(JSON.stringify({
            messages: [
                { name: '.pkg.Entry', fields: [] },
                { name: 'PKG.entry', fields: [] }
            ]
        }));

        await expect(inspectSchema(bytes)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
    });

    it('rejects duplicate field numbers and names', async () => {
        for (const fields of [
            [
                { number: 1, name: 'first', type: 'int32', label: 'optional', ref: null },
                { number: 1, name: 'second', type: 'int32', label: 'optional', ref: null }
            ],
            [
                { number: 1, name: 'same', type: 'int32', label: 'optional', ref: null },
                { number: 2, name: 'same', type: 'int32', label: 'optional', ref: null }
            ]
        ]) {
            const bytes = Buffer.from(JSON.stringify({ messages: [{ name: 'Entry', fields }] }));
            await expect(inspectSchema(bytes)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
        }
    });

    it('enforces protobuf field-number boundaries', async () => {
        for (const number of [0, 19_000, 19_999, 2 ** 29]) {
            const bytes = Buffer.from(JSON.stringify({
                messages: [{
                    name: 'Entry',
                    fields: [{ number, name: 'value', type: 'int32', label: 'optional', ref: null }]
                }]
            }));
            await expect(inspectSchema(bytes)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
        }

        const maximum = loadSchemaRegistry(Buffer.from(JSON.stringify({
            messages: [{
                name: 'Entry',
                fields: [{ number: (2 ** 29) - 1, name: 'value', type: 'int32', label: 'optional', ref: null }]
            }]
        })));
        expect(maximum.fieldCount).toBe(1);
    });

    it('rejects missing or unresolved message refs and unknown scalar types', async () => {
        const messageFields: Array<Record<string, unknown>> = [
            { number: 1, name: 'child', type: 'message', label: 'optional', ref: 'Missing' },
            { number: 1, name: 'child', type: 'message', label: 'optional', ref: null },
            { number: 1, name: 'child', type: 'message', label: 'optional', ref: '' },
            { number: 1, name: 'child', type: 'message', label: 'optional' }
        ];
        for (const field of messageFields) {
            const unresolved = Buffer.from(JSON.stringify({
                messages: [{ name: 'Entry', fields: [field] }]
            }));
            await expect(inspectSchema(unresolved)).rejects.toMatchObject({ code: 'UNRESOLVED_TYPE' });
        }

        const unknown = Buffer.from(JSON.stringify({
            messages: [{
                name: 'Entry',
                fields: [{ number: 1, name: 'value', type: 'int', label: 'optional', ref: null }]
            }]
        }));
        await expect(inspectSchema(unknown)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
    });

    it('accepts zero-field messages and rejects duplicate JSON keys', async () => {
        const zeroFieldSchema = Buffer.from(JSON.stringify({ messages: [{ name: 'Entry', fields: [] }] }));
        const report = await inspectSchema(zeroFieldSchema);
        expect(report.schema?.messages).toBe(1);
        expect(report.schema?.fields).toBe(0);

        const duplicateJson = Buffer.from('{"messages":[],"messages":[{"name":"Entry","fields":[]}]}');
        await expect(inspectSchema(duplicateJson)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
    });

    it('keeps namespace-qualified refs and enum metadata in a frozen registry', () => {
        const registry = loadSchemaRegistry(Buffer.from(JSON.stringify({
            messages: [
                {
                    name: 'pkg.Entry',
                    fields: [
                        { number: 1, name: 'child', type: 'message', label: 'optional', ref: '.pkg.Child' },
                        { number: 2, name: 'kind', type: 'enum', label: 'optional', ref: 'pkg.Mode' },
                        { number: 3, name: 'title', type: 'string', label: 'optional', ref: null },
                        { number: 4, name: 'payload', type: 'bytes', label: 'optional', ref: null }
                    ]
                },
                { name: 'pkg.Child', fields: [] }
            ]
        })));

        expect(registry.messages['pkg.entry'].fields['1'].ref).toBe('.pkg.Child');
        expect(registry.messages['pkg.entry'].fields['2'].ref).toBe('pkg.Mode');
        expect(registry.messages['pkg.entry'].fields['2'].type).toBe('enum');
        expect(Object.isFrozen(registry)).toBe(true);
        expect(Object.isFrozen(registry.messages)).toBe(true);
        expect(Object.isFrozen(registry.messages['pkg.entry'])).toBe(true);
        expect(Object.isFrozen(registry.messages['pkg.entry'].fields)).toBe(true);
        expect(Object.isFrozen(registry.messages['pkg.entry'].fields['1'])).toBe(true);
    });
});
