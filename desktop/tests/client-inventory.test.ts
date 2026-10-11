import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FoundationError } from '../src/service/compatibility/errors';
import { inventoryClient } from '../src/service/import/client-inventory';
import { isClientInventory } from '../src/shared/client-validation';

const temporaryDirectories: string[] = [];

interface Fixture {
    readonly root: string;
    readonly windowsPath: string;
    readonly scriptBytes: Buffer;
    readonly scriptMd5: string;
    readonly scriptRelativePath: string;
}

interface FixtureOptions {
    readonly assetHashList?: unknown[];
    readonly indexBytes?: Buffer;
    readonly writeScript?: boolean;
}

function md5(bytes: Buffer): string {
    return createHash('md5').update(bytes).digest('hex');
}

function sha256(bytes: Buffer): string {
    return createHash('sha256').update(bytes).digest('hex');
}

function assetEntry(name: string, bytes: Buffer, size = bytes.byteLength): string {
    return `${name}|${md5(bytes)}|${size}`;
}

function candidateFilename(bytes: Buffer, appVersion = 307, buildCode = 321): string {
    return `assethash_${appVersion}_${buildCode}_${md5(bytes)}.bytes`;
}

function indexDocument(assetHashList: unknown[]): Record<string, unknown> {
    return {
        buildCode: 321,
        appVersion: 307,
        channel: 0,
        versionName: 'v5.3.1',
        assetHashList
    };
}

async function createFixture(options: FixtureOptions = {}): Promise<Fixture> {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ap-client-inventory-'));
    temporaryDirectories.push(root);
    for (const fileName of ['AetherGazer.exe', 'GameAssembly.dll', 'UnityPlayer.dll']) {
        await writeFile(path.join(root, fileName), Buffer.from(`fixture:${fileName}`));
    }

    const windowsPath = path.join(root, 'AetherGazer_Data', 'StreamingAssets', 'Windows');
    await mkdir(windowsPath, { recursive: true });
    const scriptBytes = Buffer.from('static scripts64 test fixture');
    const scriptMd5 = md5(scriptBytes);
    const scriptRelativePath = path.join(scriptMd5[0] ?? '', scriptMd5[1] ?? '', `${scriptMd5}.ys`);
    const defaultEntries = [assetEntry('scripts64', scriptBytes)];
    const indexBytes = options.indexBytes
        ?? Buffer.from(JSON.stringify(indexDocument(options.assetHashList ?? defaultEntries)), 'utf8');
    await writeFile(path.join(windowsPath, 'AssetHash_Info.bytes'), indexBytes);
    await writeFile(path.join(windowsPath, candidateFilename(indexBytes)), indexBytes);

    if (options.writeScript !== false) {
        const scriptPath = path.join(windowsPath, scriptRelativePath);
        await mkdir(path.dirname(scriptPath), { recursive: true });
        await writeFile(scriptPath, scriptBytes);
    }
    return { root, windowsPath, scriptBytes, scriptMd5, scriptRelativePath };
}

async function addCandidate(
    fixture: Fixture,
    document: Record<string, unknown>,
    appVersion: number,
    buildCode: number
): Promise<string> {
    const bytes = Buffer.from(JSON.stringify(document), 'utf8');
    const name = candidateFilename(bytes, appVersion, buildCode);
    await writeFile(path.join(fixture.windowsPath, name), bytes);
    return name;
}

async function expectInventoryError(promise: Promise<unknown>, code: string): Promise<void> {
    await expect(promise).rejects.toMatchObject<Partial<FoundationError>>({ code });
}

afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe('inventoryClient', () => {
    it('returns a read-only G0 fingerprint and matches the canonical index by content and identity', async () => {
        const fixture = await createFixture();

        const report = await inventoryClient(fixture.root);

        // The IPC validator must accept every fingerprint emitted by the real producer.
        expect(isClientInventory(report)).toBe(true);
        expect(report.root).toBe(path.resolve(fixture.root));
        expect(report.state).toBe('observed');
        expect(report.gate).toBe('G0');
        expect(report.businessReady).toBe(false);
        expect(report.identity).toEqual({
            buildCode: 321,
            appVersion: 307,
            channel: 0,
            versionName: 'v5.3.1'
        });
        expect(report.index.entryCount).toBe(1);
        expect(report.index.scriptsLogicalName).toBe('scripts64');
        expect(report.index.sha256).toBe(sha256(Buffer.from(JSON.stringify(indexDocument([
            assetEntry('scripts64', fixture.scriptBytes)
        ])), 'utf8')));
        expect(report.scripts.path).toBe(`AetherGazer_Data/StreamingAssets/Windows/${fixture.scriptRelativePath.split(path.sep).join('/')}`);
        expect(report.scripts.expectedMd5).toBe(fixture.scriptMd5);
        expect(report.scripts.md5).toBe(fixture.scriptMd5);
        expect(report.scripts.sha256).toBe(sha256(fixture.scriptBytes));
        expect(report.keyFiles.map(file => file.path)).toContain('GameAssembly.dll');
        expect(report.indexCandidates).toHaveLength(1);
        expect(report.indexCandidates[0]?.canonicalMatch).toBe(true);
        expect(report.issues.join(' ')).toContain('SDK identity remains unverified');
        expect(report.issues.join(' ')).toContain('full resource closure is unverified');
    });

    it('reports other version candidates without replacing the content-and-identity match', async () => {
        const fixture = await createFixture();
        const otherScript = Buffer.from('old scripts32 fixture');
        const otherName = assetEntry('scripts64', otherScript);
        const otherCandidate = await addCandidate(fixture, {
            buildCode: 320,
            appVersion: 306,
            channel: 0,
            versionName: 'v5.3.0',
            assetHashList: [otherName]
        }, 306, 320);

        const report = await inventoryClient(fixture.root);

        expect(report.indexCandidates).toHaveLength(2);
        expect(isClientInventory(report)).toBe(true);
        expect(report.indexCandidates.filter(candidate => candidate.canonicalMatch)).toHaveLength(1);
        expect(report.indexCandidates.find(candidate => candidate.path.endsWith(otherCandidate))?.identityMatch).toBe(false);
        expect(report.issues.join(' ')).toContain('Other assethash version candidates are present');
        expect(report.issues.join(' ')).toContain('never modification time');
    });

    it('reports same-identity candidates with different content as a conflict', async () => {
        const fixture = await createFixture();
        const conflictingBytes = Buffer.from(JSON.stringify({
            buildCode: 321,
            appVersion: 307,
            channel: 0,
            versionName: 'v5.3.1',
            note: 'different index content',
            assetHashList: [assetEntry('scripts64', fixture.scriptBytes)]
        }), 'utf8');
        await writeFile(path.join(fixture.windowsPath, candidateFilename(conflictingBytes)), conflictingBytes);

        const report = await inventoryClient(fixture.root);

        expect(report.indexCandidates.filter(candidate => candidate.identityMatch)).toHaveLength(2);
        expect(report.indexCandidates.filter(candidate => candidate.canonicalMatch)).toHaveLength(1);
        expect(report.issues.join(' ')).toContain('This identity conflict requires review');
    });

    it.each([
        ['malformed md5', (bytes: Buffer) => `scripts64|not-md5|${bytes.byteLength}`],
        ['negative size', (bytes: Buffer) => `scripts64|${md5(bytes)}|-1`],
        ['out-of-bound size', (bytes: Buffer) => `scripts64|${md5(bytes)}|68719476737`]
    ])('rejects %s entries', async (_label, makeEntry) => {
        const scriptBytes = Buffer.from('static scripts64 test fixture');
        const fixture = await createFixture({ assetHashList: [makeEntry(scriptBytes)] });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_INDEX_INVALID');
    });

    it('rejects an index with no scripts64 definition', async () => {
        const otherBytes = Buffer.from('other resource');
        const fixture = await createFixture({ assetHashList: [assetEntry('other.bin', otherBytes)] });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_INDEX_INVALID');
    });

    it('rejects path traversal in a logical asset name', async () => {
        const scriptBytes = Buffer.from('static scripts64 test fixture');
        const fixture = await createFixture({ assetHashList: [`../scripts64|${md5(scriptBytes)}|${scriptBytes.byteLength}`] });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_PATH_UNSAFE');
    });

    it('rejects duplicate logical names using Windows case-insensitive comparison', async () => {
        const scriptBytes = Buffer.from('static scripts64 test fixture');
        const secondBytes = Buffer.from('different logical entry');
        const fixture = await createFixture({ assetHashList: [
            assetEntry('scripts64', scriptBytes),
            assetEntry('SCRIPTS64', secondBytes)
        ] });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_INDEX_INVALID');
    });

    it('rejects non-string asset entries and duplicate JSON object keys', async () => {
        const typedFixture = await createFixture({ assetHashList: [42] });
        await expectInventoryError(inventoryClient(typedFixture.root), 'CLIENT_INDEX_INVALID');

        const scriptBytes = Buffer.from('static scripts64 test fixture');
        const validEntry = assetEntry('scripts64', scriptBytes);
        const duplicateKeyBytes = Buffer.from(
            `{"buildCode":321,"buildCode":321,"appVersion":307,"channel":0,"versionName":"v5.3.1","assetHashList":[${JSON.stringify(validEntry)}]}`,
            'utf8'
        );
        const duplicateFixture = await createFixture({ indexBytes: duplicateKeyBytes });
        await expectInventoryError(inventoryClient(duplicateFixture.root), 'CLIENT_INDEX_INVALID');
    });

    it('rejects a script file whose size does not match the index', async () => {
        const scriptBytes = Buffer.from('static scripts64 test fixture');
        const fixture = await createFixture({ assetHashList: [assetEntry('scripts64', scriptBytes, scriptBytes.byteLength + 1)] });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_RESOURCE_SIZE_MISMATCH');
    });

    it('rejects missing script resources instead of searching another directory', async () => {
        const fixture = await createFixture({ writeScript: false });

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_FILE_MISSING');
    });

    it('rejects a scripts path that traverses a directory link', async context => {
        const fixture = await createFixture();
        const outside = await mkdtemp(path.join(os.tmpdir(), 'ap-client-inventory-outside-'));
        temporaryDirectories.push(outside);
        const firstFanoutDirectory = path.join(fixture.windowsPath, fixture.scriptMd5[0] ?? '');
        await rm(firstFanoutDirectory, { recursive: true, force: true });
        try {
            await symlink(outside, firstFanoutDirectory, process.platform === 'win32' ? 'junction' : 'dir');
        } catch (error) {
            const code = typeof error === 'object' && error !== null && 'code' in error
                ? String((error as { code: unknown }).code)
                : '';
            if (process.platform === 'win32' && ['EPERM', 'EACCES', 'UNKNOWN'].includes(code)) {
                context.skip('directory link creation is unavailable on this Windows host');
            }
            throw error;
        }

        await expectInventoryError(inventoryClient(fixture.root), 'CLIENT_PATH_UNSAFE');
    });
});
