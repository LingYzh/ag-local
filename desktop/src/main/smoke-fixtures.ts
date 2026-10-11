import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Small synthetic filesystem input for the real inventory worker, never a game fixture. */
export async function createSmokeClient(output: string): Promise<string> {
    const directory = await mkdtemp(join(output, 'synthetic-client-'));
    const windows = join(directory, 'AetherGazer_Data', 'StreamingAssets', 'Windows');
    await mkdir(windows, { recursive: true });
    for (const name of ['AetherGazer.exe', 'GameAssembly.dll', 'UnityPlayer.dll']) {
        await writeFile(join(directory, name), `synthetic-only:${name}`, { flag: 'wx' });
    }
    const scripts = Buffer.from('synthetic inventory bytes; never executed');
    const md5 = createHash('md5').update(scripts).digest('hex');
    const resourceDirectory = join(windows, md5[0], md5[1]);
    await mkdir(resourceDirectory, { recursive: true });
    await writeFile(join(resourceDirectory, `${md5}.ys`), scripts, { flag: 'wx' });
    const index = Buffer.from(JSON.stringify({ buildCode: 1, appVersion: 1, channel: 0,
        versionName: 'synthetic-control-only', assetHashList: [`scripts64|${md5}|${scripts.length}`] }));
    const indexMd5 = createHash('md5').update(index).digest('hex');
    await writeFile(join(windows, 'AssetHash_Info.bytes'), index, { flag: 'wx' });
    await writeFile(join(windows, `assethash_1_1_${indexMd5}.bytes`), index, { flag: 'wx' });
    return directory;
}
