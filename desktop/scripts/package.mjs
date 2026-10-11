import { packager } from '@electron/packager';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const root = resolve('.');
const metadata = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const output = join(root, 'out');
await mkdir(output, { recursive: true });
// Each run gets a fresh workspace-owned staging and destination; no existing package is deleted.
const staging = await mkdtemp(join(output, 'stage-'));
const destination = await mkdtemp(join(output, 'portable-'));
await cp(join(root, 'dist'), join(staging, 'dist'), { recursive: true });
await cp(join(root, '../LICENSE'), join(staging, 'LICENSE'));
await cp(join(root, 'THIRD_PARTY_NOTICES.txt'), join(staging, 'THIRD_PARTY_NOTICES.txt'));
await writeFile(join(staging, 'package.json'), JSON.stringify({
    name: metadata.name, productName: metadata.productName, version: metadata.version,
    description: metadata.description, main: metadata.main,
    author: 'Alpha Persei Contributors', private: true
}, null, 4));
const directories = await packager({
    dir: staging, out: destination, name: 'Alpha Persei', executableName: 'AlphaPersei',
    platform: 'win32', arch: 'x64', electronVersion: metadata.devDependencies.electron,
    asar: true, prune: false, overwrite: false,
    appVersion: metadata.version, appCopyright: 'Alpha Persei Contributors'
});
const directory = directories[0];
if (!directory) throw new Error('Packager did not produce a portable application');
const asar = await readFile(join(directory, 'resources/app.asar'));
const report = {
    at: new Date().toISOString(), directory, executable: join(directory, 'AlphaPersei.exe'),
    version: metadata.version, electron: metadata.devDependencies.electron,
    platform: 'win32', architecture: 'x64',
    asarSha256: createHash('sha256').update(asar).digest('hex')
};
await writeFile(join(output, 'latest-package.json'), JSON.stringify(report, null, 4));
console.log(JSON.stringify(report, null, 4));
