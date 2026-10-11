import { build } from 'esbuild';
import { spawn } from 'node:child_process';
import { mkdtemp, unlink, rmdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import os from 'node:os';

const root = fileURLToPath(new URL('..', import.meta.url));
const temporary = await mkdtemp(join(os.tmpdir(), 'ap-inventory-cli-'));
const entry = join(temporary, 'inventory.cjs');
try {
    await build({ entryPoints: [join(root, 'src/service/import/inventory-cli.ts')], outfile: entry,
        bundle: true, platform: 'node', target: 'node22', format: 'cjs', logLevel: 'silent' });
    process.exitCode = await new Promise(resolve => {
        const child = spawn(process.execPath, [entry, ...process.argv.slice(2)], { stdio: 'inherit', shell: false, windowsHide: true });
        child.on('error', error => { console.error(error.message); resolve(1); });
        child.on('exit', code => resolve(code ?? 1));
    });
} finally {
    await unlink(entry).catch(() => {});
    await rmdir(temporary).catch(() => {});
}
