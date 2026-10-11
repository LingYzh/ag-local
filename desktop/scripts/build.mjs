import { build } from 'esbuild';
import { cp } from 'node:fs/promises';

await build({
    entryPoints: {
        'main/main': 'src/main/main.ts',
        'preload/preload': 'src/preload/preload.ts',
        'service/worker': 'src/service/worker.ts'
    },
    outdir: 'dist', outExtension: { '.js': '.cjs' },
    bundle: true, platform: 'node', target: 'node22', format: 'cjs',
    external: ['electron'], sourcemap: true, logLevel: 'info'
});
await cp('fixtures', 'dist/fixtures', { recursive: true });
