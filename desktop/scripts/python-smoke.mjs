import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { basename, join, isAbsolute } from 'node:path';
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: { python: { type: 'string' } }, strict: true });
if (!values.python || !isAbsolute(values.python)) throw new Error('--python requires an explicit absolute runtime path');
const root = fileURLToPath(new URL('..', import.meta.url));
const qa = join(root, 'qa');
await mkdir(qa, { recursive: true });
const fixture = await mkdtemp(join(qa, 'python-synthetic-'));
const output = join(qa, `${basename(fixture)}-report.json`);
await mkdir(join(fixture, 'server'));
await mkdir(join(fixture, 'client'));
const artifacts = [];
for (const role of ['schema', 'protocol_overlay', 'runtime_lock', 'content', 'seed', 'login_plan',
    'client_exe', 'client_sdk', 'client_index', 'client_scripts']) {
    const bytes = Buffer.from(role === 'schema' ? JSON.stringify({ messages: [{ name: 'Synthetic.Empty', fields: [] }] }) : `synthetic:${role}`);
    const artifactRoot = role.startsWith('client_') ? 'client' : 'server';
    await writeFile(join(fixture, artifactRoot, `${role}.json`), bytes, { flag: 'wx' });
    artifacts.push({ role, root: artifactRoot, path: `${role}.json`, sha256: createHash('sha256').update(bytes).digest('hex') });
}
await writeFile(join(fixture, 'manifest.json'), JSON.stringify({
    manifest_version: 1, tuple_id: 'synthetic-control-test-only', state: 'imported',
    identity: { platform: 'synthetic', channel: 'synthetic', architecture: 'synthetic', app_version: 'synthetic', resource_version: 'synthetic' },
    capabilities: { hall: 'unverified' }, artifacts
}, null, 4), { flag: 'wx' });
const runtimeHash = createHash('sha256');
for await (const chunk of createReadStream(values.python)) runtimeHash.update(chunk);
const exitCode = await new Promise(resolve => {
    const child = spawn(process.execPath, [join(root, 'scripts/compatibility-check.mjs'),
        '--python', values.python, '--python-sha256', runtimeHash.digest('hex'),
        '--entry', join(root, '../v5_server/bootstrap/controlled_service.py'),
        '--bundle', fixture, '--output', output],
    { shell: false, windowsHide: true, stdio: 'inherit' });
    child.on('error', error => { console.error(error.message); resolve(1); });
    child.on('exit', code => resolve(code ?? 1));
});
console.log(JSON.stringify({ fixture, output, syntheticOnly: true, exitCode }));
process.exitCode = exitCode;
