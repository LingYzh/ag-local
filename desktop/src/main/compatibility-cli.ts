import { parseArgs } from 'node:util';
import { realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { PythonCompatibilitySupervisor } from './python-supervisor';
import { fault } from '../shared/validation';

async function main(): Promise<void> {
    const { values } = parseArgs({ options: {
        python: { type: 'string' }, 'python-sha256': { type: 'string' },
        entry: { type: 'string' }, bundle: { type: 'string' }, output: { type: 'string' }
    }, strict: true, allowPositionals: false });
    if (!values.python || !values['python-sha256'] || !values.entry || !values.bundle) {
        throw new Error('--python, --python-sha256, --entry and --bundle are required');
    }
    let output: string | null = null;
    if (values.output) {
        if (!path.isAbsolute(values.output)) throw new Error('--output must be an explicit absolute filename');
        const parent = await realpath(path.dirname(values.output));
        const bundle = await realpath(values.bundle);
        const relative = path.relative(bundle, parent);
        if (!relative || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))) {
            throw new Error('Control report output must be outside the inspected bundle');
        }
        output = path.join(parent, path.basename(values.output));
    }
    const supervisor = new PythonCompatibilitySupervisor({ executable: values.python,
        executableSha256: values['python-sha256'], entryPoint: values.entry, bundleDirectory: values.bundle });
    try {
        const first = await supervisor.start();
        const stopped = await supervisor.stop();
        const second = await supervisor.start();
        const final = await supervisor.stop();
        if (first.instanceId === second.instanceId) throw new Error('Restart did not create a fresh private identity');
        const report = { passed: true, timestamp: new Date().toISOString(),
            businessReady: false, checks: ['static preflight', 'private identity', 'status before shutdown',
                'shutdown acknowledgement and exit', 'restart with fresh identity'], first, stopped, second, final };
        if (output) {
            await writeFile(output, `${JSON.stringify(report, null, 4)}\n`, { encoding: 'utf8', flag: 'wx' });
        }
        console.log(JSON.stringify(report, null, 4));
    } finally {
        if (supervisor.getStatus().state === 'READY') await supervisor.stop();
    }
}

void main().catch(error => { console.error(JSON.stringify(fault(error))); process.exitCode = 1; });
