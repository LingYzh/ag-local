import { writeFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { inventoryClient } from './client-inventory';
import { fault } from '../../shared/validation';

async function main(): Promise<void> {
    const { values } = parseArgs({ options: {
        client: { type: 'string' }, output: { type: 'string' }
    }, strict: true, allowPositionals: false });
    if (!values.client || !path.isAbsolute(values.client)) throw new Error('--client requires an explicit absolute directory');
    const inventory = await inventoryClient(values.client);
    if (values.output) {
        if (!path.isAbsolute(values.output)) throw new Error('--output requires an explicit absolute filename');
        const parent = await realpath(path.dirname(values.output));
        const relative = path.relative(inventory.root, parent);
        if (!relative || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))) {
            throw new Error('Inventory output must be outside the original client directory');
        }
        await writeFile(path.join(parent, path.basename(values.output)), `${JSON.stringify(inventory, null, 4)}\n`, { encoding: 'utf8', flag: 'wx' });
    }
    // Absolute user paths and the full private report go only to the explicitly selected output.
    console.log(JSON.stringify({ state: inventory.state, businessReady: inventory.businessReady,
        identity: inventory.identity, indexSha256: inventory.index.sha256,
        scriptsSha256: inventory.scripts.sha256, issues: inventory.issues, outputSaved: !!values.output }, null, 4));
}

void main().catch(error => {
    console.error(JSON.stringify(fault(error)));
    process.exitCode = 1;
});
