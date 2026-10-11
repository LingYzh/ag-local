import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import type { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { PythonCompatibilitySupervisor } from '../src/main/python-supervisor';

const directories: string[] = [];
const roles = ['schema', 'protocol_overlay', 'runtime_lock', 'content', 'seed', 'login_plan',
    'client_exe', 'client_sdk', 'client_index', 'client_scripts'];

afterEach(async () => {
    for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(state = 'imported'): Promise<{ root: string; executableHash: string }> {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ap-python-bridge-'));
    directories.push(root);
    await mkdir(path.join(root, 'server'));
    await mkdir(path.join(root, 'client'));
    const artifacts = [];
    for (const role of roles) {
        const bytes = Buffer.from(role === 'schema'
            ? JSON.stringify({ messages: [{ name: 'cs_10200', fields: [] }] }) : role);
        const artifactRoot = role.startsWith('client_') ? 'client' : 'server';
        await writeFile(path.join(root, artifactRoot, `${role}.json`), bytes);
        artifacts.push({ role, root: artifactRoot, path: `${role}.json`,
            sha256: createHash('sha256').update(bytes).digest('hex') });
    }
    await writeFile(path.join(root, 'manifest.json'), JSON.stringify({
        manifest_version: 1, tuple_id: 'synthetic-only', state,
        identity: { platform: 'windows', channel: 'test', architecture: 'x64', app_version: '1', resource_version: '1' },
        capabilities: { hall: 'unverified' }, artifacts
    }));
    return { root, executableHash: createHash('sha256').update(await readFile(process.execPath)).digest('hex') };
}

type FakeRequest = { command: 'status' | 'shutdown'; requestId: string; instanceId: string };
type FakeChild = EventEmitter & { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough };

function fakePython(mode: 'normal' | 'forged' | 'business-ready' | 'no-exit' | 'hold-ready-status' = 'normal') {
    let started = 0;
    const commands: string[] = [];
    const children: FakeChild[] = [];
    const instanceIds: string[] = [];
    const requests: FakeRequest[][] = [];
    const reply = (childIndex: number, requestIndex: number) => {
        const request = requests[childIndex]?.[requestIndex];
        const child = children[childIndex];
        if (!request || !child) throw new Error('The fake request does not exist');
        child.stdout.write(`${JSON.stringify({ kind: 'response', version: 1, instanceId: request.instanceId,
            requestId: request.requestId, result: { ok: true, value: {
                state: request.command === 'shutdown' ? 'STOPPED' : 'READY',
                instanceId: request.instanceId, scope: 'python-compatibility', businessReady: false,
                tupleId: 'synthetic-only', lastError: null
            } } })}\n`);
    };
    const sendDiagnostic = (childIndex: number, value: unknown) => {
        const child = children[childIndex];
        if (!child) throw new Error('The fake child does not exist');
        child.stderr.write(`${JSON.stringify(value)}\n`);
    };
    const fakeSpawn = ((_exe: string, args: string[]) => {
        const childIndex = started++;
        const child = Object.assign(new EventEmitter(), {
            stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough()
        });
        children.push(child);
        const instanceId = args[args.indexOf('--instance-id') + 1];
        instanceIds.push(instanceId);
        requests.push([]);
        const send = (value: unknown) => child.stdout.write(`${JSON.stringify(value)}\n`);
        queueMicrotask(() => send({
            kind: 'ready', version: 1,
            instanceId: mode === 'forged' ? '00000000-0000-4000-8000-000000000000' : instanceId,
            scope: 'python-compatibility', businessReady: mode === 'business-ready', tupleId: 'synthetic-only'
        }));
        child.stdin.on('data', (chunk: Buffer) => {
            const request = JSON.parse(chunk.toString()) as FakeRequest;
            commands.push(request.command);
            const requestIndex = requests[childIndex].push(request) - 1;
            if (mode === 'hold-ready-status' && request.command === 'status' && requestIndex > 0) return;
            reply(childIndex, requestIndex);
            const exitsCooperatively = mode === 'no-exit' ? childIndex > 0 : mode !== 'hold-ready-status';
            if (request.command === 'shutdown' && exitsCooperatively) queueMicrotask(() => child.emit('close', 0));
        });
        child.stdin.on('finish', () => {
            const exitsCooperatively = mode === 'no-exit' ? childIndex > 0 : mode !== 'hold-ready-status';
            if (exitsCooperatively) queueMicrotask(() => child.emit('close', 0));
        });
        return child;
    }) as unknown as typeof spawn;
    return { spawn: fakeSpawn, commands, children, instanceIds, reply, sendDiagnostic,
        get started() { return started; } };
}

describe('private Python compatibility lifecycle', () => {
    it('checks the tuple, proves identity repeatedly and requires acknowledgement plus exit', async () => {
        const { root, executableHash } = await fixture();
        const fake = fakePython();
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: executableHash, entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root,
            spawn: fake.spawn, timeoutMs: 200 });
        expect(await supervisor.start()).toMatchObject({ state: 'READY', scope: 'python-compatibility', businessReady: false });
        expect(await supervisor.stop()).toMatchObject({ state: 'STOPPED', businessReady: false });
        expect(fake.commands).toEqual(['status', 'status', 'shutdown']);
        expect(await supervisor.start()).toMatchObject({ state: 'READY' });
        expect(fake.started).toBe(2);
        await supervisor.stop();
    });

    it('rejects an observed tuple before creating a child', async () => {
        const { root, executableHash } = await fixture('observed');
        const fake = fakePython();
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: executableHash, entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root, spawn: fake.spawn });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'PYTHON_BUNDLE_NOT_ADMITTED' });
        expect(fake.started).toBe(0);
    });

    it('rejects a changed runtime fingerprint before creating a child', async () => {
        const { root } = await fixture();
        const fake = fakePython();
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: '0'.repeat(64), entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root, spawn: fake.spawn });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'PYTHON_RUNTIME_HASH_MISMATCH' });
        expect(fake.started).toBe(0);
    });

    it.each(['forged', 'business-ready'] as const)('rejects a %s handshake and cooperatively closes its own pipe', async mode => {
        const { root, executableHash } = await fixture();
        const fake = fakePython(mode);
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: executableHash, entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root,
            spawn: fake.spawn, timeoutMs: 200 });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'PYTHON_CONTROL_INVALID' });
        expect(fake.commands).toEqual([]);
    });

    it('keeps a timed-out shutdown failed until close, then starts a new UUID cleanly', async () => {
        const { root, executableHash } = await fixture();
        const fake = fakePython('no-exit');
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: executableHash, entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root,
            spawn: fake.spawn, timeoutMs: 50 });
        await supervisor.start();
        await expect(supervisor.stop()).rejects.toMatchObject({ code: 'PYTHON_EXIT_TIMEOUT' });
        await new Promise(resolve => setImmediate(resolve));
        expect(fake.started).toBe(1);
        expect(fake.commands).toEqual(['status', 'status', 'shutdown']);
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED', lastError: { code: 'PYTHON_EXIT_TIMEOUT' } });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'PYTHON_OWNERSHIP_UNRESOLVED' });

        const firstInstanceId = fake.instanceIds[0];
        fake.children[0].emit('close', 0);
        await new Promise(resolve => setImmediate(resolve));
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED', lastError: { code: 'PYTHON_EXIT_TIMEOUT' } });

        expect(await supervisor.start()).toMatchObject({ state: 'READY' });
        expect(fake.started).toBe(2);
        expect(fake.instanceIds[1]).not.toBe(firstInstanceId);
        expect(await supervisor.stop()).toMatchObject({ state: 'STOPPED' });
        expect(fake.commands).toEqual(['status', 'status', 'shutdown', 'status', 'status', 'shutdown']);
    });

    it('serializes READY status checks and ignores late status and diagnostics after timeout', async () => {
        const { root, executableHash } = await fixture();
        const fake = fakePython('hold-ready-status');
        const supervisor = new PythonCompatibilitySupervisor({ executable: process.execPath,
            executableSha256: executableHash, entryPoint: path.join(root, 'manifest.json'), bundleDirectory: root,
            spawn: fake.spawn, timeoutMs: 200 });
        await supervisor.start();

        const verification = supervisor.start();
        await expect(supervisor.stop()).rejects.toMatchObject({ code: 'SERVICE_BUSY' });
        await expect(verification).rejects.toMatchObject({ code: 'PYTHON_REQUEST_TIMEOUT' });
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED', lastError: { code: 'PYTHON_REQUEST_TIMEOUT' } });

        fake.reply(0, 1);
        fake.sendDiagnostic(0, { stage: 'preflight', code: 'PYTHON_LATE_DIAGNOSTIC', detail: 'late diagnostic' });
        await new Promise(resolve => setImmediate(resolve));
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED', lastError: { code: 'PYTHON_REQUEST_TIMEOUT' } });

        fake.children[0].emit('close', 0);
        await new Promise(resolve => setImmediate(resolve));
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED', lastError: { code: 'PYTHON_REQUEST_TIMEOUT' } });
    });
});
