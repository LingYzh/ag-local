import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { UtilityProcess } from 'electron';
import type { WorkerRequest } from '../src/shared/contracts';
import { ServiceSupervisor } from '../src/main/service-supervisor';

class FakeChild extends EventEmitter {
    readonly requests: WorkerRequest[] = [];

    postMessage(message: unknown): void {
        this.requests.push(message as WorkerRequest);
    }

    sendReady(instanceId: string): void {
        this.emit('message', {
            kind: 'ready',
            version: 1,
            instanceId,
            scope: 'diagnostics',
            businessReady: false
        });
    }

    sendResponse(request: WorkerRequest, value: unknown): void {
        this.emit('message', {
            kind: 'response',
            version: 1,
            instanceId: request.instanceId,
            requestId: request.requestId,
            result: { ok: true, value }
        });
    }

    exit(code = 0): void {
        this.emit('exit', code);
    }
}

function asUtilityProcess(child: FakeChild): UtilityProcess {
    return child as unknown as UtilityProcess;
}

function createHarness(timeoutMs = 100): {
    supervisor: ServiceSupervisor;
    children: FakeChild[];
    fork: ReturnType<typeof vi.fn>;
} {
    const children: FakeChild[] = [];
    const fork = vi.fn((_workerPath: string, _instanceId: string) => {
        const child = new FakeChild();
        children.push(child);
        return asUtilityProcess(child);
    });
    return {
        supervisor: new ServiceSupervisor('worker.cjs', { fork, timeoutMs }),
        children,
        fork
    };
}

function runtimeStatus(state: 'READY' | 'STOPPED', instanceId: string): Record<string, unknown> {
    return {
        state,
        instanceId,
        scope: 'diagnostics',
        businessReady: false,
        lastError: null
    };
}

describe('ServiceSupervisor lifecycle', () => {
    it('accepts only a matching diagnostics-ready handshake', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;

        await Promise.resolve();
        child.sendReady(randomUUID());
        expect(supervisor.getStatus().state).toBe('PREFLIGHT');
        child.sendReady(instanceId);

        await expect(starting).resolves.toMatchObject({
            state: 'READY',
            instanceId,
            scope: 'diagnostics',
            businessReady: false
        });
    });

    it('shares concurrent start calls and forks once', async () => {
        const { supervisor, children, fork } = createHarness();
        const first = supervisor.start();
        const second = supervisor.start();
        const instanceId = fork.mock.calls[0][1] as string;

        await Promise.resolve();
        expect(second).toBe(first);
        expect(fork).toHaveBeenCalledTimes(1);
        children[0].sendReady(instanceId);
        await Promise.all([first, second]);
        expect(supervisor.getStatus().state).toBe('READY');
    });

    it('waits for an in-flight start before stopping and rejects new starts while stopping', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();

        const stopping = supervisor.stop();
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'SERVICE_BUSY' });
        child.sendReady(instanceId);
        await expect(starting).resolves.toMatchObject({ state: 'READY', instanceId });

        await Promise.resolve();
        const shutdown = child.requests.find(request => request.command === 'shutdown');
        if (!shutdown) throw new Error('Stop did not send a shutdown request after start completed');
        child.sendResponse(shutdown, runtimeStatus('STOPPED', instanceId));
        child.exit(0);

        await expect(stopping).resolves.toMatchObject({ state: 'STOPPED', instanceId });
    });

    it('waits for the shutdown response and owned child exit', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        child.sendReady(instanceId);
        await starting;

        const stopping = supervisor.stop();
        const shutdown = child.requests[0];
        expect(shutdown.command).toBe('shutdown');
        expect(supervisor.getStatus().state).toBe('DRAINING');
        child.sendResponse(shutdown, runtimeStatus('STOPPED', instanceId));
        child.exit(0);

        await expect(stopping).resolves.toMatchObject({ state: 'STOPPED', instanceId });
    });

    it('rejects a forged shutdown success payload without treating it as an acknowledgement', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        child.sendReady(instanceId);
        await starting;

        const stopping = supervisor.stop();
        const shutdown = child.requests[0];
        child.sendResponse(shutdown, runtimeStatus('STOPPED', randomUUID()));

        await expect(stopping).rejects.toMatchObject({ code: 'WORKER_RESPONSE_INVALID' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            lastError: { code: 'WORKER_RESPONSE_INVALID' }
        });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        child.exit(0);
    });

    it('rejects a malformed bundle report from the worker', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        child.sendReady(instanceId);
        await starting;

        const inspection = supervisor.inspect('C:\\fixture');
        child.sendResponse(child.requests[0], {
            tupleId: 'fixture',
            state: 'observed',
            artifactsVerified: -1,
            manifestComplete: false,
            declaredHallPassed: false,
            businessReady: false,
            issues: [],
            schema: null
        });

        await expect(inspection).rejects.toMatchObject({ code: 'WORKER_RESPONSE_INVALID' });
        expect(supervisor.getStatus()).toMatchObject({ state: 'FAILED' });
        child.exit(0);
    });

    it('rejects in-flight requests and reports a failed state after an unexpected exit', async () => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const child = children[0];
        const instanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        child.sendReady(instanceId);
        await starting;

        const inspection = supervisor.inspect('C:\\fixture');
        expect(child.requests[0].command).toBe('inspect');
        child.exit(9);

        await expect(inspection).rejects.toMatchObject({ code: 'WORKER_EXITED' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId,
            lastError: { code: 'WORKER_EXITED' }
        });
    });

    it('retains a timed-out child and ignores messages from its old instance after restart', async () => {
        const { supervisor, children, fork } = createHarness(25);
        const starting = supervisor.start();
        const oldChild = children[0];
        const oldInstanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        oldChild.sendReady(oldInstanceId);
        await starting;

        const inspection = supervisor.inspect('C:\\fixture');
        await expect(inspection).rejects.toMatchObject({ code: 'WORKER_REQUEST_TIMEOUT' });
        expect(supervisor.getStatus().state).toBe('FAILED');
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        expect(fork).toHaveBeenCalledTimes(1);

        oldChild.exit(0);
        const restarting = supervisor.start();
        const newChild = children[1];
        const newInstanceId = fork.mock.calls[1][1] as string;
        await Promise.resolve();
        oldChild.sendReady(oldInstanceId);
        expect(supervisor.getStatus().state).toBe('PREFLIGHT');
        expect(supervisor.getStatus().instanceId).toBe(newInstanceId);
        newChild.sendReady(newInstanceId);
        await expect(restarting).resolves.toMatchObject({ state: 'READY', instanceId: newInstanceId });
    });

    it('preserves an acknowledged shutdown timeout through a retry and late exit, then starts a new instance', async () => {
        const { supervisor, children, fork } = createHarness(25);
        const starting = supervisor.start();
        const oldChild = children[0];
        const oldInstanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        oldChild.sendReady(oldInstanceId);
        await starting;

        const stopping = supervisor.stop();
        const shutdown = oldChild.requests[0];
        expect(shutdown.command).toBe('shutdown');
        oldChild.sendResponse(shutdown, runtimeStatus('STOPPED', oldInstanceId));
        await expect(stopping).rejects.toMatchObject({ code: 'WORKER_EXIT_TIMEOUT' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: oldInstanceId,
            lastError: { code: 'WORKER_EXIT_TIMEOUT' }
        });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        expect(fork).toHaveBeenCalledTimes(1);

        const repeatedStop = supervisor.stop();
        const repeatedShutdown = oldChild.requests[1];
        if (repeatedShutdown) oldChild.sendResponse(repeatedShutdown, runtimeStatus('STOPPED', oldInstanceId));
        oldChild.exit(0);
        await expect(repeatedStop).rejects.toMatchObject({ code: 'WORKER_EXIT_TIMEOUT' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: oldInstanceId,
            lastError: { code: 'WORKER_EXIT_TIMEOUT' }
        });

        const restarting = supervisor.start();
        const newChild = children[1];
        const newInstanceId = fork.mock.calls[1][1] as string;
        expect(newInstanceId).not.toBe(oldInstanceId);
        await Promise.resolve();
        oldChild.exit(9);
        oldChild.sendReady(oldInstanceId);
        expect(supervisor.getStatus()).toMatchObject({ state: 'PREFLIGHT', instanceId: newInstanceId });
        newChild.sendReady(newInstanceId);
        await expect(restarting).resolves.toMatchObject({ state: 'READY', instanceId: newInstanceId });

        const inspection = supervisor.inspect('C:\\fixture');
        await expect(inspection).rejects.toMatchObject({ code: 'WORKER_REQUEST_TIMEOUT' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: newInstanceId,
            lastError: { code: 'WORKER_REQUEST_TIMEOUT' }
        });
        oldChild.exit(0);
        oldChild.sendReady(oldInstanceId);
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: newInstanceId,
            lastError: { code: 'WORKER_REQUEST_TIMEOUT' }
        });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        expect(fork).toHaveBeenCalledTimes(2);
    });

    it.each([0, 9])('keeps the first control fault when an unacknowledged instance exits with code %i', async exitCode => {
        const { supervisor, children, fork } = createHarness();
        const starting = supervisor.start();
        const oldChild = children[0];
        const oldInstanceId = fork.mock.calls[0][1] as string;
        await Promise.resolve();
        oldChild.sendReady(oldInstanceId);
        await starting;

        const stopping = supervisor.stop();
        const shutdown = oldChild.requests[0];
        oldChild.sendResponse(shutdown, runtimeStatus('STOPPED', randomUUID()));
        await expect(stopping).rejects.toMatchObject({ code: 'WORKER_RESPONSE_INVALID' });
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: oldInstanceId,
            lastError: { code: 'WORKER_RESPONSE_INVALID' }
        });
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        expect(fork).toHaveBeenCalledTimes(1);

        oldChild.exit(exitCode);
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: oldInstanceId,
            lastError: { code: 'WORKER_RESPONSE_INVALID' }
        });
        oldChild.exit(exitCode === 0 ? 9 : 0);
        expect(supervisor.getStatus()).toMatchObject({
            state: 'FAILED',
            instanceId: oldInstanceId,
            lastError: { code: 'WORKER_RESPONSE_INVALID' }
        });

        const restarting = supervisor.start();
        const newChild = children[1];
        const newInstanceId = fork.mock.calls[1][1] as string;
        expect(newInstanceId).not.toBe(oldInstanceId);
        await Promise.resolve();
        oldChild.sendReady(oldInstanceId);
        oldChild.exit(0);
        expect(supervisor.getStatus()).toMatchObject({ state: 'PREFLIGHT', instanceId: newInstanceId });
        newChild.sendReady(newInstanceId);
        await expect(restarting).resolves.toMatchObject({ state: 'READY', instanceId: newInstanceId });
    });

    it('fails a handshake timeout without discarding ownership or replacing the child', async () => {
        const { supervisor, children, fork } = createHarness(20);
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_READY_TIMEOUT' });
        expect(supervisor.getStatus().state).toBe('FAILED');
        expect(children).toHaveLength(1);
        await expect(supervisor.start()).rejects.toMatchObject({ code: 'WORKER_OWNERSHIP_UNRESOLVED' });
        expect(fork).toHaveBeenCalledTimes(1);
    });
});
