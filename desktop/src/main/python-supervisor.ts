import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import type { FoundationFault } from '../shared/contracts';
import type { PythonCompatibilityStatus } from '../shared/python-contracts';
import { fault, isInstanceId, isRecord } from '../shared/validation';
import { inspectBundle } from '../service/compatibility';
import { parseJsonBytes } from '../service/compatibility/json';

const MAX_LINE_BYTES = 64 * 1024;
const ADMITTED_STATES = new Set(['imported', 'static_passed', 'hall_passed', 'flows_passed']);

interface PythonOptions {
    executable: string;
    executableSha256: string;
    entryPoint: string;
    bundleDirectory: string;
    timeoutMs?: number;
    spawn?: typeof spawn;
}

interface Pending {
    command: 'status' | 'shutdown';
    resolve: (value: PythonCompatibilityStatus) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
}

interface OwnedChild {
    process: ChildProcessWithoutNullStreams;
    instanceId: string;
    tupleId: string;
    ready: boolean;
    acknowledged: boolean;
    failed: boolean;
    exited: boolean;
    buffer: Buffer;
    diagnosticBuffer: Buffer;
    lastFault: FoundationFault | null;
    pending: Map<string, Pending>;
    resolveReady: () => void;
    rejectReady: (error: Error) => void;
    exit: Promise<number>;
    resolveExit: (code: number) => void;
}

function problem(code: string, detail: string): Error & FoundationFault {
    return Object.assign(new Error(detail), { code, detail });
}

function exact(value: Record<string, unknown>, keys: string[]): boolean {
    return Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
}

async function fileHash(filename: string): Promise<string> {
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(filename)) hash.update(chunk);
    return hash.digest('hex');
}

/** Controls only the child created here, through its private pipes. Never uses PID/name lookup or kill. */
export class PythonCompatibilitySupervisor {
    private child: OwnedChild | null = null;
    private operation: Promise<PythonCompatibilityStatus> | null = null;
    private current: PythonCompatibilityStatus = {
        state: 'CREATED', instanceId: null, scope: 'python-compatibility',
        businessReady: false, tupleId: null, lastError: null
    };

    constructor(private readonly options: PythonOptions) {}

    getStatus(): PythonCompatibilityStatus {
        return { ...this.current, lastError: this.current.lastError ? { ...this.current.lastError } : null };
    }

    start(): Promise<PythonCompatibilityStatus> {
        if (this.operation) return Promise.reject(problem('SERVICE_BUSY', 'A lifecycle operation is already pending'));
        if (this.current.state === 'READY' && this.child?.ready && !this.child.failed) {
            return this.ownOperation(this.verifyStatus());
        }
        if (this.child) return Promise.reject(problem('PYTHON_OWNERSHIP_UNRESOLVED', 'The previous child has not exited'));
        return this.ownOperation(this.startInternal());
    }

    stop(): Promise<PythonCompatibilityStatus> {
        if (this.operation) return Promise.reject(problem('SERVICE_BUSY', 'A lifecycle operation is already pending'));
        return this.ownOperation(this.stopInternal());
    }

    private ownOperation(operation: Promise<PythonCompatibilityStatus>): Promise<PythonCompatibilityStatus> {
        this.operation = operation;
        void operation.then(() => { this.operation = null; }, () => { this.operation = null; });
        return operation;
    }

    private async startInternal(): Promise<PythonCompatibilityStatus> {
        this.current = { ...this.current, state: 'PREFLIGHT', lastError: null };
        let child: OwnedChild | null = null;
        try {
            for (const filename of [this.options.executable, this.options.entryPoint, this.options.bundleDirectory]) {
                if (!path.isAbsolute(filename)) throw problem('PYTHON_PATH_INVALID', 'Explicit absolute paths are required');
            }
            if (!/^[a-f0-9]{64}$/i.test(this.options.executableSha256)) {
                throw problem('PYTHON_RUNTIME_UNLOCKED', 'The Python executable must have an explicit SHA-256');
            }
            const executable = await realpath(this.options.executable);
            if (await fileHash(executable) !== this.options.executableSha256.toLowerCase()) {
                throw problem('PYTHON_RUNTIME_HASH_MISMATCH', 'Python runtime fingerprint changed');
            }
            const entryPoint = await realpath(this.options.entryPoint);
            const bundle = await realpath(this.options.bundleDirectory);
            const report = await inspectBundle(bundle);
            if (!report.manifestComplete || !ADMITTED_STATES.has(report.state)) {
                throw problem('PYTHON_BUNDLE_NOT_ADMITTED', 'A complete, hash-verified imported tuple is required');
            }
            const instanceId = randomUUID();
            const spawnChild = this.options.spawn ?? spawn;
            const process = spawnChild(executable, ['-I', '-u', entryPoint, '--instance-id', instanceId, '--bundle', bundle], {
                cwd: path.dirname(entryPoint), shell: false, windowsHide: true,
                stdio: ['pipe', 'pipe', 'pipe']
            }) as ChildProcessWithoutNullStreams;
            let resolveReady!: () => void;
            let rejectReady!: (error: Error) => void;
            const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
            let resolveExit!: (code: number) => void;
            const exit = new Promise<number>(resolve => { resolveExit = resolve; });
            const ownedChild: OwnedChild = {
                process, instanceId, tupleId: report.tupleId, ready: false,
                acknowledged: false, failed: false, exited: false, buffer: Buffer.alloc(0),
                diagnosticBuffer: Buffer.alloc(0), lastFault: null,
                pending: new Map(), resolveReady, rejectReady, exit, resolveExit
            };
            child = ownedChild;
            this.child = ownedChild;
            this.current = { ...this.current, instanceId, tupleId: ownedChild.tupleId };
            process.stdout.on('data', (chunk: Buffer) => this.consume(ownedChild, chunk));
            // Accept only the controlled entry's small structured preflight errors, never raw logs.
            process.stderr.on('data', (chunk: Buffer) => this.diagnostic(ownedChild, chunk));
            process.stdin.on('error', () => this.fail(ownedChild, problem('PYTHON_PIPE_CLOSED', 'The private control pipe closed')));
            process.on('error', () => this.fail(ownedChild, problem('PYTHON_SPAWN_FAILED', 'Python could not be started')));
            process.on('close', code => {
                if (ownedChild.exited) return;
                ownedChild.exited = true;
                ownedChild.ready = false;
                ownedChild.resolveExit(code ?? -1);
                const failure = ownedChild.lastFault ?? { code: 'PYTHON_EXITED', detail: `Python exited with code ${code}` };
                ownedChild.rejectReady(problem(failure.code, failure.detail));
                const normal = ownedChild.acknowledged && code === 0 && !ownedChild.failed;
                for (const pending of ownedChild.pending.values()) {
                    clearTimeout(pending.timer);
                    pending.reject(problem('PYTHON_EXITED', 'The control child exited'));
                }
                ownedChild.pending.clear();
                if (this.child === ownedChild) {
                    this.child = null;
                    this.current = { ...this.current, state: normal ? 'STOPPED' : 'FAILED',
                        lastError: normal ? null : failure };
                }
            });
            await this.withTimeout(ready, 'PYTHON_READY_TIMEOUT');
            // READY plus an independent request verifies the private child identity twice.
            await this.request(ownedChild, 'status');
            if (this.child !== ownedChild || ownedChild.exited || ownedChild.failed || !ownedChild.ready) {
                throw problem('PYTHON_IDENTITY_UNVERIFIED', 'The owned child failed before startup completed');
            }
            this.current = { ...this.current, state: 'READY', lastError: null };
            return this.getStatus();
        } catch (error) {
            if (child && this.child === child && !child.exited) {
                this.fail(child, error instanceof Error ? error : problem('PYTHON_START_FAILED', 'Python startup failed'));
            } else if (!child) {
                this.current = { ...this.current, state: 'FAILED', lastError: fault(error) };
            }
            throw error;
        }
    }

    private async verifyStatus(): Promise<PythonCompatibilityStatus> {
        const child = this.child;
        if (!child?.ready || child.failed || child.exited) {
            throw problem('PYTHON_IDENTITY_UNVERIFIED', 'Python identity is not verified');
        }
        const status = await this.request(child, 'status');
        if (this.child !== child || !child.ready || child.failed || child.exited) {
            throw problem('PYTHON_IDENTITY_UNVERIFIED', 'The owned child failed during status verification');
        }
        return status;
    }

    private async stopInternal(): Promise<PythonCompatibilityStatus> {
        const child = this.child;
        if (!child) {
            this.current = { ...this.current, state: 'STOPPED' };
            return this.getStatus();
        }
        if (!child.ready) throw problem('PYTHON_IDENTITY_UNVERIFIED', 'The owned child has no verified identity');
        try {
            await this.request(child, 'status');
            this.current = { ...this.current, state: 'DRAINING' };
            await this.request(child, 'shutdown');
            const code = await this.withTimeout(child.exit, 'PYTHON_EXIT_TIMEOUT');
            if (code !== 0) throw problem('PYTHON_EXIT_FAILED', `Python exited with code ${code}`);
            return this.getStatus();
        } catch (error) {
            this.fail(child, error instanceof Error ? error : problem('PYTHON_STOP_FAILED', 'Shutdown failed'));
            throw error;
        }
    }

    private async withTimeout<T>(promise: Promise<T>, code: string): Promise<T> {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
            return await Promise.race([promise, new Promise<T>((_resolve, reject) => {
                timer = setTimeout(() => reject(problem(code, 'The private control operation timed out')),
                    this.options.timeoutMs ?? 10_000);
            })]);
        } finally {
            clearTimeout(timer);
        }
    }

    private request(child: OwnedChild, command: Pending['command']): Promise<PythonCompatibilityStatus> {
        if (this.child !== child || !child.ready || child.failed || child.exited) {
            return Promise.reject(problem('PYTHON_IDENTITY_UNVERIFIED', 'No verified live child owns this channel'));
        }
        if (child.pending.size >= 8) return Promise.reject(problem('PYTHON_BUSY', 'Too many pending control requests'));
        const requestId = randomUUID();
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.fail(child, problem('PYTHON_REQUEST_TIMEOUT', `Python '${command}' timed out`));
            }, this.options.timeoutMs ?? 10_000);
            child.pending.set(requestId, { command, resolve, reject, timer });
            child.process.stdin.write(`${JSON.stringify({ version: 1, instanceId: child.instanceId, requestId, command })}\n`);
        });
    }

    private consume(child: OwnedChild, chunk: Buffer): void {
        if (this.child !== child || child.exited || child.failed) return;
        child.buffer = Buffer.concat([child.buffer, chunk]);
        for (;;) {
            const newline = child.buffer.indexOf(10);
            if (newline === -1) {
                if (child.buffer.length > MAX_LINE_BYTES) this.fail(child, problem('PYTHON_CONTROL_INVALID', 'Control line exceeded the limit'));
                break;
            }
            if (newline > MAX_LINE_BYTES) {
                this.fail(child, problem('PYTHON_CONTROL_INVALID', 'Control line exceeded the limit'));
                return;
            }
            const line = child.buffer.subarray(0, newline);
            child.buffer = child.buffer.subarray(newline + 1);
            try {
                const value: unknown = parseJsonBytes(line, 'PYTHON_CONTROL_INVALID', 'Python control message');
                if (!isRecord(value) || value.version !== 1 || value.instanceId !== child.instanceId) {
                    throw problem('PYTHON_CONTROL_INVALID', 'Control identity does not match the owned instance');
                }
                if (!child.ready) {
                    if (!exact(value, ['kind', 'version', 'instanceId', 'scope', 'businessReady', 'tupleId'])
                        || value.kind !== 'ready' || value.scope !== 'python-compatibility'
                        || value.businessReady !== false || value.tupleId !== child.tupleId) {
                        throw problem('PYTHON_CONTROL_INVALID', 'Invalid Python handshake');
                    }
                    child.ready = true;
                    child.resolveReady();
                    continue;
                }
                if (!exact(value, ['kind', 'version', 'instanceId', 'requestId', 'result'])
                    || value.kind !== 'response' || !isInstanceId(value.requestId) || !isRecord(value.result)) {
                    throw problem('PYTHON_CONTROL_INVALID', 'Invalid Python response envelope');
                }
                const pending = child.pending.get(value.requestId);
                if (!pending) throw problem('PYTHON_CONTROL_INVALID', 'Response has no pending request');
                const payload = value.result.value;
                const state = pending.command === 'shutdown' ? 'STOPPED' : 'READY';
                if (!exact(value.result, ['ok', 'value']) || value.result.ok !== true || !isRecord(payload)
                    || !exact(payload, ['state', 'instanceId', 'scope', 'businessReady', 'tupleId', 'lastError'])
                    || payload.state !== state || payload.instanceId !== child.instanceId
                    || payload.tupleId !== child.tupleId || payload.scope !== 'python-compatibility'
                    || payload.businessReady !== false || payload.lastError !== null) {
                    throw problem('PYTHON_CONTROL_INVALID', 'Invalid Python status payload');
                }
                child.pending.delete(value.requestId);
                clearTimeout(pending.timer);
                if (pending.command === 'shutdown') child.acknowledged = true;
                pending.resolve(payload as unknown as PythonCompatibilityStatus);
            } catch (error) {
                this.fail(child, error instanceof Error ? error : problem('PYTHON_CONTROL_INVALID', 'Invalid control JSON'));
                return;
            }
        }
    }

    private diagnostic(child: OwnedChild, chunk: Buffer): void {
        if (this.child !== child || child.exited || child.failed) return;
        child.diagnosticBuffer = Buffer.concat([child.diagnosticBuffer, chunk]);
        if (child.diagnosticBuffer.length > MAX_LINE_BYTES) {
            child.diagnosticBuffer = Buffer.alloc(0);
            return;
        }
        for (;;) {
            const newline = child.diagnosticBuffer.indexOf(10);
            if (newline < 0) return;
            const line = child.diagnosticBuffer.subarray(0, newline);
            child.diagnosticBuffer = child.diagnosticBuffer.subarray(newline + 1);
            try {
                const value = parseJsonBytes(line, 'PYTHON_DIAGNOSTIC_INVALID', 'Python diagnostic');
                if (isRecord(value) && exact(value, ['stage', 'code', 'detail'])
                    && value.stage === 'preflight' && typeof value.code === 'string'
                    && /^[A-Z][A-Z0-9_]{0,63}$/.test(value.code)
                    && typeof value.detail === 'string' && value.detail.length <= 4096) {
                    child.lastFault = { code: value.code, detail: value.detail };
                }
            } catch { /* Non-contract stderr is drained, not exposed. */ }
        }
    }

    private fail(child: OwnedChild, error: Error): void {
        if (this.child !== child || child.exited || child.failed) return;
        child.failed = true;
        child.ready = false;
        child.lastFault = fault(error, 'PYTHON_CONTROL_INVALID');
        this.current = { ...this.current, state: 'FAILED', lastError: { ...child.lastFault } };
        child.rejectReady(error);
        for (const pending of child.pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(error);
        }
        child.pending.clear();
        child.buffer = Buffer.alloc(0);
        child.process.stdin.end();
    }
}
