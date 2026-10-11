import { randomUUID } from 'node:crypto';
import type { ForkOptions, UtilityProcess } from 'electron';
import {
    CONTROL_VERSION
} from '../shared/contracts';
import type {
    BundleReport,
    FoundationFault,
    LifecycleState,
    RuntimeStatus,
    WorkerCommand,
    WorkerReady,
    WorkerRequest
} from '../shared/contracts';
import { isInstanceId, isRecord } from '../shared/validation';
import type { ClientInventory } from '../shared/client-contracts';
import { isClientInventory } from '../shared/client-validation';

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_PENDING_REQUESTS = 32;

type WorkerFork = (workerPath: string, instanceId: string) => UtilityProcess | Promise<UtilityProcess>;

export interface ServiceSupervisorOptions {
    fork?: WorkerFork;
    timeoutMs?: number;
}

interface PendingRequest {
    command: WorkerCommand;
    resolve: (value: unknown) => void;
    reject: (reason: Error) => void;
    timer: ReturnType<typeof setTimeout>;
}

interface ManagedChild {
    process: UtilityProcess;
    instanceId: string;
    ready: boolean;
    expectedExit: boolean;
    shutdownAcknowledged: boolean;
    exited: boolean;
    exitCode: number | null;
    readyTimer: ReturnType<typeof setTimeout> | null;
    pending: Map<string, PendingRequest>;
    readyPromise: Promise<void>;
    resolveReady: () => void;
    rejectReady: (reason: Error) => void;
    exitPromise: Promise<number>;
    resolveExit: (code: number) => void;
}

function defaultFork(workerPath: string, instanceId: string): Promise<UtilityProcess> {
    return import('electron').then(({ utilityProcess }) => {
        const options: ForkOptions = { stdio: 'pipe' };
        return utilityProcess.fork(workerPath, [instanceId], options);
    });
}

function makeError(code: string, detail: string): Error & FoundationFault {
    return Object.assign(new Error(detail), { code, detail });
}

function errorFault(error: unknown, fallbackCode: string): FoundationFault {
    if (isRecord(error) && typeof error.code === 'string' && typeof error.detail === 'string') {
        return { code: error.code, detail: error.detail };
    }
    return {
        code: fallbackCode,
        detail: error instanceof Error ? error.message : 'Unexpected worker error'
    };
}

function hasOnlyKeys(value: Record<string, unknown>, keys: string[]): boolean {
    return Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
}

function isReadyMessage(value: unknown, instanceId: string): value is WorkerReady {
    return isRecord(value)
        && hasOnlyKeys(value, ['kind', 'version', 'instanceId', 'scope', 'businessReady'])
        && value.kind === 'ready'
        && value.version === CONTROL_VERSION
        && value.instanceId === instanceId
        && value.scope === 'diagnostics'
        && value.businessReady === false;
}

interface ParsedWorkerResponse {
    requestId: string;
    result: { ok: true; value: unknown } | { ok: false; error: FoundationFault };
}

function isFoundationFault(value: unknown): value is FoundationFault {
    return isRecord(value)
        && hasOnlyKeys(value, ['code', 'detail'])
        && typeof value.code === 'string'
        && value.code.length > 0
        && typeof value.detail === 'string';
}

function parseWorkerResponse(value: Record<string, unknown>, instanceId: string): ParsedWorkerResponse | null {
    if (!hasOnlyKeys(value, ['kind', 'version', 'instanceId', 'requestId', 'result'])
        || value.kind !== 'response'
        || value.version !== CONTROL_VERSION
        || value.instanceId !== instanceId
        || !isInstanceId(value.requestId)
        || !isRecord(value.result)) {
        return null;
    }
    if (value.result.ok === true
        && hasOnlyKeys(value.result, ['ok', 'value'])
        && Object.prototype.hasOwnProperty.call(value.result, 'value')) {
        return { requestId: value.requestId, result: { ok: true, value: value.result.value } };
    }
    if (value.result.ok === false
        && hasOnlyKeys(value.result, ['ok', 'error'])
        && isFoundationFault(value.result.error)) {
        return { requestId: value.requestId, result: { ok: false, error: value.result.error } };
    }
    return null;
}

function isRuntimeStatus(value: unknown, instanceId: string, state: 'READY' | 'STOPPED'): boolean {
    return isRecord(value)
        && hasOnlyKeys(value, ['state', 'instanceId', 'scope', 'businessReady', 'lastError'])
        && value.state === state
        && value.instanceId === instanceId
        && value.scope === 'diagnostics'
        && value.businessReady === false
        && (value.lastError === null || isFoundationFault(value.lastError));
}

function isBundleReport(value: unknown): value is BundleReport {
    if (!isRecord(value)
        || !hasOnlyKeys(value, [
            'tupleId', 'state', 'artifactsVerified', 'manifestComplete',
            'declaredHallPassed', 'businessReady', 'issues', 'schema'
        ])
        || typeof value.tupleId !== 'string'
        || value.tupleId.length === 0
        || value.tupleId.length > 64
        || typeof value.state !== 'string'
        || value.state.length === 0
        || !Number.isSafeInteger(value.artifactsVerified)
        || (value.artifactsVerified as number) < 0
        || typeof value.manifestComplete !== 'boolean'
        || typeof value.declaredHallPassed !== 'boolean'
        || value.businessReady !== false
        || !Array.isArray(value.issues)
        || !value.issues.every(issue => typeof issue === 'string')) {
        return false;
    }
    if (value.schema === null) return true;
    return isRecord(value.schema)
        && hasOnlyKeys(value.schema, ['sha256', 'messages', 'fields'])
        && typeof value.schema.sha256 === 'string'
        && /^[a-f0-9]{64}$/i.test(value.schema.sha256)
        && Number.isSafeInteger(value.schema.messages)
        && (value.schema.messages as number) >= 0
        && Number.isSafeInteger(value.schema.fields)
        && (value.schema.fields as number) >= 0;
}

export class ServiceSupervisor {
    private readonly forkWorker: WorkerFork;
    private readonly timeoutMs: number;
    private state: LifecycleState = 'CREATED';
    private instanceId: string | null = null;
    private lastError: FoundationFault | null = null;
    private child: ManagedChild | null = null;
    private startOperation: Promise<RuntimeStatus> | null = null;
    private stopOperation: Promise<RuntimeStatus> | null = null;

    constructor(workerPath: string, options: ServiceSupervisorOptions = {}) {
        this.workerPath = workerPath;
        this.forkWorker = options.fork ?? defaultFork;
        this.timeoutMs = Number.isFinite(options.timeoutMs) && (options.timeoutMs ?? 0) > 0
            ? options.timeoutMs!
            : DEFAULT_TIMEOUT_MS;
    }

    private readonly workerPath: string;

    getStatus(): RuntimeStatus {
        return {
            state: this.state,
            instanceId: this.instanceId,
            scope: 'diagnostics',
            businessReady: false,
            lastError: this.lastError ? { ...this.lastError } : null
        };
    }

    start(): Promise<RuntimeStatus> {
        if (this.stopOperation) return Promise.reject(makeError('SERVICE_BUSY', 'The service is stopping'));
        if (this.startOperation) return this.startOperation;
        if (this.state === 'READY' && this.child?.ready) return Promise.resolve(this.getStatus());
        if (this.child) {
            return Promise.reject(makeError('WORKER_OWNERSHIP_UNRESOLVED', 'The previous worker is still owned and cannot be replaced'));
        }

        const operation = this.startInternal();
        this.startOperation = operation;
        void operation.then(
            () => { if (this.startOperation === operation) this.startOperation = null; },
            () => { if (this.startOperation === operation) this.startOperation = null; }
        );
        return operation;
    }

    stop(): Promise<RuntimeStatus> {
        if (this.stopOperation) return this.stopOperation;

        const operation = this.startOperation
            ? this.startOperation.then(() => this.stopInternal(), () => this.stopInternal())
            : this.stopInternal();
        this.stopOperation = operation;
        void operation.then(
            () => { if (this.stopOperation === operation) this.stopOperation = null; },
            () => { if (this.stopOperation === operation) this.stopOperation = null; }
        );
        return operation;
    }

    inspect(directory: string): Promise<BundleReport> {
        const child = this.child;
        if (!child || !child.ready || this.state !== 'READY') {
            return Promise.reject(makeError('SERVICE_NOT_READY', 'Start the diagnostics worker before inspecting a bundle'));
        }
        return this.sendRequest<BundleReport>(child, 'inspect', directory);
    }

    inventory(directory: string): Promise<ClientInventory> {
        const child = this.child;
        if (!child || !child.ready || this.state !== 'READY') {
            return Promise.reject(makeError('SERVICE_NOT_READY', 'Start the diagnostics worker before inspecting the client'));
        }
        return this.sendRequest<ClientInventory>(child, 'inventory', directory);
    }

    private async startInternal(): Promise<RuntimeStatus> {
        const instanceId = randomUUID();
        this.instanceId = instanceId;
        this.state = 'PREFLIGHT';
        this.lastError = null;

        let worker: UtilityProcess;
        try {
            worker = await this.forkWorker(this.workerPath, instanceId);
        } catch (error) {
            this.state = 'FAILED';
            this.lastError = errorFault(error, 'WORKER_START_FAILED');
            throw makeError(this.lastError.code, this.lastError.detail);
        }

        let resolveReady!: () => void;
        let rejectReady!: (reason: Error) => void;
        const readyPromise = new Promise<void>((resolve, reject) => {
            resolveReady = resolve;
            rejectReady = reject;
        });
        let resolveExit!: (code: number) => void;
        const exitPromise = new Promise<number>(resolve => { resolveExit = resolve; });
        const record: ManagedChild = {
            process: worker,
            instanceId,
            ready: false,
            expectedExit: false,
            shutdownAcknowledged: false,
            exited: false,
            exitCode: null,
            readyTimer: null,
            pending: new Map(),
            readyPromise,
            resolveReady,
            rejectReady,
            exitPromise,
            resolveExit
        };
        this.child = record;
        worker.on('message', message => this.handleMessage(record, message));
        worker.on('exit', code => this.handleExit(record, code));
        worker.on('error', (type, location, report) => {
            const detail = [type, location, report].filter(value => value !== undefined).map(String).join(' ');
            this.failRecord(record, { code: 'WORKER_PROCESS_ERROR', detail: detail || 'Worker process error' });
        });

        record.readyTimer = setTimeout(() => {
            const issue = { code: 'WORKER_READY_TIMEOUT', detail: 'Worker did not complete its identity handshake in time' };
            this.failRecord(record, issue);
            record.rejectReady(makeError(issue.code, issue.detail));
        }, this.timeoutMs);

        try {
            await record.readyPromise;
        } catch (error) {
            if (this.child === record && !record.exited) {
                this.failRecord(record, errorFault(error, 'WORKER_START_FAILED'));
            }
            throw error instanceof Error ? error : makeError('WORKER_START_FAILED', 'Worker failed to start');
        } finally {
            if (record.readyTimer) clearTimeout(record.readyTimer);
            record.readyTimer = null;
        }

        if (this.child !== record || !record.ready || this.getStatus().state !== 'READY') {
            throw makeError('WORKER_START_FAILED', 'Worker identity could not be confirmed');
        }
        return this.getStatus();
    }

    private async stopInternal(): Promise<RuntimeStatus> {
        const record = this.child;
        if (!record) {
            this.state = 'STOPPED';
            return this.getStatus();
        }
        if (!record.ready || (this.state !== 'READY' && this.state !== 'FAILED')) {
            throw makeError('WORKER_IDENTITY_UNVERIFIED', 'The owned worker has no verified identity and cannot receive control commands');
        }

        this.state = 'DRAINING';
        record.expectedExit = true;
        try {
            await this.sendRequest<RuntimeStatus>(record, 'shutdown', undefined, true);
            record.shutdownAcknowledged = true;
            const code = await this.waitForExit(record);
            if (code !== 0) {
                throw makeError('WORKER_EXIT_FAILED', `Worker exited with code ${code}`);
            }
            if (this.child === record) {
                this.child = null;
                this.state = 'STOPPED';
                this.lastError = null;
            }
            return this.getStatus();
        } catch (error) {
            const issue = errorFault(error, 'WORKER_STOP_FAILED');
            if (this.child === record && !record.exited) this.failRecord(record, issue);
            throw makeError(issue.code, issue.detail);
        }
    }

    private sendRequest<T extends RuntimeStatus | BundleReport | ClientInventory>(
        record: ManagedChild,
        command: WorkerCommand,
        directory?: string,
        whileDraining = false
    ): Promise<T> {
        const expectedState = whileDraining ? 'DRAINING' : 'READY';
        if (this.child !== record || !record.ready || this.state !== expectedState) {
            return Promise.reject(makeError('SERVICE_NOT_READY', 'The diagnostics worker is not ready for this command'));
        }
        if (record.pending.size >= MAX_PENDING_REQUESTS) {
            return Promise.reject(makeError('WORKER_BUSY', 'The worker has too many pending requests'));
        }

        const requestId = randomUUID();
        const request: WorkerRequest = {
            version: CONTROL_VERSION,
            instanceId: record.instanceId,
            requestId,
            command,
            ...(directory === undefined ? {} : { directory })
        };

        return new Promise<T>((resolve, reject) => {
            const timer = setTimeout(() => {
                const issue = { code: 'WORKER_REQUEST_TIMEOUT', detail: `Worker command '${command}' timed out` };
                this.failRecord(record, issue);
            }, this.timeoutMs);
            record.pending.set(requestId, {
                command,
                resolve: value => resolve(value as T),
                reject,
                timer
            });
            try {
                record.process.postMessage(request);
            } catch (error) {
                this.failRecord(record, errorFault(error, 'WORKER_SEND_FAILED'));
            }
        });
    }

    private handleMessage(record: ManagedChild, message: unknown): void {
        if (this.child !== record) return;
        if (isRecord(message) && message.kind === 'response' && message.instanceId === record.instanceId) {
            if (!record.ready) {
                this.failRecord(record, {
                    code: 'WORKER_RESPONSE_INVALID',
                    detail: 'Worker sent a response before completing its identity handshake'
                });
                return;
            }
            const response = parseWorkerResponse(message, record.instanceId);
            if (!response) {
                this.failRecord(record, { code: 'WORKER_RESPONSE_INVALID', detail: 'Worker response envelope is invalid' });
                return;
            }
            const pending = record.pending.get(response.requestId);
            if (!pending) return;

            if (response.result.ok) {
                const validPayload = pending.command === 'inspect'
                    ? isBundleReport(response.result.value)
                    : pending.command === 'inventory' ? isClientInventory(response.result.value)
                    : isRuntimeStatus(response.result.value, record.instanceId,
                        pending.command === 'shutdown' ? 'STOPPED' : 'READY');
                if (!validPayload) {
                    this.failRecord(record, {
                        code: 'WORKER_RESPONSE_INVALID',
                        detail: `Worker returned an invalid '${pending.command}' payload`
                    });
                    return;
                }
            }

            clearTimeout(pending.timer);
            record.pending.delete(response.requestId);
            if (response.result.ok) {
                if (pending.command === 'shutdown') record.shutdownAcknowledged = true;
                pending.resolve(response.result.value);
            } else {
                pending.reject(makeError(response.result.error.code, response.result.error.detail));
            }
            return;
        }
        if (!record.ready) {
            if (this.state === 'PREFLIGHT' && isReadyMessage(message, record.instanceId)) {
                record.ready = true;
                this.state = 'READY';
                this.lastError = null;
                record.resolveReady();
            }
            return;
        }
    }

    private handleExit(record: ManagedChild, code: number): void {
        if (record.exited) return;
        record.exited = true;
        record.exitCode = code;
        if (record.readyTimer) clearTimeout(record.readyTimer);
        record.readyTimer = null;
        record.resolveExit(code);
        record.rejectReady(makeError('WORKER_EXITED', `Worker exited before becoming ready (code ${code})`));

        const issue = record.expectedExit && record.shutdownAcknowledged && code === 0
            ? null
            : { code: 'WORKER_EXITED', detail: `Worker exited unexpectedly with code ${code}` };
        this.rejectPending(record, makeError(issue?.code ?? 'WORKER_EXITED', issue?.detail ?? 'Worker exited'));

        if (this.child !== record) return;
        this.child = null;
        if (issue) {
            this.state = 'FAILED';
            this.lastError = issue;
        } else {
            this.state = 'STOPPED';
            this.lastError = null;
        }
    }

    private waitForExit(record: ManagedChild): Promise<number> {
        if (record.exited) return Promise.resolve(record.exitCode ?? -1);
        return new Promise<number>((resolve, reject) => {
            const timer = setTimeout(() => {
                const issue = { code: 'WORKER_EXIT_TIMEOUT', detail: 'Worker acknowledged shutdown but did not exit in time' };
                this.failRecord(record, issue);
                reject(makeError(issue.code, issue.detail));
            }, this.timeoutMs);
            void record.exitPromise.then(code => {
                clearTimeout(timer);
                resolve(code);
            });
        });
    }

    private failRecord(record: ManagedChild, issue: FoundationFault): void {
        if (this.child === record && this.state !== 'STOPPED') {
            this.state = 'FAILED';
            this.lastError = { ...issue };
        }
        this.rejectPending(record, makeError(issue.code, issue.detail));
    }

    private rejectPending(record: ManagedChild, error: Error): void {
        for (const [requestId, pending] of record.pending) {
            clearTimeout(pending.timer);
            pending.reject(error);
            record.pending.delete(requestId);
        }
    }
}
