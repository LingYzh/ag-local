import { CONTROL_VERSION } from '../shared/contracts';
import type {
    BundleReport,
    LifecycleState,
    Result,
    RuntimeStatus,
    WorkerRequest,
    WorkerResponse
} from '../shared/contracts';
import { fault, isInstanceId, parseWorkerRequest } from '../shared/validation';
import { inspectBundle } from './compatibility';
import { inventoryClient } from './import/client-inventory';
import type { ClientInventory } from '../shared/client-contracts';

interface ParentPortLike {
    on(event: 'message', listener: (event: { data: unknown }) => void): this;
    on(event: 'close', listener: () => void): this;
    postMessage(message: unknown): void;
}

const parentPort = (process as NodeJS.Process & { parentPort?: ParentPortLike | null }).parentPort;
const instanceId = process.argv[process.argv.length - 1];

if (!parentPort || !isInstanceId(instanceId)) {
    process.exit(1);
}

const port: ParentPortLike = parentPort;
let draining = false;
let activeInspections = 0;
let shutdownRequest: WorkerRequest | null = null;

function runtimeStatus(state: LifecycleState): RuntimeStatus {
    return {
        state,
        instanceId,
        scope: 'diagnostics',
        businessReady: false,
        lastError: null
    };
}

function sendResponse(request: WorkerRequest, result: Result<RuntimeStatus | BundleReport | ClientInventory>): void {
    const response: WorkerResponse = {
        kind: 'response',
        version: CONTROL_VERSION,
        instanceId,
        requestId: request.requestId,
        result
    };
    port.postMessage(response);
}

function respondToRequest(request: WorkerRequest): Promise<void> {
    if (request.command === 'status') {
        sendResponse(request, { ok: true, value: runtimeStatus('READY') });
        return Promise.resolve();
    }
    if (request.command === 'inspect') {
        return inspectBundle(request.directory!)
            .then(report => sendResponse(request, { ok: true, value: report }))
            .catch(error => sendResponse(request, { ok: false, error: fault(error) }));
    }
    if (request.command === 'inventory') {
        return inventoryClient(request.directory!)
            .then(report => sendResponse(request, { ok: true, value: report }))
            .catch(error => sendResponse(request, { ok: false, error: fault(error) }));
    }
    return Promise.resolve();
}

function finishShutdownWhenDrained(): void {
    if (!draining || !shutdownRequest || activeInspections > 0) return;
    const request = shutdownRequest;
    shutdownRequest = null;
    sendResponse(request, { ok: true, value: runtimeStatus('STOPPED') });
    setTimeout(() => process.exit(0), 25);
}

port.on('message', event => {
    let request: WorkerRequest;
    try {
        request = parseWorkerRequest(event.data, instanceId);
    } catch {
        return;
    }

    if (request.command === 'shutdown') {
        if (draining) return;
        draining = true;
        shutdownRequest = request;
        finishShutdownWhenDrained();
        return;
    }

    if (draining) {
        if (request.command === 'inspect' || request.command === 'inventory') {
            sendResponse(request, {
                ok: false,
                error: { code: 'WORKER_DRAINING', detail: 'The diagnostics worker is shutting down' }
            });
        } else {
            sendResponse(request, { ok: true, value: runtimeStatus('DRAINING') });
        }
        return;
    }

    if (request.command === 'inspect' || request.command === 'inventory') {
        activeInspections += 1;
        void respondToRequest(request).finally(() => {
            activeInspections -= 1;
            finishShutdownWhenDrained();
        });
        return;
    }

    void respondToRequest(request);
});

port.on('close', () => process.exit(0));

port.postMessage({
    kind: 'ready',
    version: CONTROL_VERSION,
    instanceId,
    scope: 'diagnostics',
    businessReady: false
});
