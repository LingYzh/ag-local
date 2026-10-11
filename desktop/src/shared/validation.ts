import { CONTROL_VERSION } from './contracts';
import type { FoundationFault, WorkerRequest } from './contracts';

export function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isInstanceId(value: unknown): value is string {
    return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

export function parseWorkerRequest(value: unknown, instanceId: string): WorkerRequest {
    if (!isRecord(value) || value.version !== CONTROL_VERSION || value.instanceId !== instanceId
        || !isInstanceId(value.requestId) || typeof value.command !== 'string'
        || !['status', 'inspect', 'inventory', 'shutdown'].includes(value.command)) {
        throw new Error('INVALID_CONTROL_MESSAGE');
    }
    if (Object.keys(value).some(key => !['version', 'instanceId', 'requestId', 'command', 'directory'].includes(key))) {
        throw new Error('INVALID_CONTROL_MESSAGE');
    }
    if (value.command === 'inspect' || value.command === 'inventory') {
        if (typeof value.directory !== 'string' || !value.directory || value.directory.length > 4096 || value.directory.includes('\0')) {
            throw new Error('INVALID_BUNDLE_DIRECTORY');
        }
    } else if (value.directory !== undefined) {
        throw new Error('INVALID_CONTROL_MESSAGE');
    }
    return value as unknown as WorkerRequest;
}

export function fault(error: unknown, fallback = 'INTERNAL_ERROR'): FoundationFault {
    if (isRecord(error) && typeof error.code === 'string' && typeof error.detail === 'string') {
        return { code: error.code, detail: error.detail };
    }
    return { code: fallback, detail: error instanceof Error ? error.message : 'Unexpected foundation error' };
}
