import type { ClientInventory } from './client-contracts';

export const CONTROL_VERSION = 1 as const;

export type LifecycleState = 'CREATED' | 'PREFLIGHT' | 'READY' | 'DRAINING' | 'STOPPED' | 'FAILED';

export interface FoundationFault {
    code: string;
    detail: string;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: FoundationFault };

export interface RuntimeStatus {
    state: LifecycleState;
    instanceId: string | null;
    scope: 'diagnostics';
    businessReady: false;
    lastError: FoundationFault | null;
}

export interface EnvironmentInfo {
    appVersion: string;
    electron: string;
    node: string;
    platform: string;
    architecture: string;
    mode: 'foundation';
}

export interface BundleReport {
    tupleId: string;
    state: string;
    artifactsVerified: number;
    manifestComplete: boolean;
    declaredHallPassed: boolean;
    businessReady: false;
    issues: string[];
    schema: { sha256: string; messages: number; fields: number } | null;
}

export interface SelectedBundle {
    directory: string;
}

export interface DesktopBridge {
    getEnvironment(): Promise<Result<EnvironmentInfo>>;
    getStatus(): Promise<Result<RuntimeStatus>>;
    startService(): Promise<Result<RuntimeStatus>>;
    stopService(): Promise<Result<RuntimeStatus>>;
    chooseBundle(): Promise<Result<SelectedBundle | null>>;
    inspectBundle(): Promise<Result<BundleReport>>;
    chooseClient(): Promise<Result<SelectedBundle | null>>;
    inspectClient(): Promise<Result<ClientInventory>>;
}

export type WorkerCommand = 'status' | 'inspect' | 'inventory' | 'shutdown';

export interface WorkerRequest {
    version: typeof CONTROL_VERSION;
    instanceId: string;
    requestId: string;
    command: WorkerCommand;
    directory?: string;
}

export interface WorkerReady {
    kind: 'ready';
    version: typeof CONTROL_VERSION;
    instanceId: string;
    scope: 'diagnostics';
    businessReady: false;
}

export interface WorkerResponse {
    kind: 'response';
    version: typeof CONTROL_VERSION;
    instanceId: string;
    requestId: string;
    result: Result<RuntimeStatus | BundleReport | ClientInventory>;
}

export const IPC_CHANNELS = {
    environment: 'ap:environment',
    status: 'ap:status',
    start: 'ap:start',
    stop: 'ap:stop',
    choose: 'ap:choose-bundle',
    inspect: 'ap:inspect-bundle',
    chooseClient: 'ap:choose-client',
    inspectClient: 'ap:inspect-client'
} as const;
