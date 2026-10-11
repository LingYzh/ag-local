import type { FoundationFault, LifecycleState } from './contracts';

export interface PythonCompatibilityStatus {
    state: LifecycleState;
    instanceId: string | null;
    scope: 'python-compatibility';
    businessReady: false;
    tupleId: string | null;
    lastError: FoundationFault | null;
}
