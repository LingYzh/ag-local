import type { ClientInventory } from './client-contracts';
import { isRecord } from './validation';

const hash = (value: unknown, length: number) => typeof value === 'string'
    && new RegExp(`^[a-f0-9]{${length}}$`, 'i').test(value);
const boundedInteger = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const strings = (value: unknown) => Array.isArray(value) && value.length <= 256
    && value.every(item => typeof item === 'string' && item.length <= 8192);

function file(value: unknown): boolean {
    return isRecord(value) && typeof value.path === 'string' && value.path.length <= 4096
        && boundedInteger(value.size) && hash(value.sha256, 64);
}

function identity(value: unknown): boolean {
    return isRecord(value) && boundedInteger(value.buildCode) && boundedInteger(value.appVersion)
        && boundedInteger(value.channel) && typeof value.versionName === 'string' && value.versionName.length <= 128;
}

export function isClientInventory(value: unknown): value is ClientInventory {
    if (!isRecord(value) || value.state !== 'observed' || value.gate !== 'G0' || value.businessReady !== false
        || typeof value.root !== 'string' || value.root.length > 4096 || !identity(value.identity)
        || !file(value.index) || !isRecord(value.index) || !boundedInteger(value.index.entryCount)
        || !['scripts64', 'scripts64.ys'].includes(String(value.index.scriptsLogicalName))
        || !Array.isArray(value.keyFiles) || value.keyFiles.length < 5 || value.keyFiles.length > 69 || !value.keyFiles.every(file)
        || !file(value.scripts) || !isRecord(value.scripts) || !hash(value.scripts.expectedMd5, 32)
        || !hash(value.scripts.md5, 32) || value.scripts.md5 !== value.scripts.expectedMd5
        || !['scripts64', 'scripts64.ys'].includes(String(value.scripts.logicalName))
        || !Array.isArray(value.indexCandidates) || value.indexCandidates.length > 64
        || !strings(value.issues) || !strings(value.limitations)) return false;
    return value.indexCandidates.every(candidate => isRecord(candidate) && file(candidate)
        && hash(candidate.md5, 32) && identity(candidate.identity)
        && boundedInteger(candidate.filenameAppVersion) && boundedInteger(candidate.filenameBuildCode)
        && typeof candidate.identityMatch === 'boolean' && typeof candidate.canonicalMatch === 'boolean');
}
