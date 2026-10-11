import { describe, expect, it } from 'vitest';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isBundleResource, isTrustedRenderer } from '../src/main/security';
import { parseWorkerRequest } from '../src/shared/validation';

describe('desktop trust boundary', () => {
    const root = resolve('test-renderer');
    const entry = pathToFileURL(resolve(root, 'index.html')).href;
    it('accepts only the bundled main frame, preserving hash navigation', () => {
        expect(isTrustedRenderer(`${entry}#components`, entry, true)).toBe(true);
        expect(isTrustedRenderer(entry, entry, false)).toBe(false);
        expect(isTrustedRenderer('https://example.com', entry, true)).toBe(false);
        expect(isTrustedRenderer(pathToFileURL(resolve(root, 'other.html')).href, entry, true)).toBe(false);
        expect(isTrustedRenderer(`${entry}?path=other`, entry, true)).toBe(false);
    });
    it('denies external and other local resources', () => {
        expect(isBundleResource(entry, root)).toBe(true);
        expect(isBundleResource(pathToFileURL(resolve(root, '../secret.txt')).href, root)).toBe(false);
        expect(isBundleResource('https://example.com/script.js', root)).toBe(false);
        expect(isBundleResource('ws://127.0.0.1:5173', root)).toBe(false);
    });
    it('rejects wrong instances, unknown commands and arbitrary extra fields', () => {
        const instanceId = randomUUID();
        const request = { version: 1, instanceId, requestId: randomUUID(), command: 'status' };
        expect(parseWorkerRequest(request, instanceId).command).toBe('status');
        expect(() => parseWorkerRequest(request, randomUUID())).toThrow();
        expect(() => parseWorkerRequest({ ...request, command: 'shell' }, instanceId)).toThrow();
        expect(() => parseWorkerRequest({ ...request, path: '/anything' }, instanceId)).toThrow();
    });
});
