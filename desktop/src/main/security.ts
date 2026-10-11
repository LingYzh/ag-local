import { fileURLToPath } from 'node:url';
import { relative, resolve, isAbsolute } from 'node:path';

export function isTrustedRenderer(actualUrl: string, expectedUrl: string, isMainFrame: boolean): boolean {
    if (!isMainFrame) return false;
    try {
        const actual = new URL(actualUrl);
        const expected = new URL(expectedUrl);
        actual.hash = '';
        expected.hash = '';
        return actual.protocol === 'file:' && actual.href === expected.href;
    } catch {
        return false;
    }
}

export function isBundleResource(url: string, rendererRoot: string): boolean {
    try {
        if (url.startsWith('data:')) return true;
        if (!url.startsWith('file:')) return false;
        const difference = relative(resolve(rendererRoot), resolve(fileURLToPath(url)));
        return !difference.startsWith('..') && !isAbsolute(difference);
    } catch {
        return false;
    }
}
