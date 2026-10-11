import { FoundationError } from './errors';

const MAX_JSON_DEPTH = 256;

function rejectDuplicateKeys(text: string, code: string, label: string): void {
    let cursor = 0;

    const fail = (detail: string): never => {
        throw new FoundationError(code, `${label}: ${detail}`);
    };

    const skipWhitespace = (): void => {
        while (cursor < text.length && /[\t\n\r ]/.test(text[cursor])) {
            cursor += 1;
        }
    };

    const readString = (): string => {
        if (text[cursor] !== '"') {
            return fail('expected a JSON string');
        }
        const start = cursor;
        cursor += 1;
        while (cursor < text.length) {
            const character = text[cursor];
            cursor += 1;
            if (character === '\\') {
                cursor += 1;
            } else if (character === '"') {
                return JSON.parse(text.slice(start, cursor)) as string;
            }
        }
        return fail('unterminated JSON string');
    };

    const readObject = (depth: number): void => {
        cursor += 1;
        skipWhitespace();
        if (text[cursor] === '}') {
            cursor += 1;
            return;
        }

        const keys = new Set<string>();
        while (cursor < text.length) {
            skipWhitespace();
            const key = readString();
            if (keys.has(key)) {
                fail(`duplicate JSON property ${JSON.stringify(key)}`);
            }
            keys.add(key);
            skipWhitespace();
            cursor += 1; // JSON.parse has already verified the colon.
            readValue(depth + 1);
            skipWhitespace();
            if (text[cursor] === '}') {
                cursor += 1;
                return;
            }
            cursor += 1; // JSON.parse has already verified the comma.
        }
        fail('unterminated JSON object');
    };

    const readArray = (depth: number): void => {
        cursor += 1;
        skipWhitespace();
        if (text[cursor] === ']') {
            cursor += 1;
            return;
        }
        while (cursor < text.length) {
            readValue(depth + 1);
            skipWhitespace();
            if (text[cursor] === ']') {
                cursor += 1;
                return;
            }
            cursor += 1; // JSON.parse has already verified the comma.
        }
        fail('unterminated JSON array');
    };

    const readValue = (depth: number): void => {
        if (depth > MAX_JSON_DEPTH) {
            fail(`JSON nesting exceeds ${MAX_JSON_DEPTH}`);
        }
        skipWhitespace();
        const character = text[cursor];
        if (character === '{') {
            readObject(depth);
        } else if (character === '[') {
            readArray(depth);
        } else if (character === '"') {
            readString();
        } else {
            while (cursor < text.length && !/[\t\n\r ,\]}]/.test(text[cursor])) {
                cursor += 1;
            }
        }
    };

    readValue(0);
    skipWhitespace();
    if (cursor !== text.length) {
        fail('unexpected trailing JSON data');
    }
}

export function parseJsonBytes(bytes: Uint8Array, code: string, label: string): unknown {
    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
        throw new FoundationError(code, `${label} is not valid UTF-8: ${errorMessage(error)}`);
    }

    let value: unknown;
    try {
        value = JSON.parse(text) as unknown;
    } catch (error) {
        throw new FoundationError(code, `${label} is not valid JSON: ${errorMessage(error)}`);
    }

    rejectDuplicateKeys(text, code, label);
    return value;
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'invalid input';
}
