import { createHash } from 'node:crypto';
import { FoundationError } from './errors';
import { parseJsonBytes } from './json';

export const MAX_SCHEMA_BYTES = 32 * 1024 * 1024;

const SCALAR_TYPES = new Set([
    'double', 'float', 'int32', 'int64', 'uint32', 'uint64',
    'sint32', 'sint64', 'fixed32', 'fixed64', 'sfixed32', 'sfixed64',
    'bool', 'string', 'bytes'
]);
const MESSAGE_NAME = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface SchemaField {
    readonly number: number;
    readonly name: string;
    readonly type: string;
    readonly label: 'required' | 'optional' | 'repeated';
    readonly ref: string | null;
}

export interface SchemaMessage {
    readonly name: string;
    readonly fields: Readonly<Record<string, SchemaField>>;
}

export interface SchemaRegistry {
    readonly sha256: string;
    readonly messages: Readonly<Record<string, SchemaMessage>>;
    readonly messageCount: number;
    readonly fieldCount: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function schemaInvalid(detail: string): FoundationError {
    return new FoundationError('SCHEMA_INVALID', detail);
}

function normalizeMessageName(value: string): string {
    const normalized = value.trim().replace(/^\.+/, '').toLowerCase();
    if (!normalized || !MESSAGE_NAME.test(normalized)) {
        throw schemaInvalid(`invalid message name ${JSON.stringify(value)}`);
    }
    return normalized;
}

function normalizeMessageRef(value: string, source: string, fieldName: string): string {
    try {
        return normalizeMessageName(value);
    } catch {
        throw new FoundationError('UNRESOLVED_TYPE', `${source}.${fieldName} has invalid message ref ${JSON.stringify(value)}`);
    }
}

export function loadSchemaRegistry(bytes: Buffer): SchemaRegistry {
    if (bytes.byteLength > MAX_SCHEMA_BYTES) {
        throw schemaInvalid(`schema exceeds the ${MAX_SCHEMA_BYTES}-byte limit`);
    }

    const document = parseJsonBytes(bytes, 'SCHEMA_INVALID', 'schema');
    if (!isRecord(document) || !Array.isArray(document.messages)) {
        throw schemaInvalid("schema must be an object with a 'messages' array");
    }
    if (document.messages.length === 0) {
        throw schemaInvalid('schema messages array must not be empty');
    }

    const mutableMessages = Object.create(null) as Record<string, SchemaMessage>;
    const messageFields: Array<{ source: string; field: SchemaField }> = [];
    let fieldCount = 0;

    for (const [messageIndex, rawMessage] of document.messages.entries()) {
        const context = `messages[${messageIndex}]`;
        if (!isRecord(rawMessage) || typeof rawMessage.name !== 'string' || !Array.isArray(rawMessage.fields)) {
            throw schemaInvalid(`${context} must have a string name and fields array`);
        }

        const messageName = normalizeMessageName(rawMessage.name);
        if (Object.hasOwn(mutableMessages, messageName)) {
            throw schemaInvalid(`duplicate normalized message name ${JSON.stringify(messageName)}`);
        }

        const fields = Object.create(null) as Record<string, SchemaField>;
        const seenNames = new Set<string>();
        for (const [fieldIndex, rawField] of rawMessage.fields.entries()) {
            const fieldContext = `${context}.fields[${fieldIndex}]`;
            if (!isRecord(rawField)) {
                throw schemaInvalid(`${fieldContext} must be an object`);
            }

            const number = rawField.number;
            if (typeof number !== 'number' || !Number.isInteger(number)
                || number < 1 || number > (2 ** 29) - 1
                || (number >= 19_000 && number <= 19_999)) {
                throw schemaInvalid(`${fieldContext}.number is not a legal protobuf field number`);
            }
            if (Object.hasOwn(fields, String(number))) {
                throw schemaInvalid(`${messageName} has duplicate field number ${number}`);
            }

            if (typeof rawField.name !== 'string' || !FIELD_NAME.test(rawField.name)) {
                throw schemaInvalid(`${fieldContext}.name must be a non-empty identifier`);
            }
            if (seenNames.has(rawField.name)) {
                throw schemaInvalid(`${messageName} has duplicate field name ${JSON.stringify(rawField.name)}`);
            }
            seenNames.add(rawField.name);

            if (typeof rawField.type !== 'string' || !rawField.type.trim()) {
                throw schemaInvalid(`${fieldContext}.type must be a non-empty string`);
            }
            const type = rawField.type.trim().toLowerCase();
            if (!SCALAR_TYPES.has(type) && type !== 'message' && type !== 'enum') {
                throw schemaInvalid(`${fieldContext}.type is unknown: ${JSON.stringify(rawField.type)}`);
            }

            if (typeof rawField.label !== 'string'
                || !['required', 'optional', 'repeated'].includes(rawField.label)) {
                throw schemaInvalid(`${fieldContext}.label must be required, optional, or repeated`);
            }

            const rawRef = rawField.ref;
            const hasRef = Object.hasOwn(rawField, 'ref');
            if (type === 'message'
                && (!hasRef || typeof rawRef !== 'string' || !rawRef.trim())) {
                throw new FoundationError('UNRESOLVED_TYPE', `${messageName}.${rawField.name} is missing its message ref`);
            }
            if (!hasRef || (rawRef !== null && (typeof rawRef !== 'string' || !rawRef.trim()))) {
                throw schemaInvalid(`${fieldContext}.ref must be a non-empty string or null`);
            }
            if (SCALAR_TYPES.has(type) && rawRef !== null) {
                throw schemaInvalid(`${fieldContext}.ref is only valid for message or enum fields`);
            }

            const field = Object.freeze({
                number,
                name: rawField.name,
                type,
                label: rawField.label as SchemaField['label'],
                ref: rawRef as string | null
            });
            fields[String(number)] = field;
            messageFields.push({ source: messageName, field });
        }

        fieldCount += Object.keys(fields).length;
        mutableMessages[messageName] = Object.freeze({
            name: messageName,
            fields: Object.freeze(fields)
        });
    }

    for (const { source, field } of messageFields) {
        if (field.type !== 'message') {
            continue;
        }
        const target = normalizeMessageRef(field.ref as string, source, field.name);
        if (!Object.hasOwn(mutableMessages, target)) {
            throw new FoundationError(
                'UNRESOLVED_TYPE',
                `${source}.${field.name} references missing message ${JSON.stringify(field.ref)}`
            );
        }
    }

    return Object.freeze({
        sha256: createHash('sha256').update(bytes).digest('hex'),
        messages: Object.freeze(mutableMessages),
        messageCount: Object.keys(mutableMessages).length,
        fieldCount
    });
}
