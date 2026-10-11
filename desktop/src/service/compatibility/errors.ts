export class FoundationError extends Error {
    code: string;
    detail: string;

    constructor(code: string, detail: string) {
        super(detail);
        this.name = 'FoundationError';
        this.code = code;
        this.detail = detail;
    }
}
