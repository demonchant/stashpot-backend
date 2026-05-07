/**
 * StashPot — Structured Logger
 *
 * Redacts sensitive fields automatically. Never logs Authorization headers,
 * tokens, signatures, or private keys.
 */
export declare const log: {
    info: (msg: string, meta?: any) => void;
    warn: (msg: string, meta?: any) => void;
    error: (msg: string, meta?: any) => void;
    debug: (msg: string, meta?: any) => void;
};
export declare function newErrorId(): string;
