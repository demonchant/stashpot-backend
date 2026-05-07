/**
 * StashPot — Structured Logger
 *
 * Redacts sensitive fields automatically. Never logs Authorization headers,
 * tokens, signatures, or private keys.
 */
const SENSITIVE_KEYS = [
    'authorization', 'cookie', 'set-cookie',
    'jwt', 'token', 'secret', 'password',
    'private_key', 'privatekey', 'mnemonic',
    'signature', 'api_key', 'apikey',
    'idempotency-key',
];
function redact(obj, depth = 0) {
    if (depth > 6)
        return '[depth-limit]';
    if (obj === null || obj === undefined)
        return obj;
    if (typeof obj !== 'object')
        return obj;
    if (Array.isArray(obj))
        return obj.map(v => redact(v, depth + 1));
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
        if (SENSITIVE_KEYS.some(s => k.toLowerCase().includes(s))) {
            out[k] = '[REDACTED]';
        }
        else {
            out[k] = redact(v, depth + 1);
        }
    }
    return out;
}
function fmt(level, msg, meta) {
    const base = {
        ts: new Date().toISOString(),
        level,
        msg,
    };
    if (meta)
        base.meta = redact(meta);
    return JSON.stringify(base);
}
export const log = {
    info: (msg, meta) => console.log(fmt('info', msg, meta)),
    warn: (msg, meta) => console.warn(fmt('warn', msg, meta)),
    error: (msg, meta) => console.error(fmt('error', msg, meta)),
    debug: (msg, meta) => {
        if (process.env.NODE_ENV !== 'production')
            console.log(fmt('debug', msg, meta));
    },
};
export function newErrorId() {
    return `err_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
//# sourceMappingURL=logger.js.map