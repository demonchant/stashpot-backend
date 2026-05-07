/**
 * StashPot — Audit Logging (Critical Missing Concept #3)
 *
 * Every financial state change is logged to an append-only audit table.
 * The audit table has no UPDATE or DELETE permissions (enforced at schema level).
 * Each row includes a hash chain: sha256(prev_hash || row_json) for tamper detection.
 */
import crypto from 'crypto';
import { db } from '../models/db.js';
/**
 * Write an audit log entry with hash-chain integrity.
 */
export async function audit(entry) {
    try {
        const prev = await db.query('SELECT row_hash FROM audit_log ORDER BY created_at DESC, id DESC LIMIT 1');
        const prevHash = prev.rows[0]?.row_hash || '0'.repeat(64);
        const rowData = JSON.stringify({
            ...entry,
            metadata: entry.metadata ?? {},
            timestamp: new Date().toISOString(),
        });
        const rowHash = crypto
            .createHash('sha256')
            .update(prevHash + rowData)
            .digest('hex');
        await db.query(`INSERT INTO audit_log(
         action, user_id, target_id, amount, metadata,
         ip, user_agent, status, error, prev_hash, row_hash
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [
            entry.action,
            entry.user_id ?? null,
            entry.target_id ?? null,
            entry.amount ?? null,
            JSON.stringify(entry.metadata ?? {}),
            entry.ip ?? null,
            entry.user_agent ?? null,
            entry.status,
            entry.error ?? null,
            prevHash,
            rowHash,
        ]);
    }
    catch (err) {
        // Audit logging must never break the main flow — log locally if DB fails
        console.error('[audit] Failed to write log:', err.message, entry);
    }
}
/**
 * Convenience helper to build an audit entry from an Express request.
 */
export function auditFromReq(req, action, extra = {}) {
    return {
        action,
        user_id: req.user?.id ?? null,
        ip: (req.headers['x-forwarded-for'] || req.ip || null),
        user_agent: (req.headers['user-agent'] || null),
        status: 'success',
        ...extra,
    };
}
//# sourceMappingURL=audit.js.map