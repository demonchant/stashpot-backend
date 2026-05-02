/**
 * StashPot — Audit Logging (Critical Missing Concept #3)
 *
 * Every financial state change is logged to an append-only audit table.
 * The audit table has no UPDATE or DELETE permissions (enforced at schema level).
 * Each row includes a hash chain: sha256(prev_hash || row_json) for tamper detection.
 */

import crypto      from 'crypto';
import { db }      from '../models/db.js';
import { Request } from 'express';
import { AuthRequest } from '../middleware/auth.js';

export type AuditAction =
  | 'auth.login'
  | 'auth.nonce_issued'
  | 'auth.privy_verify'
  | 'auth.link_wallet'
  | 'pool.deposit'
  | 'pool.withdraw'
  | 'pool.draw_executed'
  | 'pool.prize_claimed'
  | 'circle.created'
  | 'circle.joined'
  | 'circle.contribution'
  | 'circle.cycle_payout'
  | 'vault.created'
  | 'vault.funded'
  | 'vault.ping'
  | 'vault.cancelled'
  | 'vault.activated'
  | 'vault.share_claimed'
  | 'loan.issued'
  | 'loan.repaid'
  | 'loan.defaulted'
  | 'loan.liquidated'
  | 'fiat.deposit_initiated'
  | 'fiat.deposit_completed'
  | 'fiat.withdrawal'
  | 'referral.registered'
  | 'referral.reward_paid'
  | 'admin.feature_toggled'
  | 'admin.pause'
  | 'webhook.received'
  | 'webhook.rejected'
  | 'security.suspicious_activity';

interface AuditEntry {
  action:       AuditAction;
  user_id?:     string | null;
  target_id?:   string | null;
  amount?:      number | null;
  metadata?:    Record<string, any>;
  ip?:          string | null;
  user_agent?:  string | null;
  status:       'success' | 'failure';
  error?:       string | null;
}

/**
 * Write an audit log entry with hash-chain integrity.
 */
export async function audit(entry: AuditEntry): Promise<void> {
  try {
    const prev = await db.query(
      'SELECT row_hash FROM audit_log ORDER BY created_at DESC, id DESC LIMIT 1',
    );
    const prevHash = prev.rows[0]?.row_hash || '0'.repeat(64);

    const rowData = JSON.stringify({
      ...entry,
      metadata:  entry.metadata ?? {},
      timestamp: new Date().toISOString(),
    });
    const rowHash = crypto
      .createHash('sha256')
      .update(prevHash + rowData)
      .digest('hex');

    await db.query(
      `INSERT INTO audit_log(
         action, user_id, target_id, amount, metadata,
         ip, user_agent, status, error, prev_hash, row_hash
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        entry.action,
        entry.user_id   ?? null,
        entry.target_id ?? null,
        entry.amount    ?? null,
        JSON.stringify(entry.metadata ?? {}),
        entry.ip         ?? null,
        entry.user_agent ?? null,
        entry.status,
        entry.error      ?? null,
        prevHash,
        rowHash,
      ],
    );
  } catch (err) {
    // Audit logging must never break the main flow — log locally if DB fails
    console.error('[audit] Failed to write log:', (err as Error).message, entry);
  }
}

/**
 * Convenience helper to build an audit entry from an Express request.
 */
export function auditFromReq(
  req: AuthRequest,
  action: AuditAction,
  extra: Partial<AuditEntry> = {},
): AuditEntry {
  return {
    action,
    user_id:    req.user?.id ?? null,
    ip:         (req.headers['x-forwarded-for'] as string || req.ip || null) as string | null,
    user_agent: (req.headers['user-agent'] as string || null),
    status:     'success',
    ...extra,
  };
}
