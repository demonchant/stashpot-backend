/**
 * StashPot — Audit Logging (Critical Missing Concept #3)
 *
 * Every financial state change is logged to an append-only audit table.
 * The audit table has no UPDATE or DELETE permissions (enforced at schema level).
 * Each row includes a hash chain: sha256(prev_hash || row_json) for tamper detection.
 */
import { AuthRequest } from '../middleware/auth.js';
export type AuditAction = 'auth.login' | 'auth.nonce_issued' | 'auth.privy_verify' | 'auth.link_wallet' | 'pool.deposit' | 'pool.withdraw' | 'pool.draw_executed' | 'pool.prize_claimed' | 'circle.created' | 'circle.joined' | 'circle.contribution' | 'circle.cycle_payout' | 'vault.created' | 'vault.funded' | 'vault.ping' | 'vault.cancelled' | 'vault.activated' | 'vault.share_claimed' | 'loan.issued' | 'loan.repaid' | 'loan.defaulted' | 'loan.liquidated' | 'fiat.deposit_initiated' | 'fiat.deposit_completed' | 'fiat.withdrawal' | 'referral.registered' | 'referral.reward_paid' | 'admin.feature_toggled' | 'admin.pause' | 'webhook.received' | 'webhook.rejected' | 'security.suspicious_activity';
interface AuditEntry {
    action: AuditAction;
    user_id?: string | null;
    target_id?: string | null;
    amount?: number | null;
    metadata?: Record<string, any>;
    ip?: string | null;
    user_agent?: string | null;
    status: 'success' | 'failure';
    error?: string | null;
}
/**
 * Write an audit log entry with hash-chain integrity.
 */
export declare function audit(entry: AuditEntry): Promise<void>;
/**
 * Convenience helper to build an audit entry from an Express request.
 */
export declare function auditFromReq(req: AuthRequest, action: AuditAction, extra?: Partial<AuditEntry>): AuditEntry;
export {};
