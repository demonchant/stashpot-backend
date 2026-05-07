/**
 * StashPot — Audit Log External Anchoring
 *
 * Fixes finding #6 from the advanced audit:
 *   "Hash chain protects integrity, not deletion or partial truncation."
 *
 * STRATEGY:
 *   Periodically (every 1000 rows or every 6 hours, whichever first) we:
 *   1. Read the latest audit_log row → its row_hash is the chain head.
 *   2. Sign it with the protocol's anchor key (Ed25519).
 *   3. Publish it externally:
 *        a. As a Solana memo transaction (immutable)
 *        b. To S3 with object lock (worm)
 *        c. To at least one external mirror
 *   4. Store the anchor record locally for verification.
 *
 *   If the audit log is later truncated or rewritten, the latest anchor
 *   still exists externally. Anyone can verify: "the chain MUST extend
 *   the published anchor head" — if it doesn't, the log was tampered.
 *
 * Configurable: set ANCHOR_DESTINATIONS in env. Production must include
 * at least one append-only external destination.
 *
 * Anchor verification is best-effort by design. The cron scheduler in
 * jobs/runner.ts kicks anchorAuditLog() periodically. Failures are
 * logged and audited but do not stop the application — this is a
 * forensic backstop, not a hot-path dependency.
 */
interface AnchorRecord {
    anchor_id: string;
    chain_head: string;
    row_count: number;
    signed_at: Date;
    signature: string;
    destinations: AnchorDest[];
}
interface AnchorDest {
    type: 'solana_memo' | 's3' | 'mirror';
    status: 'pending' | 'published' | 'failed';
    ref: string | null;
    error?: string;
}
/**
 * Take a snapshot of the current chain head, sign it, publish it,
 * and record the anchor in the local anchor_log table.
 *
 * Idempotent: if the head has not advanced since the last anchor,
 * this is a no-op.
 */
export declare function anchorAuditLog(): Promise<AnchorRecord | null>;
/**
 * Verify the audit log against the latest anchor.
 *
 * Returns:
 *   - { ok: true, head, anchor }     — chain extends the latest anchor
 *   - { ok: false, reason: '...' }   — chain has been tampered or truncated
 */
export declare function verifyAgainstLastAnchor(): Promise<{
    ok: boolean;
    reason?: string;
    head?: string;
    anchor?: {
        chain_head: string;
        row_count: number;
    };
}>;
export {};
