/**
 * StashPot — Deterministic Merkle Tree Builder
 *
 * Fixes finding #5 from the advanced audit:
 *   "Backend builds the Merkle tree → backend = trust point"
 *
 * Properties this builder must guarantee:
 *
 *   [P1] DETERMINISTIC ORDERING
 *        Participants are sorted by wallet pubkey (lexicographic).
 *        No insertion-order dependence. Any reviewer who fetches the
 *        same on-chain UserAccount set will produce identical leaves.
 *
 *   [P2] REPRODUCIBLE LEAF FORMAT
 *        The leaf hash format matches the on-chain `compute_leaf`:
 *        sha256(owner_le32 || weight_le16 || cum_start_le16 || cum_end_le16)
 *
 *   [P3] CUMULATIVE BOUNDS
 *        Each leaf carries [cum_start, cum_end) such that
 *        cum_end - cum_start == weight. This closes the "ordering
 *        attack" — backend cannot shift a winner's slice without
 *        invalidating their proof.
 *
 *   [P4] NO ENTRY ELIGIBILITY DECISIONS
 *        This file does NOT decide who is "eligible". It accepts the
 *        full set of pool entries and computes weights. Eligibility
 *        gates (active flag, prize_opted_in flag, ENTRY_CUTOFF_SECS)
 *        live in the data filter at the call site, are documented in
 *        the spec, and produce auditable reasons.
 *
 *   [P5] EXTERNAL VERIFIABILITY
 *        verifyTree() takes a root and a set of entries and returns true
 *        iff the root reproduces. Anyone — auditor, user, third party —
 *        can call this to confirm a draw was honest.
 *
 * SPEC VERSION: 1
 * Bump this constant if the algorithm or leaf format ever changes.
 * The version is committed on-chain via WeightsCommitted.formula_version.
 */
export declare const MERKLE_SPEC_VERSION = 1;
export interface ParticipantInput {
    /** Solana wallet pubkey, base58 — NOT a UUID */
    wallet: string;
    /** Average balance (USDC) — EMA-smoothed */
    avgBalance: number;
    /** Hours held since join */
    heldHours: number;
    /** Number of early withdrawals */
    earlyWithdrawals: number;
}
export interface MerkleLeaf {
    wallet: string;
    weight: bigint;
    cumStart: bigint;
    cumEnd: bigint;
    hash: Buffer;
}
export interface MerkleTree {
    spec_version: number;
    root: Buffer;
    total_weight: bigint;
    leaves: MerkleLeaf[];
    /** sha256 of the canonicalized leaf array — used as a tree fingerprint */
    fingerprint: Buffer;
}
export declare function computeWeight(p: ParticipantInput): bigint;
/**
 * Leaf format — MUST match contracts/programs/prize_module/src/lib.rs::compute_leaf
 *   sha256(owner[32] || weight_le16 || cum_start_le16 || cum_end_le16)
 */
export declare function computeLeaf(wallet: string, weight: bigint, cumStart: bigint, cumEnd: bigint): Buffer;
/**
 * Build a Merkle tree from a set of pool entries.
 *
 * GUARANTEES:
 *   [P1] Sorted lexicographically by wallet pubkey before anything else.
 *        Two callers passing the same set in any order produce the same root.
 *   [P3] Each leaf includes [cum_start, cum_end), assigned in sort order.
 *
 * The fingerprint is sha256 over the canonical wallet|weight tuples, useful
 * for off-chain auditors to confirm two backends produced the same tree
 * before checking the root.
 */
export declare function buildTree(participants: ParticipantInput[]): MerkleTree;
export declare function getProof(tree: MerkleTree, walletBase58: string): Buffer[];
/**
 * Reproduce the tree from raw participants and confirm the root matches.
 *
 * This is the function any third-party auditor calls to verify a draw
 * was honest. They:
 *   1. Fetch UserAccount PDAs from the chain
 *   2. Compute (avg_balance, held_hours, early_exits) from on-chain history
 *   3. Call verifyTree(participants, expected_root)
 *   4. If true, the backend cannot have rigged this draw
 */
export declare function verifyTree(participants: ParticipantInput[], expectedRoot: Buffer): {
    valid: boolean;
    computed_root: Buffer;
    spec_version: number;
};
