/**
 * StashPot — Transaction Locking (HARDENED)
 *
 * Fix from advanced audit finding #2: Lock keys are now NAMESPACED.
 *
 * Previously: hash(userId) and hash("pool:weekly") shared a 64-bit space.
 * Astronomically rare collision (~2^-64), but not zero.
 *
 * Now: every lock kind has a 32-bit namespace prefix combined with a
 * 32-bit hash of the identifier. PostgreSQL advisory locks accept the
 * (classid, objid) form natively — we use that to keep namespaces fully
 * separate by API rather than hoping hashes don't collide.
 *
 * Namespace IDs are stable constants and must never be reused.
 */
import { PoolClient } from 'pg';
declare const LOCK_NS: {
    readonly USER: 1;
    readonly RESOURCE: 2;
    readonly POOL: 3;
    readonly DRAW: 4;
};
/**
 * Execute `fn` inside a transaction holding a per-user advisory lock.
 *
 * The lock is automatically released on COMMIT or ROLLBACK.
 * If another caller holds the lock, this call waits up to `timeoutMs`.
 */
export declare function withUserLock<T>(userId: string, fn: (client: PoolClient) => Promise<T>, timeoutMs?: number): Promise<T>;
/**
 * Lock two users in a deadlock-safe order (e.g. for transfers).
 */
export declare function withTwoUserLocks<T>(userA: string, userB: string, fn: (client: PoolClient) => Promise<T>, timeoutMs?: number): Promise<T>;
/**
 * Named resource lock — for things like "draw:weekly", "pool:daily",
 * "circle:<uuid>". Uses the RESOURCE namespace which cannot collide
 * with USER locks.
 */
export declare function withResourceLock<T>(resource: string, fn: (client: PoolClient) => Promise<T>, timeoutMs?: number): Promise<T>;
/**
 * Specialized: lock for an entire draw cycle (only one runner per pool).
 * Distinct namespace so it never blocks a deposit's resource lock.
 */
export declare function withDrawLock<T>(poolType: string, fn: (client: PoolClient) => Promise<T>, timeoutMs?: number): Promise<T>;
export { LOCK_NS };
