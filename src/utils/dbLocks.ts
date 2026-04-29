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
import crypto         from 'crypto';
import { db }         from '../models/db.js';

// ─── Lock namespaces — never reuse a number ───────────────────────────────────
const LOCK_NS = {
  USER:     1,   // per-user serialization
  RESOURCE: 2,   // named resource (e.g. "draw:weekly", "pool:daily", "circle:<uuid>")
  POOL:     3,   // pool-specific (deposit/withdraw guards)
  DRAW:     4,   // draw-specific (only one runner per draw)
} as const;

/**
 * Hash an identifier to a stable 32-bit signed int (PostgreSQL int4).
 */
function id32(s: string): number {
  const hash = crypto.createHash('sha256').update(s).digest();
  // Read as int32, signed
  return new DataView(hash.buffer, hash.byteOffset, 4).getInt32(0, false);
}

/**
 * Acquire a transaction-scoped advisory lock with namespacing.
 * Uses the two-int form: pg_advisory_xact_lock(int4, int4).
 */
async function acquireLock(
  client: PoolClient,
  namespace: number,
  identifier: string,
): Promise<void> {
  const objId = id32(identifier);
  await client.query(
    'SELECT pg_advisory_xact_lock($1, $2)',
    [namespace, objId],
  );
}

/**
 * Execute `fn` inside a transaction holding a per-user advisory lock.
 *
 * The lock is automatically released on COMMIT or ROLLBACK.
 * If another caller holds the lock, this call waits up to `timeoutMs`.
 */
export async function withUserLock<T>(
  userId:    string,
  fn:        (client: PoolClient) => Promise<T>,
  timeoutMs: number = 10_000,
): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL lock_timeout = ${timeoutMs}`);
    await acquireLock(client, LOCK_NS.USER, userId);

    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Lock two users in a deadlock-safe order (e.g. for transfers).
 */
export async function withTwoUserLocks<T>(
  userA:     string,
  userB:     string,
  fn:        (client: PoolClient) => Promise<T>,
  timeoutMs: number = 10_000,
): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL lock_timeout = ${timeoutMs}`);

    // Sort by hashed id so A→B and B→A always acquire in the same order
    const aId = id32(userA);
    const bId = id32(userB);
    const [first, second] = aId < bId
      ? [userA, userB]
      : aId > bId
        ? [userB, userA]
        : (userA < userB ? [userA, userB] : [userB, userA]); // tiebreak by string

    await acquireLock(client, LOCK_NS.USER, first);
    await acquireLock(client, LOCK_NS.USER, second);

    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Named resource lock — for things like "draw:weekly", "pool:daily",
 * "circle:<uuid>". Uses the RESOURCE namespace which cannot collide
 * with USER locks.
 */
export async function withResourceLock<T>(
  resource:  string,
  fn:        (client: PoolClient) => Promise<T>,
  timeoutMs: number = 30_000,
): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL lock_timeout = ${timeoutMs}`);
    await acquireLock(client, LOCK_NS.RESOURCE, resource);

    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Specialized: lock for an entire draw cycle (only one runner per pool).
 * Distinct namespace so it never blocks a deposit's resource lock.
 */
export async function withDrawLock<T>(
  poolType:  string,
  fn:        (client: PoolClient) => Promise<T>,
  timeoutMs: number = 60_000,
): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL lock_timeout = ${timeoutMs}`);
    await acquireLock(client, LOCK_NS.DRAW, poolType);

    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export { LOCK_NS };
