/**
 * StashPot — Idempotency Middleware (HARDENED)
 *
 * Fixes from advanced audit finding #1:
 *   - Canonical JSON serialization (sorted keys recursively) prevents
 *     `{a:1,b:2}` and `{b:2,a:1}` from being seen as different requests.
 *   - Floats are normalized to a canonical representation.
 *   - Numbers serialize via the JSON number form (no precision drift in keys).
 *
 * Scoping: key = sha256(user_id || idempotency_header || canonical_path_body)
 * - Same user + same key + canonically-equal body → cached response replayed
 * - Same user + same key + different canonical body → 409 (key reuse conflict)
 * - Different users cannot collide
 */

import { Request, Response, NextFunction } from 'express';
import crypto                                from 'crypto';
import { db }                                from '../models/db.js';
import { AuthRequest }                       from '../middleware/auth.js';

/**
 * Recursive canonical JSON serializer.
 * - Object keys sorted lexicographically at every depth
 * - Arrays preserve order (semantic ordering matters)
 * - Numbers serialized via Number.prototype.toString (consistent IEEE-754)
 * - undefined fields omitted (matches JSON.stringify behavior)
 * - null preserved
 *
 * NOTE: This is the same algorithm as JCS (RFC 8785) for the subset we use.
 * We do NOT support custom toJSON or BigInt.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'null';

  const t = typeof value;

  if (t === 'boolean')   return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value as number)) return 'null';
    return (value as number).toString();
  }
  if (t === 'string')    return JSON.stringify(value);

  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }

  if (t === 'object') {
    const keys = Object.keys(value as object).sort();
    const parts = keys
      .filter(k => (value as any)[k] !== undefined)
      .map(k => JSON.stringify(k) + ':' + canonicalize((value as any)[k]));
    return '{' + parts.join(',') + '}';
  }

  return 'null';
}

/**
 * Idempotency middleware — required on every financial mutation endpoint.
 *
 * Required header: Idempotency-Key (16-128 chars, [a-zA-Z0-9_-]+)
 */
export async function requireIdempotency(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const key = req.headers['idempotency-key'] as string | undefined;

  if (!key || typeof key !== 'string' || key.length < 16 || key.length > 128) {
    res.status(400).json({ error: 'Idempotency-Key header required (16-128 chars)' });
    return;
  }
  if (!/^[a-zA-Z0-9_\-]+$/.test(key)) {
    res.status(400).json({ error: 'Idempotency-Key contains invalid characters' });
    return;
  }

  const userId = req.user?.id;
  if (!userId) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  // [FIX] Canonical hash — order-independent, precision-stable
  const canonical = canonicalize({ path: req.path, body: req.body });
  const bodyHash  = crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
  const fullKey   = `${userId}:${key}:${bodyHash}`;
  const scopePrefix = `${userId}:${key}:`;

  // 1. Exact match → replay cached response
  const cached = await db.query(
    'SELECT response FROM idempotency_keys WHERE key = $1',
    [fullKey],
  );
  if (cached.rows.length) {
    res.set('X-Idempotent-Replay', 'true');
    res.json(cached.rows[0].response);
    return;
  }

  // 2. Same user+key with different body → key-reuse conflict
  const conflict = await db.query(
    "SELECT 1 FROM idempotency_keys WHERE key LIKE $1 AND key != $2 LIMIT 1",
    [`${scopePrefix}%`, fullKey],
  );
  if (conflict.rows.length) {
    res.status(409).json({
      error: 'Idempotency-Key already used with a different request body',
    });
    return;
  }

  // 3. New request — hijack res.json to cache on success
  const originalJson = res.json.bind(res);
  res.json = ((body: any) => {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      db.query(
        'INSERT INTO idempotency_keys(key, response) VALUES($1, $2) ON CONFLICT DO NOTHING',
        [fullKey, JSON.stringify(body)],
      ).catch(err => console.error('[idempotency] cache write failed:', err.message));
    }
    return originalJson(body);
  }) as any;

  next();
}
