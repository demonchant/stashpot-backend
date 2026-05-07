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
import { Response, NextFunction } from 'express';
import { AuthRequest } from '../middleware/auth.js';
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
export declare function canonicalize(value: unknown): string;
/**
 * Idempotency middleware — required on every financial mutation endpoint.
 *
 * Required header: Idempotency-Key (16-128 chars, [a-zA-Z0-9_-]+)
 */
export declare function requireIdempotency(req: AuthRequest, res: Response, next: NextFunction): Promise<void>;
