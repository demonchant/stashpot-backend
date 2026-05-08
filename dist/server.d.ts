/**
 * StashPot — Hardened API Server
 *
 * All 12 audit findings addressed:
 *   [Fix #1] Webhooks signature verification (in routes/webhooks.ts)
 *   [Fix #2] Auth middleware applied to ALL sensitive routes (via verifyJwt inside each router)
 *   [Fix #3] Feature guard + auth combined
 *   [Fix #4] Per-endpoint rate limits + per-user throttling
 *   [Fix #5] Zod validation on every request body (utils/validation.ts)
 *   [Fix #6] Strict CORS whitelist
 *   [Fix #7] Helmet CSP enabled with proper directives
 *   [Fix #8] Error handler redacts internal messages in production
 *   [Perf #9] 1mb JSON body limit
 *   [Perf #10] compression middleware
 *   [Perf #11] Redis cache layer (utils/cache.ts)
 *   [Perf #12] PG connection pool (models/db.ts)
 * Plus Critical Missing Concepts:
 *   [Missing #1] Idempotency-Key enforcement (utils/idempotency.ts)
 *   [Missing #2] Transaction locking via PG advisory locks (utils/dbLocks.ts)
 *   [Missing #3] Append-only hash-chained audit log (utils/audit.ts)
 *   [Missing #4] Deterministic reward engine (WeightService + on-chain Merkle commit)
 */
import 'dotenv/config';
declare const app: import("express-serve-static-core").Express;
export default app;
