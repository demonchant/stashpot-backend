/**
 * StashPot — Pool Routes (HARDENED)
 *
 * All fixes applied:
 *   [#2] verifyJwt on every route
 *   [#5] Zod validation on every request body
 *   [Missing #1] Idempotency-Key required on mutations
 *   [Missing #2] withUserLock on every balance mutation
 *   [Missing #3] Audit log on every mutation
 */
declare const router: import("express-serve-static-core").Router;
export default router;
