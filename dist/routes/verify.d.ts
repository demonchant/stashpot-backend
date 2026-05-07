/**
 * StashPot — Public Verifiability Endpoints
 *
 * Zero trust required — anyone can reproduce the winner selection
 * from on-chain data plus what these endpoints return.
 *
 * No auth. Cached via Redis.
 */
declare const router: import("express-serve-static-core").Router;
export default router;
