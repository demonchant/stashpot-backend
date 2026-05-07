/**
 * StashPot — Webhook Handlers (Fix #1: webhook security)
 *
 * Every webhook endpoint:
 *   1. Reads the RAW body (json-parser on /api/webhooks does verify+preserve)
 *   2. Validates provider HMAC signature with constant-time comparison
 *   3. Validates timestamp is within ±5 minutes (prevents replay)
 *   4. Records every event by provider_ref — duplicate deliveries become no-ops
 *   5. Never modifies balances without an existing pending fiat_transaction row
 *   6. Audits every receipt — accepted and rejected
 */
declare const router: import("express-serve-static-core").Router;
export default router;
