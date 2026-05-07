/**
 * StashPot — Admin Routes
 *
 * Admin-only operations. Auth gated by JWT + admin-list check.
 * Use ADMIN_USER_IDS env var (comma-separated UUIDs) for a static
 * allowlist. In production this should be tied to a multisig.
 */
declare const router: import("express-serve-static-core").Router;
export default router;
