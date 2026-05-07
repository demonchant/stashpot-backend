/**
 * StashPot Feature Flags — Live Reload
 *
 * Closes SECURITY.md §6.4: features can now be toggled WITHOUT restarting
 * the service.
 *
 * Source of truth, in priority order:
 *   1. `feature_flags` DB table (live, per-environment, audited)
 *   2. Env vars (FEATURE_<NAME>) — fallback for cold start
 *   3. Hardcoded defaults
 *
 * The DB is polled every 10 seconds. Updates take effect protocol-wide
 * within that window. An admin endpoint (POST /api/admin/features) lets
 * authorized callers flip flags at runtime.
 *
 * IMPORTANT: backend ALWAYS enforces. Frontend only mirrors for UX.
 * A user discovering the FEATURE_LOANS endpoint while it's "off" will
 * still hit a 403 because featureGuard checks the live state.
 */
export type FeatureKey = 'VAULT' | 'DEPOSITS' | 'WITHDRAWALS' | 'PRIZE_POOLS' | 'INHERITANCE' | 'CIRCLES' | 'LOANS' | 'REFERRALS' | 'FIAT' | 'CARDS';
/**
 * Synchronously read a flag — uses the cached value.
 * featureGuard middleware uses this — sync access is essential.
 */
export declare function isFeatureEnabled(key: FeatureKey): boolean;
export declare function publicFeatures(): Record<FeatureKey, boolean>;
/**
 * Refresh the in-memory cache from the DB.
 * Called every 10 seconds by the poller.
 * Safe to call concurrently — last-write-wins.
 */
export declare function refreshFeatures(): Promise<void>;
/**
 * Set a feature on/off — writes to DB and refreshes cache immediately.
 * Audits via the feature_events table.
 */
export declare function setFeature(key: FeatureKey, enabled: boolean, changedBy: string): Promise<void>;
/**
 * Start the 10-second poller.
 * Call once at server boot; idempotent.
 */
export declare function startFeaturePoller(intervalMs?: number): void;
export declare function stopFeaturePoller(): void;
export declare const FEATURES: Record<FeatureKey, boolean>;
