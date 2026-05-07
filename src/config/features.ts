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

import { db }  from '../models/db.js';
import { log } from '../utils/logger.js';

export type FeatureKey =
  | 'VAULT'
  | 'DEPOSITS'
  | 'WITHDRAWALS'
  | 'PRIZE_POOLS'
  | 'INHERITANCE'
  | 'CIRCLES'
  | 'LOANS'
  | 'REFERRALS'
  | 'FIAT'
  | 'CARDS';

const ALL_KEYS: FeatureKey[] = [
  'VAULT', 'DEPOSITS', 'WITHDRAWALS',
  'PRIZE_POOLS', 'INHERITANCE', 'CIRCLES',
  'LOANS', 'REFERRALS', 'FIAT', 'CARDS',
];

function envBool(key: string, fallback: boolean): boolean {
  const v = process.env[`FEATURE_${key}`];
  if (v === undefined) return fallback;
  return v !== 'false' && v !== '0';
}

const DEFAULTS: Record<FeatureKey, boolean> = {
  VAULT:       envBool('VAULT',       true),
  DEPOSITS:    envBool('DEPOSITS',    true),
  WITHDRAWALS: envBool('WITHDRAWALS', true),
  PRIZE_POOLS: envBool('PRIZE_POOLS', true),
  INHERITANCE: envBool('INHERITANCE', true),
  CIRCLES:     envBool('CIRCLES',     true),
  LOANS:       envBool('LOANS',       false),
  REFERRALS:   envBool('REFERRALS',   true),
  FIAT:        envBool('FIAT',        true),
  CARDS:       envBool('CARDS',       false),
};

// In-memory cache, refreshed from DB
let CURRENT: Record<FeatureKey, boolean> = { ...DEFAULTS };
let lastRefresh = 0;

/**
 * Synchronously read a flag — uses the cached value.
 * featureGuard middleware uses this — sync access is essential.
 */
export function isFeatureEnabled(key: FeatureKey): boolean {
  return CURRENT[key];
}

export function publicFeatures(): Record<FeatureKey, boolean> {
  return { ...CURRENT };
}

/**
 * Refresh the in-memory cache from the DB.
 * Called every 10 seconds by the poller.
 * Safe to call concurrently — last-write-wins.
 */
export async function refreshFeatures(): Promise<void> {
  try {
    const r = await db.query(
      'SELECT feature, enabled FROM feature_flags WHERE feature = ANY($1::text[])',
      [ALL_KEYS],
    );

    // Start from defaults; overlay DB rows
    const next: Record<FeatureKey, boolean> = { ...DEFAULTS };
    for (const row of r.rows) {
      if (ALL_KEYS.includes(row.feature)) {
        next[row.feature as FeatureKey] = !!row.enabled;
      }
    }

    // Detect changes for logging
    for (const k of ALL_KEYS) {
      if (CURRENT[k] !== next[k]) {
        log.info('feature.toggled', { feature: k, from: CURRENT[k], to: next[k] });
      }
    }

    CURRENT      = next;
    lastRefresh  = Date.now();
  } catch (err) {
    log.error('feature.refresh_failed', { err: (err as Error).message });
    // Keep CURRENT — degrade gracefully
  }
}

/**
 * Set a feature on/off — writes to DB and refreshes cache immediately.
 * Audits via the feature_events table.
 */
export async function setFeature(
  key:        FeatureKey,
  enabled:    boolean,
  changedBy:  string,
): Promise<void> {
  await db.query(
    `INSERT INTO feature_flags(feature, enabled, changed_by, changed_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (feature) DO UPDATE
     SET enabled = EXCLUDED.enabled,
         changed_by = EXCLUDED.changed_by,
         changed_at = NOW()`,
    [key, enabled, changedBy],
  );
  await db.query(
    `INSERT INTO feature_events(feature, enabled, changed_by) VALUES($1, $2, $3)`,
    [key, enabled, changedBy],
  );
  await refreshFeatures();
}

let pollerHandle: NodeJS.Timeout | null = null;

/**
 * Start the 10-second poller.
 * Call once at server boot; idempotent.
 */
export function startFeaturePoller(intervalMs = 10_000): void {
  if (pollerHandle) return;
  // First refresh immediately
  refreshFeatures().catch(() => {});
  pollerHandle = setInterval(() => {
    refreshFeatures().catch(() => {});
  }, intervalMs);
  // Don't keep the process alive solely on this timer
  pollerHandle.unref();
  log.info('feature.poller.started', { intervalMs });
}

export function stopFeaturePoller(): void {
  if (pollerHandle) {
    clearInterval(pollerHandle);
    pollerHandle = null;
  }
}

// Backward-compat — code still imports `FEATURES` as a record of booleans.
// We expose a Proxy that dispatches to the live cache so existing call
// sites (`if (FEATURES.LOANS)`) continue to work AND see live updates.
export const FEATURES = new Proxy({} as Record<FeatureKey, boolean>, {
  get(_target, prop: string) {
    return CURRENT[prop as FeatureKey];
  },
  ownKeys() { return ALL_KEYS; },
  has(_target, prop: string) { return ALL_KEYS.includes(prop as FeatureKey); },
  getOwnPropertyDescriptor() {
    return { enumerable: true, configurable: true };
  },
});
