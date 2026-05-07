-- StashPot — Migration: Add Privy Auth Support
-- Run AFTER the original schema.sql:
--   psql $DATABASE_URL -f migrations/001_add_privy.sql
--
-- Adds:
--   1. privy_did column to users (Privy's stable user identifier)
--   2. unique index on email so we can dedupe email-based signups
--   3. unique index on privy_did
--
-- Note: users.wallet is still NOT NULL because every Privy user gets either
-- an embedded Solana wallet (auto-created by Privy) OR a linked external
-- wallet (Phantom/Solflare). The wallet is always present by the time we
-- write the user row.

BEGIN;

-- 1. Add privy_did column (nullable for legacy wallet-only signups)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS privy_did TEXT;

-- 2. Unique index on privy_did (one StashPot account per Privy user)
CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_privy_did
  ON users(privy_did)
  WHERE privy_did IS NOT NULL;

-- 3. Unique index on email (case-insensitive)
-- Drops accidental duplicates by keeping the oldest record. If you have
-- existing duplicates this will fail loudly — clean them up first.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email
  ON users(LOWER(email))
  WHERE email IS NOT NULL;

-- 4. Index for fast email lookups during login
CREATE INDEX IF NOT EXISTS idx_users_email
  ON users(email)
  WHERE email IS NOT NULL;

COMMIT;
