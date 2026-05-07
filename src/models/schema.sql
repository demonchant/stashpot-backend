-- StashPot Production Schema
-- Run: psql $DATABASE_URL -f schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  wallet         TEXT NOT NULL UNIQUE,
  username       TEXT UNIQUE,
  email          TEXT,
  fcm_token      TEXT,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at   TIMESTAMPTZ DEFAULT NOW(),
  is_banned      BOOLEAN DEFAULT FALSE
);
CREATE INDEX idx_users_wallet ON users(wallet);

-- ─── Auth nonces ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_nonces (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  wallet     TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  used       BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_nonces_wallet ON auth_nonces(wallet);

-- ─── Balances ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS balances (
  user_id      UUID PRIMARY KEY REFERENCES users(id),
  usdc         NUMERIC(20,6) DEFAULT 0,
  last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Prize pool entries ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pool_entries (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id        UUID NOT NULL REFERENCES users(id),
  pool_type      TEXT NOT NULL CHECK (pool_type IN ('daily','weekly','monthly')),
  amount         NUMERIC(20,6) NOT NULL DEFAULT 0,
  avg_balance    NUMERIC(20,6) NOT NULL DEFAULT 0,
  joined_at      TIMESTAMPTZ DEFAULT NOW(),
  last_update_at TIMESTAMPTZ DEFAULT NOW(),
  early_exits    INT DEFAULT 0,
  active         BOOLEAN DEFAULT TRUE,
  prize_opted_in BOOLEAN DEFAULT TRUE,
  UNIQUE(user_id, pool_type)
);
CREATE INDEX idx_pool_entries_user ON pool_entries(user_id);
CREATE INDEX idx_pool_entries_type_active ON pool_entries(pool_type, active);

-- ─── Pool draw records ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pool_rewards (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  pool_type       TEXT NOT NULL,
  winner_id       UUID REFERENCES users(id),
  amount          NUMERIC(20,6) NOT NULL,
  round_index     BIGINT NOT NULL,
  merkle_root     TEXT,
  vrf_result      TEXT,
  random_value    TEXT,
  participants    INT DEFAULT 0,
  distributed_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_pool_rewards_round ON pool_rewards(pool_type, round_index);

-- ─── Draw lock state ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pool_draw_locks (
  pool_type TEXT PRIMARY KEY,
  locked    BOOLEAN DEFAULT FALSE,
  locked_at TIMESTAMPTZ,
  draw_at   TIMESTAMPTZ
);
INSERT INTO pool_draw_locks(pool_type) VALUES('daily'),('weekly'),('monthly') ON CONFLICT DO NOTHING;

-- ─── Transactions ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id    UUID NOT NULL REFERENCES users(id),
  type       TEXT NOT NULL,
  amount     NUMERIC(20,6) NOT NULL,
  meta       JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_tx_user ON transactions(user_id);
CREATE INDEX idx_tx_type ON transactions(type);

-- ─── Scores ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scores (
  user_id       UUID PRIMARY KEY REFERENCES users(id),
  composite     INT DEFAULT 0,
  tier          TEXT DEFAULT 'None',
  savings_dim   INT DEFAULT 0,
  circles_dim   INT DEFAULT 0,
  vaults_dim    INT DEFAULT 0,
  loans_dim     INT DEFAULT 0,
  longevity_dim INT DEFAULT 0,
  breadth_bonus BOOLEAN DEFAULT FALSE,
  in_default    BOOLEAN DEFAULT FALSE,
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS score_events (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id    UUID NOT NULL REFERENCES users(id),
  signal     TEXT NOT NULL,
  data       JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_score_events_user ON score_events(user_id);

-- ─── Inheritance (TimeLockr) ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vaults (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id          UUID NOT NULL REFERENCES users(id),
  will_pda         TEXT,
  inactivity_days  INT DEFAULT 180,
  last_ping        TIMESTAMPTZ DEFAULT NOW(),
  status           TEXT DEFAULT 'active' CHECK (status IN ('active','triggered','cancelled')),
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vault_beneficiaries (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  vault_id    UUID NOT NULL REFERENCES vaults(id),
  wallet      TEXT NOT NULL,
  pct         INT NOT NULL CHECK (pct > 0 AND pct <= 100),
  paid        BOOLEAN DEFAULT FALSE
);

-- ─── Savings Circles ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS circles (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  circle_id    BIGINT UNIQUE NOT NULL,
  name         TEXT,
  admin_id     UUID REFERENCES users(id),
  max_members  INT DEFAULT 6,
  contribution NUMERIC(20,6) NOT NULL,
  cycle_days   INT DEFAULT 7,
  started      BOOLEAN DEFAULT FALSE,
  completed    BOOLEAN DEFAULT FALSE,
  current_cycle INT DEFAULT 0,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS circle_members (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  circle_id   UUID REFERENCES circles(id),
  user_id     UUID REFERENCES users(id),
  slot_index  INT NOT NULL,
  joined_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(circle_id, user_id)
);

CREATE TABLE IF NOT EXISTS circle_contributions (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  circle_id  UUID REFERENCES circles(id),
  user_id    UUID REFERENCES users(id),
  cycle      INT NOT NULL,
  amount     NUMERIC(20,6) NOT NULL,
  tx_sig     TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(circle_id, user_id, cycle)
);

-- ─── Microloans ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS loans (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id          UUID NOT NULL REFERENCES users(id),
  loan_pda         TEXT,
  loan_type        CHAR(1) CHECK (loan_type IN ('A','B','C','D')),
  principal        NUMERIC(20,6) NOT NULL,
  apr_bps          INT NOT NULL,
  collateral       NUMERIC(20,6) DEFAULT 0,
  total_repaid     NUMERIC(20,6) DEFAULT 0,
  duration_days    INT NOT NULL,
  score_at_issuance INT,
  status           TEXT DEFAULT 'active' CHECK (status IN ('active','repaid','defaulted','liquidated')),
  issued_at        TIMESTAMPTZ DEFAULT NOW(),
  due_at           TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_loans_user ON loans(user_id, status);

-- ─── Fiat transactions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fiat_transactions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID REFERENCES users(id),
  provider        TEXT NOT NULL,
  provider_ref    TEXT UNIQUE,
  direction       TEXT CHECK (direction IN ('deposit','withdrawal')),
  fiat_amount     NUMERIC(20,2),
  fiat_currency   TEXT,
  usdc_amount     NUMERIC(20,6),
  status          TEXT DEFAULT 'pending',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  settled_at      TIMESTAMPTZ
);

-- ─── Referrals ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS referrals (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  referrer_id  UUID REFERENCES users(id),
  referred_id  UUID REFERENCES users(id),
  code         TEXT UNIQUE,
  deposited    BOOLEAN DEFAULT FALSE,
  reward_paid  BOOLEAN DEFAULT FALSE,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(referred_id)
);
CREATE INDEX idx_referrals_referrer ON referrals(referrer_id);

-- ─── Idempotency keys ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS idempotency_keys (
  key        TEXT PRIMARY KEY,
  response   JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Feature event log ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feature_events (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  feature    TEXT NOT NULL,
  enabled    BOOLEAN NOT NULL,
  changed_by TEXT,
  changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Feature flags (live state — pollable, mutable) ──────────────────────────
-- See config/features.ts. The backend polls this table every 10 seconds.
-- Toggle a feature without restarting via POST /api/admin/features.
CREATE TABLE IF NOT EXISTS feature_flags (
  feature    TEXT PRIMARY KEY,
  enabled    BOOLEAN NOT NULL,
  changed_by TEXT,
  changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Audit log (append-only, hash-chained) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  action     TEXT NOT NULL,
  user_id    UUID REFERENCES users(id),
  target_id  TEXT,
  amount     NUMERIC(20,6),
  metadata   JSONB DEFAULT '{}',
  ip         TEXT,
  user_agent TEXT,
  status     TEXT NOT NULL CHECK (status IN ('success','failure')),
  error      TEXT,
  prev_hash  CHAR(64) NOT NULL,
  row_hash   CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_user        ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_action      ON audit_log(action,  created_at DESC);
CREATE INDEX idx_audit_created     ON audit_log(created_at DESC);

-- Revoke UPDATE and DELETE from application user (must be run by superuser).
-- Uncomment for production:
-- REVOKE UPDATE, DELETE ON audit_log FROM stashpot;

-- ─── Security events ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_events (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_type TEXT NOT NULL,
  ip         TEXT,
  user_id    UUID REFERENCES users(id),
  details    JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_sec_events_type ON security_events(event_type, created_at DESC);
CREATE INDEX idx_sec_events_ip   ON security_events(ip, created_at DESC);

-- ─── Webhook dedup (prevents replay of delivered events) ─────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  provider    TEXT NOT NULL,
  event_id    TEXT NOT NULL,
  payload     JSONB,
  received_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(provider, event_id)
);
CREATE INDEX idx_webhook_provider_ts ON webhook_deliveries(provider, received_at DESC);

-- ─── Audit log external anchoring (forensic backstop) ─────────────────────────
-- Periodic snapshots of the audit_log chain head, published externally.
-- Truncation or tampering of audit_log is detected via verifyAgainstLastAnchor.
CREATE TABLE IF NOT EXISTS anchor_log (
  id           UUID PRIMARY KEY,
  chain_head   CHAR(64) NOT NULL,
  row_count    BIGINT NOT NULL,
  signed_at    TIMESTAMPTZ NOT NULL,
  signature    TEXT NOT NULL,
  destinations JSONB DEFAULT '[]',
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_anchor_signed_at ON anchor_log(signed_at DESC);
