
BEGIN;

-- ─── Extend api_keys for invite-only management 

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS email        TEXT,
  ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('pending','active','revoked','suspended')),
  ADD COLUMN IF NOT EXISTS invite_token TEXT UNIQUE,   -- one-time activation token
  ADD COLUMN IF NOT EXISTS invited_by   TEXT,          -- admin who created the invite
  ADD COLUMN IF NOT EXISTS invited_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoked_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoke_reason TEXT,
  ADD COLUMN IF NOT EXISTS daily_limit  INTEGER DEFAULT 1000,  -- max requests per day
  ADD COLUMN IF NOT EXISTS daily_used   INTEGER DEFAULT 0,     -- resets at midnight
  ADD COLUMN IF NOT EXISTS total_used   INTEGER DEFAULT 0,     -- lifetime counter
  ADD COLUMN IF NOT EXISTS last_reset   DATE DEFAULT CURRENT_DATE,
  ADD COLUMN IF NOT EXISTS notes        TEXT;                  -- admin notes

CREATE INDEX IF NOT EXISTS idx_api_keys_status       ON api_keys (status);
CREATE INDEX IF NOT EXISTS idx_api_keys_email        ON api_keys (email);
CREATE INDEX IF NOT EXISTS idx_api_keys_invite_token ON api_keys (invite_token);

-- Mark existing keys as active with no limit
UPDATE api_keys SET status = 'active', daily_limit = 999999 WHERE status = 'active';

-- ─── Score cache 
-- Persisted fallback cache (Redis is primary; this is the DB backup)

CREATE TABLE IF NOT EXISTS score_cache (
  ip          TEXT PRIMARY KEY,
  score       INTEGER NOT NULL,
  risk_level  TEXT    NOT NULL,
  payload     JSONB   NOT NULL,
  cached_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_score_cache_expires_at ON score_cache (expires_at);

-- ─── Usage log (per-key daily tracking) 

CREATE TABLE IF NOT EXISTS key_usage_log (
  id         BIGSERIAL PRIMARY KEY,
  key_id     INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  date       DATE    NOT NULL DEFAULT CURRENT_DATE,
  requests   INTEGER NOT NULL DEFAULT 0,
  scores     INTEGER NOT NULL DEFAULT 0,
  cache_hits INTEGER NOT NULL DEFAULT 0,
  errors     INTEGER NOT NULL DEFAULT 0,
  UNIQUE (key_id, date)
);

CREATE INDEX IF NOT EXISTS idx_key_usage_log_key_id ON key_usage_log (key_id);
CREATE INDEX IF NOT EXISTS idx_key_usage_log_date   ON key_usage_log (date DESC);

COMMIT;