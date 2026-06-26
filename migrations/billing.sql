-- Migration: add_billing
-- Adds subscription/plan state to users, and links api_keys to a user.
-- Safe to run multiple times (IF NOT EXISTS / IF EXISTS guards throughout).

BEGIN;

SELECT
    plan,
    subscription_status,
    current_period_end,
    cancel_at_period_end
FROM public.users
WHERE id = $1;
-- USERS: plan + Stripe identifiers ----------------------------------------

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS plan                  TEXT NOT NULL DEFAULT 'free',
  ADD COLUMN IF NOT EXISTS stripe_customer_id     TEXT,
  ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT,
  ADD COLUMN IF NOT EXISTS subscription_status    TEXT NOT NULL DEFAULT 'inactive',
  ADD COLUMN IF NOT EXISTS current_period_end     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS cancel_at_period_end    BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Constrain plan to known tiers (free, team — the only two offered today).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_plan_check'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_plan_check
      CHECK (plan IN ('free', 'team'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_subscription_status_check'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_subscription_status_check
      CHECK (subscription_status IN ('inactive', 'trialing', 'active', 'past_due', 'canceled', 'unpaid'));
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS users_stripe_customer_id_idx
  ON users (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_stripe_subscription_id_idx
  ON users (stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;

-- API_KEYS: link to owning user --------------------------------------------
-- Nullable on purpose: existing keys predate this column and have no owner.
-- New keys created via the dashboard must set this at creation time going forward.

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS api_keys_user_id_idx ON api_keys (user_id);

-- USAGE_EVENTS: per-feature daily counters ---------------------------------
-- One row per (user_id OR api_key_id, feature, day). Lets us enforce different
-- quotas per feature (active_scan, batch, watchlist, score) without overloading
-- api_keys.daily_used, which only tracks one undifferentiated counter today.

CREATE TABLE IF NOT EXISTS usage_events (
  id          BIGSERIAL PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  api_key_id  INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
  feature     TEXT NOT NULL,
  day         DATE NOT NULL DEFAULT CURRENT_DATE,
  count       INTEGER NOT NULL DEFAULT 0,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT usage_events_owner_check CHECK (
    (user_id IS NOT NULL AND api_key_id IS NULL) OR
    (user_id IS NULL AND api_key_id IS NOT NULL)
  )
);

-- One counter row per owner+feature+day, upserted on every use
CREATE UNIQUE INDEX IF NOT EXISTS usage_events_user_feature_day_idx
  ON usage_events (user_id, feature, day) WHERE user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS usage_events_key_feature_day_idx
  ON usage_events (api_key_id, feature, day) WHERE api_key_id IS NOT NULL;

COMMIT;