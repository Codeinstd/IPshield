-- Migration: migrate_auth_to_users
--
-- Background: auth.routes.js has always authenticated against api_keys
-- (email + password_hash + MFA columns living there), while the billing
-- migration assumed users was the account table. This migration makes
-- users the real source of truth for login/MFA, and turns api_keys back
-- into pure API keys linked to their owning user via user_id.
--
-- Safe to run multiple times — every step is guarded (IF NOT EXISTS / ON CONFLICT).

BEGIN;

-- 1. Add auth/MFA columns to users (mirroring what api_keys has today) -----

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_secret          TEXT,
  ADD COLUMN IF NOT EXISTS mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mfa_verified_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_backup_codes    TEXT[],
  ADD COLUMN IF NOT EXISTS reset_token         TEXT,
  ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMPTZ;

-- 2. Migrate every api_keys row that is a real login account (has both ----
--    email and password_hash) into users. Matched/inserted by email —
--    if a users row with that email already exists, its auth columns are
--    filled in from api_keys rather than creating a duplicate. In this
--    database today, none of the 3 accounts being migrated collide with
--    an existing users row, so this always inserts — but the ON CONFLICT
--    guard makes it safe to re-run or use in other environments where a
--    users row might already exist.

INSERT INTO users (email, password_hash, role, mfa_secret, mfa_enabled, mfa_verified_at, mfa_backup_codes, created_at)
SELECT
  LOWER(ak.email),
  ak.password_hash,
  ak.role,
  ak.mfa_secret,
  ak.mfa_enabled,
  ak.mfa_verified_at,
  ak.mfa_backup_codes,
  COALESCE(ak.activated_at, ak.created_at, NOW())
FROM api_keys ak
WHERE ak.email IS NOT NULL
  AND ak.password_hash IS NOT NULL
ON CONFLICT (email) DO UPDATE SET
  password_hash       = COALESCE(users.password_hash, EXCLUDED.password_hash),
  mfa_secret           = COALESCE(users.mfa_secret, EXCLUDED.mfa_secret),
  mfa_enabled          = users.mfa_enabled OR EXCLUDED.mfa_enabled,
  mfa_verified_at      = COALESCE(users.mfa_verified_at, EXCLUDED.mfa_verified_at),
  mfa_backup_codes     = COALESCE(users.mfa_backup_codes, EXCLUDED.mfa_backup_codes);

-- 3. Link each migrated api_keys row to its new/matched users row, by email.
--    The api_key itself is untouched otherwise — it keeps working exactly
--    as an API key (key_hash, daily_limit, role, etc. all stay as-is).

UPDATE api_keys ak
SET user_id = u.id
FROM users u
WHERE LOWER(ak.email) = u.email
  AND ak.password_hash IS NOT NULL
  AND ak.user_id IS NULL;

COMMIT;

-- ── Verification queries — run these manually after the migration ─────────
-- SELECT id, email, role, mfa_enabled FROM users ORDER BY id;
-- SELECT id, email, role, user_id FROM api_keys WHERE password_hash IS NOT NULL ORDER BY id;
-- Expect: 3 new users rows (designer@ipshield.live, serenitykid01@gmail.com,
-- codeinstd@gmail.com), each with mfa_enabled = true, and the matching
-- api_keys rows (1, 42, 71) now showing a non-null user_id pointing at them.