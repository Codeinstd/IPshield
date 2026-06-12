BEGIN;

-- 1. Add invite expiry column
ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS invite_expires_at TIMESTAMPTZ;

-- 2. Expire any existing pending invites that have no expiry set
--    (treats them as created today, gives 7 days from now)
UPDATE api_keys
SET invite_expires_at = NOW() + INTERVAL '7 days'
WHERE status = 'pending'
  AND invite_expires_at IS NULL;

-- 3. Verify
SELECT
  COUNT(*)                                              AS total_pending,
  COUNT(*) FILTER (WHERE invite_expires_at IS NOT NULL) AS with_expiry,
  COUNT(*) FILTER (WHERE invite_expires_at < NOW())     AS already_expired
FROM api_keys
WHERE status = 'pending';
