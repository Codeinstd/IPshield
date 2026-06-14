-- Immutable Audit Log Migration
-- Run in Render psql: psql $DATABASE_URL -f audit-immutable-migration.sql

-- 1. Add hash chain columns
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS prev_hash TEXT,
  ADD COLUMN IF NOT EXISTS row_hash  TEXT;

-- 2. Index for fast chain walks
CREATE INDEX IF NOT EXISTS idx_audit_log_id_desc
  ON audit_log (id DESC);

-- 3. Seed existing rows with GENESIS so verify doesn't break on old data
--    Only touches rows that have no hash yet
UPDATE audit_log
SET prev_hash = 'GENESIS',
    row_hash  = 'LEGACY-' || id::text
WHERE prev_hash IS NULL;

-- 4. Prevent DELETE on audit_log — append-only enforcement at DB level
--    Even direct psql access cannot delete rows
CREATE OR REPLACE RULE audit_log_no_delete AS
  ON DELETE TO audit_log
  DO INSTEAD NOTHING;

-- 5. Prevent UPDATE on audit_log — rows are immutable once written
CREATE OR REPLACE RULE audit_log_no_update AS
  ON UPDATE TO audit_log
  DO INSTEAD NOTHING;

-- 6. Verify the columns exist
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'audit_log'
  AND column_name IN ('prev_hash', 'row_hash');

-- 7. Verify the rules exist
SELECT rulename, tablename, ev_type
FROM pg_rules
WHERE tablename = 'audit_log';
