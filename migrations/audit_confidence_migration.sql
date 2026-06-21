-- Adds confidence reporting to audit_log.
--
-- IMPORTANT: confidence and confidence_reasons are NOT part of the
-- hash-chain content (see appendAuditEntry in auditLog.store.js — the
-- hashed `content` object only ever contains ip, score, risk_level,
-- scored_at, prev_hash). These columns are descriptive metadata about
-- how much real data backed a score, added after the fact. They do not
-- affect row_hash for any existing or future row, and the /verify
-- chain-walk endpoint requires no changes because of this migration.

ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS confidence         TEXT,            -- 'HIGH' | 'MEDIUM' | 'LOW' | NULL (rows written before this migration)
  ADD COLUMN IF NOT EXISTS confidence_reasons JSONB DEFAULT '[]'::jsonb;

-- Optional: index if you expect to filter/search audit history by confidence level
CREATE INDEX IF NOT EXISTS idx_audit_log_confidence ON audit_log (confidence);
