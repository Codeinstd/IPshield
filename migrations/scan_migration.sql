-- ============================================================
-- IPShield: Active Scan Results
-- Run once against your PostgreSQL database on Render
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_jobs (
  id            SERIAL PRIMARY KEY,
  job_id        TEXT        NOT NULL UNIQUE,         -- BullMQ job id
  ip            TEXT        NOT NULL,
  status        TEXT        NOT NULL DEFAULT 'queued', -- queued | running | done | failed
  requested_by  TEXT,                                -- key id or user label
  consent       BOOLEAN     NOT NULL DEFAULT FALSE,  -- user accepted disclaimer
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  error         TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
  id            SERIAL PRIMARY KEY,
  job_id        TEXT        NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
  ip            TEXT        NOT NULL,
  scanner       TEXT        NOT NULL,               -- 'nmap' | 'nuclei'
  raw           JSONB,                              -- full tool output parsed
  summary       JSONB,                              -- distilled highlights
  severity      TEXT,                              -- highest finding: CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_ip     ON scan_jobs(ip);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_job ON scan_results(job_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip  ON scan_results(ip);
