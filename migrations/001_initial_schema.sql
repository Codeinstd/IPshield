
BEGIN;

-- ─── API keys ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
  id         SERIAL PRIMARY KEY,
  key        TEXT NOT NULL UNIQUE,
  name       TEXT,
  role       TEXT NOT NULL DEFAULT 'analyst'
               CHECK (role IN ('readonly', 'analyst', 'admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used  TIMESTAMPTZ
);

INSERT INTO api_keys (key, name, role)
VALUES ('your-secret-key-here', 'admin-key', 'admin');

-- ─── Audit log (score history) ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
  id            SERIAL PRIMARY KEY,
  ip            TEXT NOT NULL,
  score         INTEGER,
  risk_level    TEXT,
  action        TEXT,
  is_proxy      BOOLEAN,
  is_tor        BOOLEAN,
  is_datacenter BOOLEAN,
  country       TEXT,
  isp           TEXT,
  asn           TEXT,
  cached        BOOLEAN DEFAULT FALSE,
  scored_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_ip        ON audit_log (ip);
CREATE INDEX IF NOT EXISTS idx_audit_scored_at ON audit_log (scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_risk      ON audit_log (risk_level);

-- ─── Blacklist ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS blacklist (
  id         SERIAL PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  severity   TEXT NOT NULL DEFAULT 'HIGH'
               CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  category   TEXT,
  reason     TEXT,
  added_by   TEXT DEFAULT 'analyst',
  added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  tags       TEXT[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip         ON blacklist (ip);
CREATE INDEX IF NOT EXISTS idx_blacklist_severity   ON blacklist (severity);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON blacklist (expires_at);

-- ─── Cases ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cases (
  id          SERIAL PRIMARY KEY,
  title       TEXT NOT NULL,
  description TEXT,
  severity    TEXT NOT NULL DEFAULT 'MEDIUM'
                CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  status      TEXT NOT NULL DEFAULT 'Open'
                CHECK (status IN ('Open','Investigating','Contained','Resolved','Closed')),
  assigned_to TEXT DEFAULT 'analyst',
  tags        TEXT[] DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases (status);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases (severity);

-- Auto-update updated_at on any row change
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_cases_updated_at ON cases;
CREATE TRIGGER trg_cases_updated_at
  BEFORE UPDATE ON cases
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Case IPs ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS case_ips (
  id         SERIAL PRIMARY KEY,
  case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  score      INTEGER,
  risk_level TEXT,
  note       TEXT,
  added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_case_ips_case_id ON case_ips (case_id);

-- ─── Case notes ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS case_notes (
  id         SERIAL PRIMARY KEY,
  case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  note       TEXT NOT NULL,
  author     TEXT DEFAULT 'analyst',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_case_notes_case_id ON case_notes (case_id);

-- ─── Watchlist ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS watchlist (
  ip             TEXT PRIMARY KEY,
  label          TEXT,
  threshold      INTEGER NOT NULL DEFAULT 30,
  last_score     INTEGER,
  last_risk      TEXT,
  last_checked   TIMESTAMPTZ,
  added_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  alert_on_change BOOLEAN NOT NULL DEFAULT TRUE
);

-- ─── Telemetry ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS telemetry (
  id          SERIAL PRIMARY KEY,
  method      TEXT,
  route       TEXT,
  status_code INTEGER,
  duration_ms INTEGER,
  api_key_id  INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
  api_version TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_route       ON telemetry (route);
CREATE INDEX IF NOT EXISTS idx_telemetry_recorded_at ON telemetry (recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_api_key_id  ON telemetry (api_key_id);

COMMIT;
