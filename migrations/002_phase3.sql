
BEGIN;

-- ─── CIDR / subnet blacklist ──────────────────────────────────────────────────
-- Extends blocking from individual IPs to whole subnets and ASNs

CREATE TABLE IF NOT EXISTS cidr_blocks (
  id         SERIAL PRIMARY KEY,
  cidr       CIDR   NOT NULL UNIQUE,          -- e.g. 185.220.101.0/24
  asn        TEXT,                             -- e.g. AS60729 (optional, for ASN-level blocks)
  severity   TEXT NOT NULL DEFAULT 'HIGH'
               CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  reason     TEXT,
  added_by   TEXT DEFAULT 'analyst',
  added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  tags       TEXT[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_cidr_blocks_cidr       ON cidr_blocks USING GIST (cidr inet_ops);
CREATE INDEX IF NOT EXISTS idx_cidr_blocks_asn        ON cidr_blocks (asn);
CREATE INDEX IF NOT EXISTS idx_cidr_blocks_expires_at ON cidr_blocks (expires_at);

-- ─── SIEM targets (multi-target support) ─────────────────────────────────────
-- Each row is a named SIEM destination. All active targets receive every event.

CREATE TABLE IF NOT EXISTS siem_targets (
  id         SERIAL PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,             -- e.g. "Splunk Production"
  type       TEXT NOT NULL
               CHECK (type IN ('splunk','elastic','sentinel','qradar','generic')),
  url        TEXT NOT NULL,
  token      TEXT,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  min_score  INTEGER NOT NULL DEFAULT 0,
  min_risk   TEXT    NOT NULL DEFAULT 'LOW'
               CHECK (min_risk IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  verify_ssl BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_sent  TIMESTAMPTZ,
  last_error TEXT
);

-- ─── Threat clusters (campaign detection) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_clusters (
  id           SERIAL PRIMARY KEY,
  cluster_key  TEXT NOT NULL,                  -- e.g. "subnet:185.220.101.0/24" or "asn:AS60729"
  cluster_type TEXT NOT NULL
                 CHECK (cluster_type IN ('subnet','asn','country')),
  ip_count     INTEGER NOT NULL DEFAULT 1,
  max_score    INTEGER NOT NULL DEFAULT 0,
  severity     TEXT,
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved     BOOLEAN NOT NULL DEFAULT FALSE,
  details      JSONB DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_clusters_key
  ON threat_clusters (cluster_key)
  WHERE resolved = FALSE;

CREATE INDEX IF NOT EXISTS idx_threat_clusters_last_seen
  ON threat_clusters (last_seen DESC);

-- ─── Case accounts ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS case_accounts (
  id           SERIAL PRIMARY KEY,
  case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  account_id   TEXT NOT NULL,                  -- external account identifier
  account_type TEXT NOT NULL DEFAULT 'user'
                 CHECK (account_type IN ('user','service','device','other')),
  note         TEXT,
  added_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_case_accounts_case_id ON case_accounts (case_id);

COMMIT;
