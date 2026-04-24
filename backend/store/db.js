/**
 * db.js — SQLite persistence via better-sqlite3
 * Place in: backend/store/db.js
 *
 * Install dep: npm install better-sqlite3
 */

const path = require("path");
let db;

try {
  const Database = require("better-sqlite3");
  db = new Database(path.join(__dirname, "../../ipshield.db"), { verbose: null });
  bootstrap();
} catch (err) {
  console.warn("SQLite unavailable — falling back to memory only:", err.message);
  db = null;
}

function bootstrap() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scores (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ip          TEXT    NOT NULL,
      score       INTEGER NOT NULL,
      risk_level  TEXT    NOT NULL,
      action      TEXT    NOT NULL,
      country     TEXT,
      city        TEXT,
      isp         TEXT,
      is_proxy    INTEGER DEFAULT 0,
      is_tor      INTEGER DEFAULT 0,
      is_dc       INTEGER DEFAULT 0,
      velocity    TEXT,
      scored_at   INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scores_ip ON scores(ip);
    CREATE INDEX IF NOT EXISTS idx_scores_risk ON scores(risk_level);
    CREATE INDEX IF NOT EXISTS idx_scores_at  ON scores(scored_at);

    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT
    );
  `);
}

function insertScore(result) {
  if (!db) return;
  try {
    const stmt = db.prepare(`
      INSERT INTO scores (ip, score, risk_level, action, country, city, isp, is_proxy, is_tor, is_dc, velocity, scored_at)
      VALUES (@ip, @score, @riskLevel, @action, @country, @city, @isp, @isProxy, @isTor, @isDc, @velocity, @scoredAt)
    `);
    stmt.run({
      ip:        result.ip,
      score:     result.score,
      riskLevel: result.riskLevel,
      action:    result.action,
      country:   result.geo?.country   || null,
      city:      result.geo?.city      || null,
      isp:       result.network?.isp   || null,
      isProxy:   result.intelligence?.isProxy    ? 1 : 0,
      isTor:     result.intelligence?.isTor      ? 1 : 0,
      isDc:      result.intelligence?.isDatacenter ? 1 : 0,
      velocity:  result.intelligence?.velocity   || null,
      scoredAt:  Date.now()
    });
  } catch (err) {
    console.error("DB insert error:", err.message);
  }
}

function getHistory(limit = 100) {
  if (!db) return [];
  try {
    return db.prepare(`
      SELECT * FROM scores ORDER BY scored_at DESC LIMIT ?
    `).all(limit);
  } catch { return []; }
}

function getRiskDistribution() {
  if (!db) return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  try {
    const rows = db.prepare(`
      SELECT risk_level, COUNT(*) as count FROM scores GROUP BY risk_level
    `).all();
    const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    rows.forEach(r => { if (r.risk_level in dist) dist[r.risk_level] = r.count; });
    return dist;
  } catch { return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }; }
}

function getTotalScored() {
  if (!db) return 0;
  try {
    return db.prepare("SELECT COUNT(*) as c FROM scores").get().c;
  } catch { return 0; }
}

function getTopThreats(limit = 10) {
  if (!db) return [];
  try {
    return db.prepare(`
      SELECT ip, score, risk_level, country, city, scored_at
      FROM scores WHERE risk_level IN ('CRITICAL','HIGH')
      ORDER BY score DESC, scored_at DESC LIMIT ?
    `).all(limit);
  } catch { return []; }
}

function isAvailable() { return !!db; }

module.exports = { insertScore, getHistory, getRiskDistribution, getTotalScored, getTopThreats, isAvailable };