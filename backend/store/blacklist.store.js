const db = require("./db");

// In-memory fallback
let memStore = [];
let nextId   = 1;

function bootstrap() {
  if (!db.isAvailable()) return;
  try {
    db.getDb().exec(`
      CREATE TABLE IF NOT EXISTS blacklist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT NOT NULL,
        severity   TEXT NOT NULL DEFAULT 'HIGH',
        category   TEXT,
        reason     TEXT,
        added_by   TEXT DEFAULT 'analyst',
        added_at   TEXT DEFAULT (datetime('now')),
        expires_at TEXT,
        tags       TEXT DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_bl_ip       ON blacklist(ip);
      CREATE INDEX IF NOT EXISTS idx_bl_severity ON blacklist(severity);
      CREATE INDEX IF NOT EXISTS idx_bl_added_at ON blacklist(added_at);
    `);
    console.log("✓ Blacklist table ready");
  } catch (err) {
    console.error("Blacklist bootstrap error:", err.message);
  }
}

// ── Helpers 
function parseTags(raw) {
  try { return JSON.parse(raw || "[]"); } catch { return []; }
}

function formatEntry(row) {
  return {
    ...row,
    tags:    parseTags(row.tags),
    expired: row.expires_at ? new Date(row.expires_at) < new Date() : false
  };
}

// ── CRUD operations with SQLite and in-memory fallback
function listBlacklist({ severity, status, q, limit = 200, offset = 0 } = {}) {
  if (db.isAvailable()) {
    try {
      const conds  = [];
      const params = [];

      if (severity) { conds.push("severity = ?"); params.push(severity); }
      if (q)        { conds.push("(ip LIKE ? OR reason LIKE ? OR category LIKE ?)"); params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
      if (status === "active")  { conds.push("(expires_at IS NULL OR expires_at > datetime('now'))"); }
      if (status === "expired") { conds.push("expires_at IS NOT NULL AND expires_at <= datetime('now')"); }

      const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
      const total = db.getDb().prepare(`SELECT COUNT(*) as c FROM blacklist ${where}`).get(...params).c;
      const rows  = db.getDb().prepare(`SELECT * FROM blacklist ${where} ORDER BY added_at DESC LIMIT ? OFFSET ?`)
                      .all(...params, limit, offset);

      return { total, entries: rows.map(formatEntry) };
    } catch (err) {
      console.error("Blacklist list error:", err.message);
      return { total: 0, entries: [] };
    }
  }
  // Memory fallback
  let entries = [...memStore];
  if (severity) entries = entries.filter(e => e.severity === severity);
  if (q)        entries = entries.filter(e =>
    e.ip.includes(q) || (e.reason || "").includes(q) || (e.category || "").includes(q));
  return { total: entries.length, entries: entries.slice(offset, offset + limit) };
}

function addToBlacklist({ ip, severity = "HIGH", category = "", reason = "", added_by = "analyst", expires_at = null, tags = [] }) {
  const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : []);

  if (db.isAvailable()) {
    try {
      const result = db.getDb().prepare(`
        INSERT INTO blacklist (ip, severity, category, reason, added_by, expires_at, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(ip, severity, category, reason, added_by, expires_at || null, tagsJson);

      return formatEntry(db.getDb().prepare("SELECT * FROM blacklist WHERE id = ?").get(result.lastInsertRowid));
    } catch (err) {
      console.error("Blacklist insert error:", err.message);
      return null;
    }
  }
  // Memory fallback
  const entry = { id: nextId++, ip, severity, category, reason, added_by, added_at: new Date().toISOString(), expires_at: expires_at || null, tags };
  memStore.unshift(entry);
  return entry;
}

function updateBlacklist(id, { severity, category, reason, expires_at, tags }) {
  if (db.isAvailable()) {
    try {
      const fields = [];
      const params = [];
      if (severity   !== undefined) { fields.push("severity = ?");   params.push(severity); }
      if (category   !== undefined) { fields.push("category = ?");   params.push(category); }
      if (reason     !== undefined) { fields.push("reason = ?");     params.push(reason); }
      if (expires_at !== undefined) { fields.push("expires_at = ?"); params.push(expires_at || null); }
      if (tags       !== undefined) { fields.push("tags = ?");       params.push(JSON.stringify(tags)); }
      if (!fields.length) return null;

      db.getDb().prepare(`UPDATE blacklist SET ${fields.join(", ")} WHERE id = ?`).run(...params, id);
      const row = db.getDb().prepare("SELECT * FROM blacklist WHERE id = ?").get(id);
      return row ? formatEntry(row) : null;
    } catch (err) {
      console.error("Blacklist update error:", err.message);
      return null;
    }
  }
  // Memory fallback
  const entry = memStore.find(e => e.id === id);
  if (entry) { Object.assign(entry, { severity, category, reason, expires_at, tags }); }
  return entry || null;
}

function deleteFromBlacklist(id) {
  if (db.isAvailable()) {
    try { db.getDb().prepare("DELETE FROM blacklist WHERE id = ?").run(id); return true; }
    catch (err) { console.error("Blacklist delete error:", err.message); return false; }
  }
  memStore = memStore.filter(e => e.id !== id);
  return true;
}

function bulkDelete(ids) {
  if (!ids?.length) return 0;
  if (db.isAvailable()) {
    try {
      const placeholders = ids.map(() => "?").join(",");
      const info = db.getDb().prepare(`DELETE FROM blacklist WHERE id IN (${placeholders})`).run(...ids);
      return info.changes;
    } catch (err) { console.error("Blacklist bulk delete error:", err.message); return 0; }
  }
  const before = memStore.length;
  memStore = memStore.filter(e => !ids.includes(e.id));
  return before - memStore.length;
}

function isBlacklisted(ip) {
  if (db.isAvailable()) {
    try {
      const row = db.getDb().prepare(
        "SELECT id FROM blacklist WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"
      ).get(ip);
      return !!row;
    } catch { return false; }
  }
  return memStore.some(e => e.ip === ip && (!e.expires_at || new Date(e.expires_at) > new Date()));
}

function getAllActiveIPs() {
  if (db.isAvailable()) {
    try {
      return db.getDb().prepare(
        "SELECT ip, severity FROM blacklist WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY severity DESC"
      ).all();
    } catch { return []; }
  }
  return memStore.filter(e => !e.expires_at || new Date(e.expires_at) > new Date());
}

function getStats() {
  if (db.isAvailable()) {
    try {
      const total   = db.getDb().prepare("SELECT COUNT(*) as c FROM blacklist").get().c;
      const active  = db.getDb().prepare("SELECT COUNT(*) as c FROM blacklist WHERE expires_at IS NULL OR expires_at > datetime('now')").get().c;
      const expired = db.getDb().prepare("SELECT COUNT(*) as c FROM blacklist WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')").get().c;
      const bySev   = db.getDb().prepare("SELECT severity, COUNT(*) as count FROM blacklist GROUP BY severity").all();
      return { total, active, expired, bySeverity: Object.fromEntries(bySev.map(r => [r.severity, r.count])) };
    } catch { return { total: 0, active: 0, expired: 0, bySeverity: {} }; }
  }
  return { total: memStore.length, active: memStore.length, expired: 0, bySeverity: {} };
}

try { bootstrap(); } catch (_) {}

module.exports = {
  listBlacklist, addToBlacklist, updateBlacklist,
  deleteFromBlacklist, bulkDelete, isBlacklisted,
  getAllActiveIPs, getStats
};