
const db = require("./db");

let memCases = [];
let nextId   = 1;

function bootstrap() {
  if (!db.isAvailable()) return;
  try {
    db.getDb().exec(`
      CREATE TABLE IF NOT EXISTS cases (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        severity    TEXT NOT NULL DEFAULT 'MEDIUM',
        status      TEXT NOT NULL DEFAULT 'Open',
        assigned_to TEXT DEFAULT 'analyst',
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now')),
        closed_at   TEXT,
        tags        TEXT DEFAULT '[]'
      );

      CREATE TABLE IF NOT EXISTS case_ips (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER NOT NULL,
        ip         TEXT NOT NULL,
        score      INTEGER,
        risk_level TEXT,
        note       TEXT,
        added_at   TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS case_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER NOT NULL,
        note       TEXT NOT NULL,
        author     TEXT DEFAULT 'analyst',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
      CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
      CREATE INDEX IF NOT EXISTS idx_case_ips_case  ON case_ips(case_id);
      CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);
    `);
    console.log("✓ Cases tables ready");
  } catch (err) {
    console.error("Cases bootstrap error:", err.message);
  }
}

function parseTags(raw) {
  try { return JSON.parse(raw || "[]"); } catch { return []; }
}

function formatCase(row, ips = [], notes = []) {
  return { ...row, tags: parseTags(row.tags), ips, notes };
}

// ── Cases CRUD
function listCases({ status, severity, q, limit = 100, offset = 0 } = {}) {
  if (db.isAvailable()) {
    try {
      const conds = [], params = [];
      if (status)   { conds.push("status = ?");   params.push(status); }
      if (severity) { conds.push("severity = ?"); params.push(severity); }
      if (q)        { conds.push("(title LIKE ? OR description LIKE ?)"); params.push(`%${q}%`, `%${q}%`); }

      const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
      const {total} = await db.query(
        `SELECT COUNT(*) as c FROM cases ${where}`
      , ...params);
      const {rows} = await db.query(`
        SELECT c.*,
          (SELECT COUNT(*) FROM case_ips   ci WHERE ci.case_id = c.id) as ip_count,
          (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id = c.id) as note_count
        FROM cases c
        ${where}
        ORDER BY c.updated_at DESC
        LIMIT ? OFFSET ?
      `).all(...params, limit, offset);

      return { total, cases: rows.map(r => formatCase(r)) };
    } catch (err) {
      console.error("Cases list error:", err.message);
      return { total: 0, cases: [] };
    }
  }
  return { total: memCases.length, cases: memCases.slice(offset, offset + limit) };
}

function getCase(id) {
    id = Number(id);
  if (db.isAvailable()) {
    try {
      const {row}   = await db.query("SELECT * FROM cases WHERE id = ?", [id]);
      if (!row) return null;
      const ips   = await db.query("SELECT * FROM case_ips   WHERE case_id = ? ORDER BY added_at DESC", [id]);
      const notes = await db.query("SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC", [id]);
      return formatCase(row, ips.rows, notes.rows);
    } catch (err) { console.error("Get case error:", err.message); return null; }
  }
  return memCases.find(c => c.id === id) || null;
}

function createCase({ title, description = "", severity = "MEDIUM", status = "Open", assigned_to = "analyst", tags = [] }) {
  const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : []);
  if (db.isAvailable()) {
    try {
      const {result} = await db.query(
        "INSERT INTO cases (title, description, severity, status, assigned_to, tags) VALUES (?, ?, ?, ?, ?, ?)"
      , [title, description, severity, status, assigned_to, tagsJson]);const row = rows[0];
      return getCase(result.lastInsertRowid);
    } catch (err) { console.error("Create case error:", err.message); return null; }
  }
  const c = { id: nextId++, title, description, severity, status, assigned_to, tags, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ips: [], notes: [] };
  memCases.unshift(c);
  return c;
}

function updateCase(id, fields) {
  if (db.isAvailable()) {
    try {
      const allowed = ["title","description","severity","status","assigned_to","tags","closed_at"];
      const sets    = [], params = [];
      for (const [k, v] of Object.entries(fields)) {
        if (!allowed.includes(k)) continue;
        sets.push(`${k} = ?`);
        params.push(k === "tags" ? JSON.stringify(v) : v);
      }
      if (!sets.length) return getCase(id);
      sets.push("updated_at = datetime('now')");
      await db.query(`UPDATE cases SET ${sets.join(", ")} WHERE id = ?`, [...params, id]);
      return getCase(id);
    } catch (err) { console.error("Update case error:", err.message); return null; }
  }
  const c = memCases.find(c => c.id === id);
  if (c) Object.assign(c, fields, { updated_at: new Date().toISOString() });
  return c || null;
}

function deleteCase(id) {
  if (db.isAvailable()) {
    try { await db.query("DELETE FROM cases WHERE id = ?", [id]); return true; }
    catch (err) { console.error("Delete case error:", err.message); return false; }
  }
  memCases = memCases.filter(c => c.id !== id);
  return true;
}

// ── Case IPs 
function addCaseIP(caseId, { ip, score, risk_level, note = "" }) {
  caseId = Number(caseId);
  if (db.isAvailable()) {
    try {
      // Check if IP already attached
      const {existing} = await db.query("SELECT id FROM case_ips WHERE case_id = ? AND ip = ?", [caseId, ip]);
      if (existing.rows[0]) return { duplicate: true };
      await db.query(
        "INSERT INTO case_ips (case_id, ip, score, risk_level, note) VALUES (?, ?, ?, ?, ?)"
      , [caseId, ip, score || null, risk_level || null, note]);
      await db.query("UPDATE cases SET updated_at = datetime('now') WHERE id = ?", [caseId]);const row = rows[0];
      return { success: true };
    } catch (err) { console.error("Add case IP error:", err.message); return { error: err.message }; }
  }
  return { success: true };
}

function removeCaseIP(caseId, ipId) {
  caseId = Number(caseId);
  ipId = Number(ipId);
  if (db.isAvailable()) {
    try {
      await db.query("DELETE FROM case_ips WHERE id = ? AND case_id = ?", [ipId, caseId]);const row = rows[0];
      await db.query("UPDATE cases SET updated_at = datetime('now') WHERE id = ?", [caseId]);const row = rows[0];
      return true;
    } catch { return false; }
  }
  return true;
}

// ── Case Notes 
function addCaseNote(caseId, { note, author = "analyst" }) {
  caseId = Number(caseId);
  if (db.isAvailable()) {
    try {
      const {result} = await db.query(
        "INSERT INTO case_notes (case_id, note, author) VALUES (?, ?, ?)"
      , [caseId, note, author]);const row = rows[0];
      await db.query("UPDATE cases SET updated_at = datetime('now') WHERE id = ?", [caseId]);
      return await db.query("SELECT * FROM case_notes WHERE id = ?", [result.lastInsertRowid]).then(res => res.rows[0]);
    } catch (err) { console.error("Add note error:", err.message); return null; }
  }
  return { id: Date.now(), case_id: caseId, note, author, created_at: new Date().toISOString() };
}

function deleteCaseNote(caseId, noteId) {
  caseId = Number(caseId);
  noteId = Number(noteId);
  if (db.isAvailable()) {
    try { await db.query("DELETE FROM case_notes WHERE id = ? AND case_id = ?", [noteId, caseId]); return true; }
    catch { return false; }
  }
  return true;
}

// ── Stats 
function getCaseStats() {
  if (db.isAvailable()) {
    try {
      const {total}      = await db.query("SELECT COUNT(*) as c FROM cases").then(res => res.rows[0].c);
      const {byStatus}   = await db.query(
        "SELECT status, COUNT(*) as count FROM cases GROUP BY status"
      ).then(res => res.rows);
      const {bySeverity} = await db.query(
        "SELECT severity, COUNT(*) as count FROM cases GROUP BY severity"
      ).then(res => res.rows);
      return {
        total,
        byStatus:   Object.fromEntries(byStatus.map(r   => [r.status,   r.count])),
        bySeverity: Object.fromEntries(bySeverity.map(r => [r.severity, r.count]))
      };
    } catch { return { total: 0, byStatus: {}, bySeverity: {} }; }
  }
  return { total: memCases.length, byStatus: {}, bySeverity: {} };
}

try { bootstrap(); } catch (_) {}

module.exports = {
  listCases, getCase, createCase, updateCase, deleteCase,
  addCaseIP, removeCaseIP, addCaseNote, deleteCaseNote, getCaseStats
};