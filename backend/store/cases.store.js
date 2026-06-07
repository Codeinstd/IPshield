
const db = require("./db");

// Helpers 
function formatCase(row, ips = [], notes = []) {
  if (!row) return null;
  return {
    ...row,
    tags: Array.isArray(row.tags) ? row.tags : [],
    ips,
    notes,
  };
}

// Cases CRUD 
async function listCases({ status, severity, q, limit = 100, offset = 0 } = {}) {
  try {
    const conds  = [];
    const params = [];
    let   i      = 1;

    if (status)   { conds.push(`c.status = $${i++}`);   params.push(status); }
    if (severity) { conds.push(`c.severity = $${i++}`); params.push(severity); }
    if (q) {
      conds.push(`(c.title ILIKE $${i} OR c.description ILIKE $${i+1})`);
      params.push(`%${q}%`, `%${q}%`);
      i += 2;
    }

    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";

    const countRes = await db.query(
      `SELECT COUNT(*) AS total FROM cases c ${where}`,
      params
    );
    const total = parseInt(countRes.rows[0].total, 10);

    const rowsRes = await db.query(
      `SELECT c.*,
         (SELECT COUNT(*) FROM case_ips   ci WHERE ci.case_id = c.id) AS ip_count,
         (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id = c.id) AS note_count
       FROM cases c
       ${where}
       ORDER BY c.updated_at DESC
       LIMIT $${i} OFFSET $${i+1}`,
      [...params, limit, offset]
    );

    return { total, cases: rowsRes.rows.map(r => formatCase(r)) };
  } catch (err) {
    console.error("Cases list error:", err.message);
    return { total: 0, cases: [] };
  }
}

async function getCase(id) {
  try {
    const caseRes = await db.query(
      "SELECT * FROM cases WHERE id = $1",
      [Number(id)]
    );
    if (!caseRes.rows.length) return null;

    const [ipsRes, notesRes] = await Promise.all([
      db.query("SELECT * FROM case_ips   WHERE case_id = $1 ORDER BY added_at DESC",  [id]),
      db.query("SELECT * FROM case_notes WHERE case_id = $1 ORDER BY created_at ASC", [id]),
    ]);

    return formatCase(caseRes.rows[0], ipsRes.rows, notesRes.rows);
  } catch (err) {
    console.error("Get case error:", err.message);
    return null;
  }
}

async function createCase({
  title,
  description = "",
  severity    = "MEDIUM",
  status      = "Open",
  assigned_to = "analyst",
  tags        = [],
}) {
  try {
    const tagsArray = Array.isArray(tags) ? tags : [];
    const result = await db.query(
      `INSERT INTO cases (title, description, severity, status, assigned_to, tags)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, description, severity, status, assigned_to, tagsArray]
    );
    return formatCase(result.rows[0]);
  } catch (err) {
    console.error("Create case error:", err.message);
    return null;
  }
}

async function updateCase(id, fields) {
  try {
    const allowed = ["title", "description", "severity", "status", "assigned_to", "tags", "closed_at"];
    const sets    = [];
    const params  = [];
    let   i       = 1;

    for (const [k, v] of Object.entries(fields)) {
      if (!allowed.includes(k)) continue;
      sets.push(`${k} = $${i++}`);
      params.push(v);
    }

    if (!sets.length) return getCase(id);

    // updated_at is handled by the DB trigger — no need to set it manually
    params.push(Number(id));
    await db.query(
      `UPDATE cases SET ${sets.join(", ")} WHERE id = $${i}`,
      params
    );

    return getCase(id);
  } catch (err) {
    console.error("Update case error:", err.message);
    return null;
  }
}

async function deleteCase(id) {
  try {
    await db.query("DELETE FROM cases WHERE id = $1", [Number(id)]);
    return true;
  } catch (err) {
    console.error("Delete case error:", err.message);
    return false;
  }
}

// Case IPs 
async function addCaseIP(caseId, { ip, score, risk_level, note = "" }) {
  try {
    const dupCheck = await db.query(
      "SELECT id FROM case_ips WHERE case_id = $1 AND ip = $2",
      [Number(caseId), ip]
    );
    if (dupCheck.rows.length) return { duplicate: true };

    await db.query(
      `INSERT INTO case_ips (case_id, ip, score, risk_level, note)
       VALUES ($1, $2, $3, $4, $5)`,
      [Number(caseId), ip, score || null, risk_level || null, note]
    );

    // Touch updated_at on the parent case
    await db.query(
      "UPDATE cases SET updated_at = NOW() WHERE id = $1",
      [Number(caseId)]
    );

    return { success: true };
  } catch (err) {
    console.error("Add case IP error:", err.message);
    return { error: err.message };
  }
}

async function removeCaseIP(caseId, ipId) {
  try {
    await db.query(
      "DELETE FROM case_ips WHERE id = $1 AND case_id = $2",
      [Number(ipId), Number(caseId)]
    );
    await db.query(
      "UPDATE cases SET updated_at = NOW() WHERE id = $1",
      [Number(caseId)]
    );
    return true;
  } catch {
    return false;
  }
}

// Case Notes 
async function addCaseNote(caseId, { note, author = "analyst" }) {
  try {
    const result = await db.query(
      `INSERT INTO case_notes (case_id, note, author)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [Number(caseId), note, author]
    );
    await db.query(
      "UPDATE cases SET updated_at = NOW() WHERE id = $1",
      [Number(caseId)]
    );
    return result.rows[0];
  } catch (err) {
    console.error("Add note error:", err.message);
    return null;
  }
}

async function deleteCaseNote(caseId, noteId) {
  try {
    await db.query(
      "DELETE FROM case_notes WHERE id = $1 AND case_id = $2",
      [Number(noteId), Number(caseId)]
    );
    return true;
  } catch {
    return false;
  }
}

// Stats 
async function getCaseStats() {
  try {
    const [totalRes, statusRes, severityRes] = await Promise.all([
      db.query("SELECT COUNT(*) AS c FROM cases"),
      db.query("SELECT status,   COUNT(*) AS count FROM cases GROUP BY status"),
      db.query("SELECT severity, COUNT(*) AS count FROM cases GROUP BY severity"),
    ]);

    return {
      total:      parseInt(totalRes.rows[0].c, 10),
      byStatus:   Object.fromEntries(statusRes.rows.map(r   => [r.status,   parseInt(r.count, 10)])),
      bySeverity: Object.fromEntries(severityRes.rows.map(r => [r.severity, parseInt(r.count, 10)])),
    };
  } catch {
    return { total: 0, byStatus: {}, bySeverity: {} };
  }
}

module.exports = {
  listCases, getCase, createCase, updateCase, deleteCase,
  addCaseIP, removeCaseIP, addCaseNote, deleteCaseNote, getCaseStats,
};