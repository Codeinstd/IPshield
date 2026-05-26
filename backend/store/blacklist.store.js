const db = require("./db");

// ── Helpers 

function formatEntry(row) {
  if (!row) return null;
  return {
    ...row,
    tags:    Array.isArray(row.tags) ? row.tags : [],
    expired: row.expires_at ? new Date(row.expires_at) < new Date() : false,
  };
}

// ── CRUD 

async function listBlacklist({ severity, status, q, limit = 200, offset = 0 } = {}) {
  try {
    const conds  = [];
    const params = [];
    let   i      = 1;

    if (severity) {
      conds.push(`severity = $${i++}`);
      params.push(severity);
    }
    if (q) {
      conds.push(`(ip ILIKE $${i} OR reason ILIKE $${i+1} OR category ILIKE $${i+2})`);
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
      i += 3;
    }
    if (status === "active") {
      conds.push(`(expires_at IS NULL OR expires_at > NOW())`);
    }
    if (status === "expired") {
      conds.push(`(expires_at IS NOT NULL AND expires_at <= NOW())`);
    }

    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";

    const countResult = await db.query(
      `SELECT COUNT(*) AS total FROM blacklist ${where}`,
      params
    );
    const total = parseInt(countResult.rows[0].total, 10);

    const rowsResult = await db.query(
      `SELECT * FROM blacklist ${where} ORDER BY added_at DESC LIMIT $${i} OFFSET $${i+1}`,
      [...params, limit, offset]
    );

    return { total, entries: rowsResult.rows.map(formatEntry) };
  } catch (err) {
    console.error("Blacklist list error:", err.message);
    return { total: 0, entries: [] };
  }
}

async function addToBlacklist({
  ip,
  severity  = "HIGH",
  category  = "",
  reason    = "",
  added_by  = "analyst",
  expires_at = null,
  tags      = [],
}) {
  try {
    // Duplicate check — is this IP already actively blacklisted?
    const dupCheck = await db.query(
      `SELECT id FROM blacklist
       WHERE ip = $1 AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [ip]
    );
    if (dupCheck.rows.length) {
      return { duplicate: true, id: dupCheck.rows[0].id };
    }

    const tagsArray = Array.isArray(tags) ? tags : [];

    const result = await db.query(
      `INSERT INTO blacklist (ip, severity, category, reason, added_by, expires_at, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [ip, severity, category, reason, added_by, expires_at || null, tagsArray]
    );

    return formatEntry(result.rows[0]);
  } catch (err) {
    console.error("Blacklist insert error:", err.message);
    return null;
  }
}

async function updateBlacklist(id, { severity, category, reason, expires_at, tags }) {
  try {
    const fields = [];
    const params = [];
    let   i      = 1;

    if (severity   !== undefined) { fields.push(`severity = $${i++}`);   params.push(severity); }
    if (category   !== undefined) { fields.push(`category = $${i++}`);   params.push(category); }
    if (reason     !== undefined) { fields.push(`reason = $${i++}`);     params.push(reason); }
    if (expires_at !== undefined) { fields.push(`expires_at = $${i++}`); params.push(expires_at || null); }
    if (tags       !== undefined) { fields.push(`tags = $${i++}`);       params.push(Array.isArray(tags) ? tags : []); }

    if (!fields.length) return null;

    params.push(id);
    const result = await db.query(
      `UPDATE blacklist SET ${fields.join(", ")} WHERE id = $${i} RETURNING *`,
      params
    );

    return formatEntry(result.rows[0]);
  } catch (err) {
    console.error("Blacklist update error:", err.message);
    return null;
  }
}

async function deleteFromBlacklist(id) {
  try {
    await db.query("DELETE FROM blacklist WHERE id = $1", [id]);
    return true;
  } catch (err) {
    console.error("Blacklist delete error:", err.message);
    return false;
  }
}

async function bulkDelete(ids) {
  if (!ids?.length) return 0;
  try {
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
    const result = await db.query(
      `DELETE FROM blacklist WHERE id IN (${placeholders})`,
      ids
    );
    return result.rowCount;
  } catch (err) {
    console.error("Blacklist bulk delete error:", err.message);
    return 0;
  }
}

async function isBlacklisted(ip) {
  try {
    const result = await db.query(
      `SELECT id FROM blacklist
       WHERE ip = $1 AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [ip]
    );
    return result.rows.length > 0;
  } catch {
    return false;
  }
}

async function getAllActiveIPs() {
  try {
    const result = await db.query(
      `SELECT ip, severity FROM blacklist
       WHERE expires_at IS NULL OR expires_at > NOW()
       ORDER BY severity DESC`
    );
    return result.rows;
  } catch {
    return [];
  }
}

async function getStats() {
  try {
    const [totalRes, activeRes, expiredRes, sevRes] = await Promise.all([
      db.query("SELECT COUNT(*) AS c FROM blacklist"),
      db.query("SELECT COUNT(*) AS c FROM blacklist WHERE expires_at IS NULL OR expires_at > NOW()"),
      db.query("SELECT COUNT(*) AS c FROM blacklist WHERE expires_at IS NOT NULL AND expires_at <= NOW()"),
      db.query("SELECT severity, COUNT(*) AS count FROM blacklist GROUP BY severity"),
    ]);

    return {
      total:      parseInt(totalRes.rows[0].c, 10),
      active:     parseInt(activeRes.rows[0].c, 10),
      expired:    parseInt(expiredRes.rows[0].c, 10),
      bySeverity: Object.fromEntries(
        sevRes.rows.map(r => [r.severity, parseInt(r.count, 10)])
      ),
    };
  } catch {
    return { total: 0, active: 0, expired: 0, bySeverity: {} };
  }
}

module.exports = {
  listBlacklist,
  addToBlacklist,
  updateBlacklist,
  deleteFromBlacklist,
  bulkDelete,
  isBlacklisted,
  getAllActiveIPs,
  getStats,
};