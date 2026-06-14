const express         = require("express");
const router          = express.Router();
const { query, validationResult } = require("express-validator");
const { getAuditLog } = require("../store/memory.store");
const db              = require("../store/db");
const { requireAuth, requireRole } = require("../middleware/auth.js");

// GET /api/audit
router.get("/", requireAuth, requireRole('readonly'), async (req, res) => { 
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;

  try {
    const [totalRes, rowsRes] = await Promise.all([
      db.query("SELECT COUNT(*) AS total FROM audit_log"),
      db.query(
        `SELECT * FROM audit_log ORDER BY scored_at DESC LIMIT $1 OFFSET $2`,
        [limit, offset]
      ),
    ]);
    const total = parseInt(totalRes.rows[0].total, 10);
    res.json({ total, limit, offset, hasMore: offset + limit < total, entries: rowsRes.rows });
  } catch (err) {
    console.error("Audit list error:", err.message);
    // Fallback to memory
    const log = getAuditLog().slice(offset, offset + limit);
    res.json({ total: getAuditLog().length, limit, offset, hasMore: false, entries: log });
  }
});

// GET /api/audit/search
router.get("/search", requireAuth, requireRole('readonly'),
  [
    query("q").optional().trim().isLength({ max: 100 }),
    query("risk").optional().isIn(["CRITICAL","HIGH","MEDIUM","LOW"]),
    query("action").optional().isIn(["BLOCK","CHALLENGE","MONITOR","ALLOW"]),
    query("country").optional().trim().isLength({ max: 100 }),
    query("from").optional().isISO8601(),
    query("to").optional().isISO8601(),
    query("minScore").optional().isInt({ min: 0, max: 100 }),
    query("maxScore").optional().isInt({ min: 0, max: 100 }),
    query("proxy").optional().isBoolean(),
    query("tor").optional().isBoolean(),
    query("datacenter").optional().isBoolean(),
    query("limit").optional().isInt({ min: 1, max: 200 }),
    query("offset").optional().isInt({ min: 0 }),
    query("sort").optional().isIn(["score_desc","score_asc","date_desc","date_asc"]),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

    const {
      q, risk, action, country,
      from, to, minScore, maxScore,
      proxy, tor, datacenter,
      limit  = 50,
      offset = 0,
      sort   = "date_desc",
    } = req.query;

    try {
      const conds  = [];
      const params = [];
      let   i      = 1;

      if (q) {
        conds.push(`(ip ILIKE $${i} OR country ILIKE $${i+1} OR isp ILIKE $${i+2})`);
        params.push(`%${q}%`, `%${q}%`, `%${q}%`);
        i += 3;
      }
      if (risk)       { conds.push(`risk_level = $${i++}`);  params.push(risk); }
      if (action)     { conds.push(`action = $${i++}`);       params.push(action); }
      if (country)    { conds.push(`country ILIKE $${i++}`);  params.push(`%${country}%`); }
      if (minScore != null && minScore !== "") { conds.push(`score >= $${i++}`); params.push(parseInt(minScore)); }
      if (maxScore != null && maxScore !== "") { conds.push(`score <= $${i++}`); params.push(parseInt(maxScore)); }
      if (proxy != null)      { conds.push(`is_proxy = $${i++}`);      params.push(proxy === "true"); }
      if (tor != null)        { conds.push(`is_tor = $${i++}`);        params.push(tor === "true"); }
      if (datacenter != null) { conds.push(`is_dc = $${i++}`); params.push(datacenter === "true"); }
      if (from) { conds.push(`scored_at >= $${i++}`); params.push(new Date(from)); }
      if (to)   { conds.push(`scored_at <= $${i++}`); params.push(new Date(to)); }

      const where   = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
      const orderBy = {
        score_desc: "score DESC",
        score_asc:  "score ASC",
        date_asc:   "scored_at ASC",
        date_desc:  "scored_at DESC",
      }[sort] || "scored_at DESC";

      const countParams = [...params];
      const dataParams  = [...params, parseInt(limit), parseInt(offset)];

      const [totalRes, rowsRes] = await Promise.all([
        db.query(`SELECT COUNT(*) AS total FROM audit_log ${where}`, countParams),
        db.query(
          `SELECT * FROM audit_log ${where} ORDER BY ${orderBy} LIMIT $${i} OFFSET $${i+1}`,
          dataParams
        ),
      ]);

      const total = parseInt(totalRes.rows[0].total, 10);
      res.json({
        total,
        limit:   parseInt(limit),
        offset:  parseInt(offset),
        hasMore: parseInt(offset) + parseInt(limit) < total,
        entries: rowsRes.rows,
      });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/audit/threats
router.get("/threats", requireAuth, requireRole('readonly'), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  try {
    const result = await db.query(
      `SELECT ip, risk_level, score, scored_at
       FROM audit_log
       WHERE risk_level IN ('CRITICAL','HIGH')
       ORDER BY scored_at DESC
       LIMIT $1`,
      [limit]
    );
    res.json({ total: result.rows.length, threats: result.rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/audit/breakdown
router.get("/breakdown", requireAuth, requireRole('readonly'), async (req, res) => {
  try {
    const [distRes, totalRes, countriesRes, ispsRes] = await Promise.all([
      db.query("SELECT risk_level, COUNT(*) AS count FROM audit_log GROUP BY risk_level"),
      db.query("SELECT COUNT(*) AS total FROM audit_log"),
      db.query("SELECT country, COUNT(*) AS count FROM audit_log WHERE country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 10"),
      db.query("SELECT isp, COUNT(*) AS count FROM audit_log WHERE isp IS NOT NULL GROUP BY isp ORDER BY count DESC LIMIT 10"),
    ]);

    const riskDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    distRes.rows.forEach(r => {
      if (r.risk_level in riskDistribution) riskDistribution[r.risk_level] = parseInt(r.count, 10);
    });

    res.json({
      riskDistribution,
      total:        parseInt(totalRes.rows[0].total, 10),
      topCountries: countriesRes.rows,
      topISPs:      ispsRes.rows,
    });
  } catch (err) {
      next(err);
    }
});

// GET /api/v2/audit/verify
router.get("/verify", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const crypto = require("crypto");
    const rows   = await db.query(
      `SELECT id, ip, score, risk_level, scored_at, prev_hash, row_hash
       FROM audit_log ORDER BY id ASC`
    );

    let prevHash = "GENESIS";
    let tampered = 0;
    const broken = [];

    for (const row of rows.rows) {
      // Skip unverifiable legacy rows (no hash yet)
      if (!row.row_hash || !row.prev_hash) continue;

      const content = JSON.stringify({
        ip:         row.ip,
        score:      row.score,
        risk_level: row.risk_level,
        scored_at:  new Date(row.scored_at).toISOString(),
        prev_hash:  row.prev_hash,
      });

      const expected = crypto
        .createHash("sha256")
        .update(content)
        .digest("hex");

      if (expected !== row.row_hash || row.prev_hash !== prevHash) {
        tampered++;
        broken.push({ id: row.id, ip: row.ip });
      }

      prevHash = row.row_hash;
    }

    res.json({
      total:    rows.rows.length,
      tampered,
      intact:   rows.rows.length - tampered,
      broken,
      verified: tampered === 0,
    });

  } catch (err) {
    console.error("[audit/verify]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;