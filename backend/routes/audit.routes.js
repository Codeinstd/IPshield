const express         = require("express");
const router          = express.Router();
const { query, validationResult } = require("express-validator");
const { getAuditLog } = require("../store/memory.store");
const db              = require("../store/db");

// ── GET /api/audit ────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;

  const log = db.isAvailable()
    ? db.getHistory(limit, offset)
    : getAuditLog().slice(offset, offset + limit);

  const total = db.isAvailable() ? db.getTotalScored() : getAuditLog().length;

  res.json({
    total,
    limit,
    offset,
    hasMore: offset + limit < total,
    entries: log
  });
});

// ── GET /api/audit/search ─────────────────────────────────────────────────────
router.get("/search",
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
    query("sort").optional().isIn(["score_desc","score_asc","date_desc","date_asc"])
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

    const {
      q, risk, action, country,
      from, to, minScore, maxScore,
      proxy, tor, datacenter,
      limit  = 50,
      offset = 0,
      sort   = "date_desc"
    } = req.query;

    const filters = {
      q:           q           || null,
      risk:        risk        || null,
      action:      action      || null,
      country:     country     || null,
      from:        from        ? new Date(from).getTime()   : null,
      to:          to          ? new Date(to).getTime()     : null,
      minScore:    minScore    != null ? parseInt(minScore) : null,
      maxScore:    maxScore    != null ? parseInt(maxScore) : null,
      proxy:       proxy       != null ? proxy === "true"   : null,
      tor:         tor         != null ? tor === "true"     : null,
      datacenter:  datacenter  != null ? datacenter === "true" : null,
    };

    let results;

    if (db.isAvailable()) {
      results = db.searchHistory(filters, parseInt(limit), parseInt(offset), sort);
    } else {
      // In-memory fallback filter
      results = filterMemory(getAuditLog(), filters, parseInt(limit), parseInt(offset), sort);
    }

    res.json({
      total:   results.total,
      limit:   parseInt(limit),
      offset:  parseInt(offset),
      hasMore: parseInt(offset) + parseInt(limit) < results.total,
      filters,
      entries: results.entries
    });
  }
);

// ── GET /api/audit/threats ────────────────────────────────────────────────────
router.get("/threats", (req, res) => {
  const limit   = Math.min(parseInt(req.query.limit) || 20, 100);
  const threats = db.isAvailable() ? db.getTopThreats(limit) : [];
  res.json({ total: threats.length, threats });
});

// ── GET /api/audit/breakdown ──────────────────────────────────────────────────
router.get("/breakdown", (req, res) => {
  if (!db.isAvailable()) {
    const log  = getAuditLog();
    const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    log.forEach(e => { if (e.riskLevel in dist) dist[e.riskLevel]++; });
    return res.json({ riskDistribution: dist, total: log.length });
  }
  res.json({
    riskDistribution: db.getRiskDistribution(),
    total:            db.getTotalScored(),
    topCountries:     db.getTopCountries(10),
    topISPs:          db.getTopISPs(10)
  });
});

// ── In-memory filter fallback ─────────────────────────────────────────────────
function filterMemory(log, filters, limit, offset, sort) {
  let results = log.filter(e => {
    if (filters.q) {
      const q = filters.q.toLowerCase();
      if (!e.ip?.includes(q) && !e.geo?.country?.toLowerCase().includes(q) &&
          !e.network?.isp?.toLowerCase().includes(q)) return false;
    }
    if (filters.risk      && e.riskLevel !== filters.risk)        return false;
    if (filters.action    && e.action !== filters.action)          return false;
    if (filters.country   && !e.geo?.country?.toLowerCase().includes(filters.country.toLowerCase())) return false;
    if (filters.minScore  != null && (e.score ?? 0) < filters.minScore) return false;
    if (filters.maxScore  != null && (e.score ?? 0) > filters.maxScore) return false;
    if (filters.proxy     != null && !!e.intelligence?.isProxy !== filters.proxy) return false;
    if (filters.tor       != null && !!e.intelligence?.isTor   !== filters.tor)   return false;
    if (filters.datacenter!= null && !!e.intelligence?.isDatacenter !== filters.datacenter) return false;
    if (filters.from) {
      const ts = e.meta?.scoredAt ? new Date(e.meta.scoredAt).getTime() : 0;
      if (ts < filters.from) return false;
    }
    if (filters.to) {
      const ts = e.meta?.scoredAt ? new Date(e.meta.scoredAt).getTime() : 0;
      if (ts > filters.to) return false;
    }
    return true;
  });

  // Sort
  results.sort((a, b) => {
    switch (sort) {
      case "score_desc": return (b.score ?? 0) - (a.score ?? 0);
      case "score_asc":  return (a.score ?? 0) - (b.score ?? 0);
      case "date_asc":
        return new Date(a.meta?.scoredAt || 0) - new Date(b.meta?.scoredAt || 0);
      default: // date_desc
        return new Date(b.meta?.scoredAt || 0) - new Date(a.meta?.scoredAt || 0);
    }
  });

  const total = results.length;
  return { total, entries: results.slice(offset, offset + limit) };
}

module.exports = router;