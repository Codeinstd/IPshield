/**
 * audit.routes.js
 * Place in: backend/routes/audit.routes.js
 */

const express        = require("express");
const router         = express.Router();
const { getAuditLog } = require("../store/memory.store");
const db             = require("../store/db");

// GET /api/audit?limit=50&source=db
router.get("/", (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const source = req.query.source;

  // Prefer DB history if available and requested, else memory
  const log = (db.isAvailable() && source !== "memory")
    ? db.getHistory(limit)
    : getAuditLog().slice(0, limit);

  res.json({ total: log.length, entries: log });
});

// GET /api/audit/threats — top critical/high IPs
router.get("/threats", (req, res) => {
  const threats = db.isAvailable() ? db.getTopThreats(20) : [];
  res.json({ total: threats.length, threats });
});

module.exports = router;