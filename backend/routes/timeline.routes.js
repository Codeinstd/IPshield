
const express = require("express");
const router  = express.Router();
const { param, query, validationResult } = require("express-validator");
const db      = require("../store/db");
const { getAuditLog } = require("../store/memory.store");

router.get("/:ip",
  [
    param("ip").trim().notEmpty().custom(ip => {
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
        throw new Error("Invalid IP address");
      return true;
    }),
    query("limit").optional().isInt({ min: 5, max: 200 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid request" });

    const ip    = req.params.ip;
    const limit = parseInt(req.query.limit) || 50;

    let history = [];

    if (db.isAvailable()) {
      try {
        history = db.getDb()
          .prepare(`
            SELECT score, risk_level, action, scored_at
            FROM scores
            WHERE ip = ?
            ORDER BY scored_at ASC
            LIMIT ?
          `)
          .all(ip, limit);
      } catch (err) {
        console.error("Timeline DB error:", err.message);
      }
    } else {
      // Fallback — filter in-memory audit log
      history = getAuditLog()
        .filter(e => e.ip === ip)
        .map(e => ({
          score:      e.score,
          risk_level: e.riskLevel,
          action:     e.action,
          scored_at:  e.meta?.scoredAt ? new Date(e.meta.scoredAt).getTime() : Date.now()
        }))
        .reverse()
        .slice(0, limit);
    }

    if (!history.length) {
      return res.json({ ip, total: 0, history: [], stats: null });
    }

    // Compute stats
    const scores = history.map(h => h.score);
    const stats  = {
      min:     Math.min(...scores),
      max:     Math.max(...scores),
      avg:     Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
      latest:  scores[scores.length - 1],
      first:   scores[0],
      trend:   scores[scores.length - 1] > scores[0] ? "increasing"
             : scores[scores.length - 1] < scores[0] ? "decreasing"
             : "stable",
      change:  scores[scores.length - 1] - scores[0]
    };

    res.json({ ip, total: history.length, history, stats });
  }
);

module.exports = router;