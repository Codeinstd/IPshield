const express = require("express");
const router  = express.Router();
const db      = require("../store/db");
const { requireAuth } = require("../middleware/auth.js");

router.get("/", requireAuth, async (req, res) => {
  try {
    const [distRes, totalRes] = await Promise.all([
      db.query(`
        SELECT risk_level, COUNT(*) AS count
        FROM audit_log
        GROUP BY risk_level
      `),
      db.query(`SELECT COUNT(*) AS total FROM audit_log`),
    ]);

    // Flat shape — matches d.CRITICAL, d.HIGH etc
    const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    distRes.rows.forEach(r => {
      if (r.risk_level in stats) {
        stats[r.risk_level] = parseInt(r.count);
      }
    });

    res.json({
      ...stats,                  // flat: CRITICAL, HIGH, MEDIUM, LOW
      total:            parseInt(totalRes.rows[0].total),
      riskDistribution: stats,   // nested: for app.js compatibility
    });

  } catch (err) {
  next(err);
}
});


module.exports = router;