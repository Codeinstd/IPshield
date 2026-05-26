const db               = require("../store/db");
const cache            = require("../store/cache");
const { getFeedStats } = require("../services/threatfeeds.service");

exports.getStats = async (req, res) => {
  try {
    const [distRes, totalRes, topRes] = await Promise.all([
      db.query(`SELECT risk_level, COUNT(*) AS count FROM audit_log GROUP BY risk_level`),
      db.query(`SELECT COUNT(*) AS total FROM audit_log`),
      db.query(`SELECT ip, risk_level, score, scored_at FROM audit_log WHERE risk_level IN ('CRITICAL','HIGH') ORDER BY scored_at DESC LIMIT 5`),
    ]);

    const riskDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    distRes.rows.forEach((r) => {
      if (r.risk_level in riskDistribution) {
        riskDistribution[r.risk_level] = parseInt(r.count, 10);
      }
    });

    res.json({
      riskDistribution,
      totalScored: parseInt(totalRes.rows[0].total, 10),
      topThreats:  topRes.rows,
      cacheSize:   cache.size(),
      dbAvailable: true,
      uptime:      Math.floor(process.uptime()),
      memoryMB:    Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      threatFeeds: getFeedStats(),
    });
  } catch (err) {
    console.error("Stats error:", err.message);
    res.status(500).json({ error: "Failed to load stats" });
  }
};