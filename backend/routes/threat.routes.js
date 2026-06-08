
const express = require("express");
const router  = express.Router();
const { requireAuth, requireRole } = require("../middleware/auth.js");
const db = require("../store/db");

// GET /threat/dashboard 
router.get("/dashboard", requireAuth, requireRole("readonly"), async (req, res) => {
  try {
    const [
      riskSummaryRes,
      recentCriticalRes,
      blacklistStatsRes,
      caseStatsRes,
      topAsnsRes,
      topCountriesRes,
      hourlyRes,
      watchlistRes,
    ] = await Promise.all([

      // Risk distribution last 24h
      db.query(`
        SELECT risk_level, COUNT(*) AS count
        FROM audit_log
        WHERE scored_at > NOW() - INTERVAL '24 hours'
        GROUP BY risk_level
      `),

      // Most recent CRITICAL/HIGH IPs
      db.query(`
        SELECT ip, score, risk_level, country, isp, scored_at
        FROM audit_log
        WHERE risk_level IN ('CRITICAL','HIGH')
          AND scored_at > NOW() - INTERVAL '24 hours'
        ORDER BY scored_at DESC
        LIMIT 20
      `),

      // Blacklist stats
      db.query(`
        SELECT
          COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > NOW()) AS active,
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE added_at > NOW() - INTERVAL '24 hours') AS added_today,
          COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count
        FROM blacklist
      `),

      // Open case stats
      db.query(`
        SELECT
          COUNT(*) FILTER (WHERE status NOT IN ('Closed','Resolved')) AS open_count,
          COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status NOT IN ('Closed','Resolved')) AS critical_open,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS opened_today
        FROM cases
      `),

      // Top threat ASNs (last 24h)
      db.query(`
        SELECT asn, COUNT(*) AS count,
               COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') AS critical_count
        FROM audit_log
        WHERE asn IS NOT NULL
          AND risk_level IN ('CRITICAL','HIGH')
          AND scored_at > NOW() - INTERVAL '24 hours'
        GROUP BY asn
        ORDER BY count DESC
        LIMIT 10
      `),

      // Top threat countries (last 24h)
      db.query(`
        SELECT country, COUNT(*) AS count
        FROM audit_log
        WHERE country IS NOT NULL
          AND risk_level IN ('CRITICAL','HIGH')
          AND scored_at > NOW() - INTERVAL '24 hours'
        GROUP BY country
        ORDER BY count DESC
        LIMIT 10
      `),

      // Hourly CRITICAL/HIGH counts (last 24h)
      db.query(`
        SELECT
          date_trunc('hour', scored_at) AS hour,
          COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') AS critical,
          COUNT(*) FILTER (WHERE risk_level = 'HIGH')     AS high,
          COUNT(*) AS total
        FROM audit_log
        WHERE scored_at > NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour ASC
      `),

      // Watchlist alerts (IPs above threshold)
      db.query(`
        SELECT ip, label, last_score, last_risk, threshold, last_checked
        FROM watchlist
        WHERE last_score >= threshold
        ORDER BY last_score DESC
        LIMIT 10
      `),
    ]);

    // Build risk distribution map
    const riskDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    riskSummaryRes.rows.forEach(r => {
      if (r.risk_level in riskDist) riskDist[r.risk_level] = parseInt(r.count, 10);
    });

    const totalScored = Object.values(riskDist).reduce((a, b) => a + b, 0);
    const threatScore = totalScored > 0
      ? Math.round(((riskDist.CRITICAL * 4 + riskDist.HIGH * 2 + riskDist.MEDIUM) / (totalScored * 4)) * 100)
      : 0;

    const bl    = blacklistStatsRes.rows[0];
    const cases = caseStatsRes.rows[0];

    res.json({
      generatedAt: new Date().toISOString(),

      // Overall threat level for the last 24h
      threatScore,
      threatLevel: threatScore > 75 ? "CRITICAL"
                 : threatScore > 50 ? "HIGH"
                 : threatScore > 25 ? "MEDIUM"
                 : "LOW",

      // Risk breakdown
      riskDistribution: riskDist,
      totalScored24h:   totalScored,

      // Recent threats
      recentThreats: recentCriticalRes.rows,

      // Blacklist
      blacklist: {
        active:       parseInt(bl.active,        10),
        total:        parseInt(bl.total,         10),
        addedToday:   parseInt(bl.added_today,   10),
        criticalCount:parseInt(bl.critical_count,10),
      },

      // Cases
      cases: {
        openCount:    parseInt(cases.open_count,    10),
        criticalOpen: parseInt(cases.critical_open, 10),
        openedToday:  parseInt(cases.opened_today,  10),
      },

      // Top threat sources
      topAsns:      topAsnsRes.rows,
      topCountries: topCountriesRes.rows,

      // Hourly trend
      hourlyTrend: hourlyRes.rows.map(r => ({
        hour:     r.hour,
        critical: parseInt(r.critical, 10),
        high:     parseInt(r.high,     10),
        total:    parseInt(r.total,    10),
      })),

      // Watchlist alerts
      watchlistAlerts: watchlistRes.rows,
    });
  } catch (err) {
  next(err);
}
});

// GET /threat/timeline 
router.get("/timeline", requireAuth, requireRole("readonly"), async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || "24"), 168); // max 7 days

  try {
    const result = await db.query(`
      SELECT
        date_trunc('hour', scored_at) AS hour,
        COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') AS critical,
        COUNT(*) FILTER (WHERE risk_level = 'HIGH')     AS high,
        COUNT(*) FILTER (WHERE risk_level = 'MEDIUM')   AS medium,
        COUNT(*) FILTER (WHERE risk_level = 'LOW')      AS low,
        COUNT(*) AS total
      FROM audit_log
      WHERE scored_at > NOW() - ($1 || ' hours')::INTERVAL
      GROUP BY hour
      ORDER BY hour ASC
    `, [hours]);

    res.json({
      hours,
      data: result.rows.map(r => ({
        hour:     r.hour,
        critical: parseInt(r.critical, 10),
        high:     parseInt(r.high,     10),
        medium:   parseInt(r.medium,   10),
        low:      parseInt(r.low,      10),
        total:    parseInt(r.total,    10),
      })),
    });
  } catch (err) {
  next(err);
}
});

module.exports = router;