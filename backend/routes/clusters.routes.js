
const express = require("express");
const router  = express.Router();
const { param, validationResult }  = require("express-validator");
const { requireAuth, requireRole } = require("../middleware/auth.js");
const { getActiveClusters, resolveCluster } = require("../services/cluster.service");
const db = require("../store/db");

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// ── GET /threat/clusters 

router.get("/", requireAuth, requireRole("readonly"), async (req, res) => {
  try {
    const limit    = Math.min(parseInt(req.query.limit || "50"), 200);
    const clusters = await getActiveClusters(limit);
    res.json({ total: clusters.length, clusters });
  } catch (err) {
    res.status(500).json({ error: "Failed to load clusters" });
  }
});

// ── GET /threat/clusters/:id/ips

router.get("/:id/ips",
  requireAuth, requireRole("readonly"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      // Get the cluster
      const clusterRes = await db.query(
        `SELECT * FROM threat_clusters WHERE id = $1`,
        [parseInt(req.params.id)]
      );
      if (!clusterRes.rows.length) {
        return res.status(404).json({ error: "Cluster not found" });
      }

      const cluster = clusterRes.rows[0];
      const details = typeof cluster.details === "string"
        ? JSON.parse(cluster.details)
        : cluster.details;

      const windowMins = details?.windowMins || 30;
      const windowStart = new Date(
        new Date(cluster.first_seen).getTime() - windowMins * 60 * 1000
      );

      let ipsRes;

      if (cluster.cluster_type === "subnet") {
        const subnet = details?.subnet;
        const prefix = subnet?.replace("/24","").replace(/\.\d+$/, ".");
        ipsRes = await db.query(
          `SELECT DISTINCT ip, score, risk_level, country, isp, asn, scored_at
           FROM audit_log
           WHERE ip LIKE $1
             AND scored_at >= $2
           ORDER BY score DESC LIMIT 100`,
          [`${prefix}%`, windowStart]
        );
      } else if (cluster.cluster_type === "asn") {
        ipsRes = await db.query(
          `SELECT DISTINCT ip, score, risk_level, country, isp, asn, scored_at
           FROM audit_log
           WHERE asn = $1
             AND scored_at >= $2
           ORDER BY score DESC LIMIT 100`,
          [details?.asn, windowStart]
        );
      } else {
        ipsRes = await db.query(
          `SELECT DISTINCT ip, score, risk_level, country, isp, asn, scored_at
           FROM audit_log
           WHERE country = $1
             AND risk_level IN ('CRITICAL','HIGH')
             AND scored_at >= $2
           ORDER BY score DESC LIMIT 100`,
          [details?.country, windowStart]
        );
      }

      res.json({
        cluster,
        total: ipsRes.rows.length,
        ips:   ipsRes.rows,
      });
    } catch (err) {
      console.error("[clusters] IPs error:", err.message);
      res.status(500).json({ error: "Failed to load cluster IPs" });
    }
  }
);

// ── POST /threat/clusters/:id/resolve 

router.post("/:id/resolve",
  requireAuth, requireRole("analyst"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const ok = await resolveCluster(parseInt(req.params.id));
      if (!ok) return res.status(404).json({ error: "Cluster not found" });
      res.json({ message: "Cluster resolved" });
    } catch (err) {
      res.status(500).json({ error: "Failed to resolve cluster" });
    }
  }
);

module.exports = router;