
const db = require("../store/db");

const CLUSTER_WINDOW_MINS = parseInt(process.env.CLUSTER_WINDOW_MINS || "30");
const CLUSTER_MIN_IPS     = parseInt(process.env.CLUSTER_MIN_IPS     || "3");

/**
 * Called after every score. Updates or creates threat_clusters rows.
 * Returns any newly formed clusters.
 */
async function detectClusters(result) {
  const { ip, score, riskLevel, network } = result;
  if (!ip) return [];

  const newClusters = [];
  const windowStart = new Date(Date.now() - CLUSTER_WINDOW_MINS * 60 * 1000);

  try {
    // Subnet cluster (/24) 
    const subnetMatch = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
    if (subnetMatch) {
      const subnet     = `${subnetMatch[1]}.0/24`;
      const clusterKey = `subnet:${subnet}`;

      // Count how many IPs from this /24 scored in the window
      const countRes = await db.query(
        `SELECT COUNT(DISTINCT ip) AS count, MAX(score) AS max_score
         FROM audit_log
         WHERE ip LIKE $1
           AND scored_at > $2`,
        [`${subnetMatch[1]}.%`, windowStart]
      );

      const count    = parseInt(countRes.rows[0].count, 10);
      const maxScore = parseInt(countRes.rows[0].max_score, 10) || score;

      if (count >= CLUSTER_MIN_IPS) {
        const cluster = await upsertCluster({
          clusterKey,
          clusterType: "subnet",
          ipCount:     count,
          maxScore,
          severity:    riskLevel,
          details:     { subnet, windowMins: CLUSTER_WINDOW_MINS, triggeredBy: ip },
        });
        if (cluster.isNew) newClusters.push(cluster);
      }
    }

    // ASN cluster 
    const asn = network?.asn;
    if (asn) {
      const clusterKey = `asn:${asn}`;

      const countRes = await db.query(
        `SELECT COUNT(DISTINCT ip) AS count, MAX(score) AS max_score
         FROM audit_log
         WHERE asn = $1
           AND scored_at > $2`,
        [asn, windowStart]
      );

      const count    = parseInt(countRes.rows[0].count, 10);
      const maxScore = parseInt(countRes.rows[0].max_score, 10) || score;

      if (count >= CLUSTER_MIN_IPS) {
        const cluster = await upsertCluster({
          clusterKey,
          clusterType: "asn",
          ipCount:     count,
          maxScore,
          severity:    riskLevel,
          details:     { asn, isp: network?.isp, windowMins: CLUSTER_WINDOW_MINS, triggeredBy: ip },
        });
        if (cluster.isNew) newClusters.push(cluster);
      }
    }

    // Country cluster 
    const country = result.geo?.country;
    if (country && (riskLevel === "CRITICAL" || riskLevel === "HIGH")) {
      const clusterKey = `country:${country}`;

      const countRes = await db.query(
        `SELECT COUNT(DISTINCT ip) AS count, MAX(score) AS max_score
         FROM audit_log
         WHERE country = $1
           AND risk_level IN ('CRITICAL','HIGH')
           AND scored_at > $2`,
        [country, windowStart]
      );

      const count    = parseInt(countRes.rows[0].count, 10);
      const maxScore = parseInt(countRes.rows[0].max_score, 10) || score;

      const COUNTRY_MIN = CLUSTER_MIN_IPS * 2; // higher threshold for country-level
      if (count >= COUNTRY_MIN) {
        const cluster = await upsertCluster({
          clusterKey,
          clusterType: "country",
          ipCount:     count,
          maxScore,
          severity:    riskLevel,
          details:     { country, windowMins: CLUSTER_WINDOW_MINS, triggeredBy: ip },
        });
        if (cluster.isNew) newClusters.push(cluster);
      }
    }
  } catch (err) {
  next(err);
}

  return newClusters;
}

async function upsertCluster({ clusterKey, clusterType, ipCount, maxScore, severity, details }) {
  try {
    // Check if active cluster already exists
    const existing = await db.query(
      `SELECT id, ip_count FROM threat_clusters
       WHERE cluster_key = $1 AND resolved = FALSE`,
      [clusterKey]
    );

    if (existing.rows.length) {
      // Update existing cluster
      await db.query(
        `UPDATE threat_clusters
         SET ip_count = $1, max_score = $2, severity = $3,
             last_seen = NOW(), details = $4
         WHERE cluster_key = $5 AND resolved = FALSE`,
        [ipCount, maxScore, severity, JSON.stringify(details), clusterKey]
      );
      return { isNew: false, clusterKey, ipCount };
    } else {
      // Create new cluster
      const res = await db.query(
        `INSERT INTO threat_clusters
           (cluster_key, cluster_type, ip_count, max_score, severity, details)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [clusterKey, clusterType, ipCount, maxScore, severity, JSON.stringify(details)]
      );
      console.log(`[cluster] New cluster detected: ${clusterKey} (${ipCount} IPs)`);
      return { isNew: true, ...res.rows[0] };
    }
  } catch (err) {
  next(err);
}
}

/**
 * Returns all active (unresolved) clusters, newest first.
 */
async function getActiveClusters(limit = 20) {
  try {
    const res = await db.query(
      `SELECT * FROM threat_clusters
       WHERE resolved = FALSE
       ORDER BY last_seen DESC
       LIMIT $1`,
      [limit]
    );
    return res.rows;
  } catch (err) {
  next(err);
}
}

/**
 * Mark a cluster as resolved (analyst dismissed it).
 */
async function resolveCluster(id) {
  try {
    await db.query(
      `UPDATE threat_clusters SET resolved = TRUE WHERE id = $1`,
      [id]
    );
    return true;
  } catch (err) {
  next(err);
}
}

module.exports = { detectClusters, getActiveClusters, resolveCluster };