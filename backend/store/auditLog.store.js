const crypto = require("crypto");
const db     = require("./db");

async function appendAuditEntry(entry) {
  return db.transaction(async (client) => {

    // Lock the last row to get its hash — prevents race conditions
    const lastRow = await client.query(
      `SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE`
    );
    const prevHash = lastRow.rows.length
      ? lastRow.rows[0].row_hash
      : "GENESIS";

    // Build deterministic content string
    const content = JSON.stringify({
      ip:         entry.ip,
      score:      entry.score,
      risk_level: entry.riskLevel || entry.risk_level,
      scored_at:  new Date(entry.scoredAt || entry.scored_at || Date.now()).toISOString(),
      prev_hash:  prevHash,
    });

    const rowHash = crypto
      .createHash("sha256")
      .update(content)
      .digest("hex");

    // Insert with hashes
    const result = await client.query(
      `INSERT INTO audit_log (
        ip, score, risk_level, action,
        country, city, isp, asn,
        is_proxy, is_tor, is_dc,
        is_feodo, is_spamhaus, is_et, otx_pulses,
        scored_at, prev_hash, row_hash
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,
        $9,$10,$11,$12,$13,$14,$15,
        NOW(),$16,$17
      ) RETURNING id, row_hash`,
      [
        entry.ip,
        entry.score,
        entry.riskLevel  || entry.risk_level,
        entry.action,
        entry.geo?.country     || entry.country    || null,
        entry.geo?.city        || entry.city       || null,
        entry.network?.isp     || entry.isp        || null,
        entry.network?.asn     || entry.asn        || null,
        entry.intelligence?.isProxy      ?? entry.is_proxy     ?? false,
        entry.intelligence?.isTor        ?? entry.is_tor       ?? false,
        entry.intelligence?.isDatacenter ?? entry.is_dc        ?? false,
        entry.threatFeeds?.feodo         ?? entry.is_feodo     ?? false,
        entry.threatFeeds?.spamhaus      ?? entry.is_spamhaus  ?? false,
        entry.threatFeeds?.emergingThreats ?? entry.is_et      ?? false,
        entry.threatFeeds?.otx?.pulseCount ?? entry.otx_pulses ?? 0,
        prevHash,
        rowHash,
      ]
    );

    return result.rows[0];
  });
}

module.exports = { appendAuditEntry };