
const { getRedis }      = require("../store/redis");
const { getAlertQueue } = require("../jobs/queues");
const db                = require("../store/db");

const THRESHOLD      = parseInt(process.env.AUTO_CASE_THRESHOLD      || "5");
const WINDOW_SECS    = parseInt(process.env.AUTO_CASE_WINDOW_SECS    || "600");
const BL_THRESHOLD   = parseInt(process.env.AUTO_BLACKLIST_THRESHOLD || "80");

/**
 * Call this after every score result.
 * Returns { autoCaseCreated, autoBlacklisted } booleans.
 */
async function checkAndAutoCase(result) {
  const redis = getRedis();
  if (!redis) return { autoCaseCreated: false, autoBlacklisted: false };

  const { ip, score, riskLevel } = result;
  let autoCaseCreated  = false;
  let autoBlacklisted  = false;

  // ── Auto-blacklist if score is above threshold ────────────────────────────
  if (score >= BL_THRESHOLD) {
    try {
      await db.query(
        `INSERT INTO blacklist (ip, severity, reason, added_by, category)
         VALUES ($1, $2, $3, 'auto', 'Auto-detected')
         ON CONFLICT (ip) DO NOTHING`,
        [ip, riskLevel, `Auto-blacklisted: score ${score}/100`]
      );
      autoBlacklisted = true;
    } catch (_) {}
  }

  // ── Sliding window counter for CRITICAL/HIGH IPs ──────────────────────────
  if (riskLevel !== "CRITICAL" && riskLevel !== "HIGH") {
    return { autoCaseCreated, autoBlacklisted };
  }

  const windowKey = `ipshield:threat:window`;
  const detailKey = `ipshield:threat:ips`;

  try {
    const now     = Date.now();
    const cutoff  = now - WINDOW_SECS * 1000;

    // Add this IP with its timestamp to a sorted set
    await redis.zadd(windowKey, now, `${ip}:${now}`);

    // Remove entries outside the window
    await redis.zremrangebyscore(windowKey, "-inf", cutoff);

    // Count IPs in the window
    const count = await redis.zcard(windowKey);

    // Store IP detail for case creation
    await redis.lpush(detailKey, JSON.stringify({ ip, score, riskLevel, ts: now }));
    await redis.ltrim(detailKey, 0, 99); // keep last 100
    await redis.expire(detailKey, WINDOW_SECS * 2);

    if (count >= THRESHOLD) {
      // Check if a case was already created recently (avoid duplicates)
      const lockKey  = `ipshield:autocase:lock`;
      const acquired = await redis.set(lockKey, "1", "EX", WINDOW_SECS, "NX");

      if (acquired) {
        // Get the IPs that triggered this
        const raw     = await redis.lrange(detailKey, 0, 49);
        const ips     = raw.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
        const caseTitle = `Auto-detected: ${count} ${riskLevel} IPs in ${Math.floor(WINDOW_SECS / 60)} minutes`;

        // Create the case directly
        const caseRes = await db.query(
          `INSERT INTO cases (title, description, severity, status, assigned_to)
           VALUES ($1, $2, $3, 'Investigating', 'auto')
           RETURNING *`,
          [
            caseTitle,
            `Automatically opened: ${count} IPs scored ${riskLevel} or higher within a ${Math.floor(WINDOW_SECS/60)}-minute window. Immediate review required.`,
            riskLevel === "CRITICAL" ? "CRITICAL" : "HIGH",
          ]
        );

        const newCase = caseRes.rows[0];

        // Attach the triggering IPs
        for (const entry of ips.slice(0, 20)) {
          try {
            await db.query(
              `INSERT INTO case_ips (case_id, ip, score, risk_level)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (case_id, ip) DO NOTHING`,
              [newCase.id, entry.ip, entry.score, entry.riskLevel]
            );
          } catch (_) {}
        }

        // Enqueue alert
        const alertQueue = getAlertQueue();
        if (alertQueue) {
          await alertQueue.add("auto-case-alert", {
            title:     caseTitle,
            message:   `Case #${newCase.id} automatically opened. ${count} threat IPs detected.`,
            caseId:    newCase.id,
            riskLevel,
            type:      "AUTO_CASE",
            details:   { count, threshold: THRESHOLD, windowMins: Math.floor(WINDOW_SECS / 60), ips: ips.slice(0, 10) },
          });
        }

        // Reset the window so it doesn't keep firing
        await redis.del(windowKey);
        autoCaseCreated = true;
        console.log(`[autoCase] Case #${newCase.id} created — ${count} threat IPs in window`);
      }
    }
  } catch (err) {
    console.error("[autoCase] Error:", err.message);
  }

  return { autoCaseCreated, autoBlacklisted };
}

module.exports = { checkAndAutoCase };