const { Worker } = require("bullmq");
const { getRedis } = require("../store/redis");

// Alert worker 
function startAlertWorker() {
  const redis = getRedis();
  if (!redis) return null;

  const worker = new Worker("alerts", async (job) => {
    const { sendAlert } = require("../services/alert.service");
    const result = await sendAlert(job.data);
    console.log(`[alertWorker] Job ${job.id} delivered to: ${result.delivered.join(", ") || "none"}`);
    return result;
  }, {
    connection: redis,
    concurrency: 3,
  });

  worker.on("failed", (job, err) => {
    console.error(`[alertWorker] Job ${job?.id} failed:`, err.message);
  });

  console.log("✓ Alert worker started");
  return worker;
}

// Batch scoring worker 
function startBatchWorker() {
  const redis = getRedis();
  if (!redis) return null;

  const worker = new Worker("batch-score", async (job) => {
    const { getFullIntel }    = require("../services/ipIntel.service");
    const { checkAndAutoCase } = require("../services/autoCase.service");
    const { sendToSIEM }       = require("../services/siem.service");
    const db                   = require("../store/db");

    const { ips, threshold, caseName, addedBy = "analyst" } = job.data;
    const total   = ips.length;
    let completed = 0;

    const results   = [];
    const blocked   = [];
    const allowed   = [];
    const failed    = [];

    // Process in chunks of 10 to respect rate limits
    const CHUNK = 10;
    for (let i = 0; i < ips.length; i += CHUNK) {
      const chunk   = ips.slice(i, i + CHUNK);
      const settled = await Promise.allSettled(chunk.map(ip => getFullIntel(ip)));

      for (let j = 0; j < settled.length; j++) {
        const r   = settled[j];
        const ip  = chunk[j];

        if (r.status === "fulfilled") {
          const result = r.value;
          results.push(result);

          // Persist to audit_log
          try {
            await db.query(
              `INSERT INTO audit_log
                 (ip, score, risk_level, action, is_proxy, is_tor,
                  is_datacenter, country, isp, asn, cached, scored_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())`,
              [
                result.ip, result.score, result.riskLevel, result.action || null,
                result.intelligence?.isProxy      || false,
                result.intelligence?.isTor        || false,
                result.intelligence?.isDatacenter || false,
                result.geo?.country  || null,
                result.network?.isp  || null,
                result.network?.asn  || null,
                result.meta?.cached  || false,
              ]
            );
          } catch (_) {}

          // Blacklist if above threshold
          if (threshold && result.score >= threshold) {
            try {
              await db.query(
                `INSERT INTO blacklist (ip, severity, reason, added_by, category)
                 VALUES ($1,$2,$3,$4,'Batch-and-block')
                 ON CONFLICT (ip) DO NOTHING`,
                [result.ip, result.riskLevel, `Batch block: score ${result.score}/100`, addedBy]
              );
              blocked.push({ ip: result.ip, score: result.score, riskLevel: result.riskLevel });
            } catch (_) {}
          } else {
            allowed.push({ ip: result.ip, score: result.score, riskLevel: result.riskLevel });
          }

          // Auto case + SIEM
          checkAndAutoCase(result).catch(() => {});
          sendToSIEM(result).catch(() => {});

        } else {
          failed.push({ ip, error: r.reason?.message || "Failed" });
        }

        completed++;
      }

      // Report progress
      await job.updateProgress(Math.round((completed / total) * 100));

      // Small delay between chunks to avoid hammering APIs
      if (i + CHUNK < ips.length) {
        await new Promise(r => setTimeout(r, 200));
      }
    }

    // Create a case if caseName provided and we have blocked IPs
    let caseId = null;
    if (caseName && blocked.length > 0) {
      try {
        const caseRes = await db.query(
          `INSERT INTO cases (title, description, severity, status, assigned_to)
           VALUES ($1, $2, $3, 'Investigating', $4)
           RETURNING id`,
          [
            caseName,
            `Batch-and-block: ${blocked.length} IPs blocked out of ${total} scored.`,
            blocked.some(b => b.riskLevel === "CRITICAL") ? "CRITICAL" : "HIGH",
            addedBy,
          ]
        );
        caseId = caseRes.rows[0].id;

        for (const b of blocked) {
          await db.query(
            `INSERT INTO case_ips (case_id, ip, score, risk_level)
             VALUES ($1,$2,$3,$4) ON CONFLICT (case_id, ip) DO NOTHING`,
            [caseId, b.ip, b.score, b.riskLevel]
          );
        }
      } catch (err) {
        console.error("[batchWorker] Case creation error:", err.message);
      }
    }

    return { total, blocked, allowed, failed, caseId };
  }, {
    connection:  getRedis(),
    concurrency: 2,
  });

  worker.on("failed", (job, err) => {
    console.error(`[batchWorker] Job ${job?.id} failed:`, err.message);
  });

  console.log("✓ Batch scoring worker started");
  return worker;
}

// Watchlist polling worker
function startWatchlistWorker() {
  const redis = getRedis();
  if (!redis) return null;

  const worker = new Worker("watchlist-poll", async (job) => {
    const { getWatchlist, updateWatchlistEntry } = require("../store/watchlist.store");
    const { getFullIntel }  = require("../services/ipIntel.service");
    const { getAlertQueue } = require("../jobs/queues");

    const items   = getWatchlist();
    if (!items.length) return { checked: 0, alerts: 0 };

    let alertsFired = 0;

    for (const item of items) {
      try {
        const result     = await getFullIntel(item.ip);
        const prevScore  = item.last_score || 0;
        const prevRisk   = item.last_risk  || "UNKNOWN";
        const newScore   = result.score;
        const newRisk    = result.riskLevel;

        await updateWatchlistEntry(item.ip, {
          last_score:   newScore,
          last_risk:    newRisk,
          last_checked: Date.now(),
        });

        // Fire alert if threshold crossed or risk level changed
        const thresholdCrossed = prevScore < item.threshold && newScore >= item.threshold;
        const riskChanged      = item.alert_on_change && prevRisk !== newRisk && prevRisk !== "UNKNOWN";

        if (thresholdCrossed || riskChanged) {
          const alertQueue = getAlertQueue();
          if (alertQueue) {
            await alertQueue.add("watchlist-alert", {
              title:     `Watchlist Alert: ${item.ip}`,
              message:   thresholdCrossed
                ? `Score crossed threshold: ${prevScore} → ${newScore} (threshold: ${item.threshold})`
                : `Risk level changed: ${prevRisk} → ${newRisk}`,
              ip:        item.ip,
              score:     newScore,
              riskLevel: newRisk,
              type:      thresholdCrossed ? "THRESHOLD_CROSSED" : "RISK_CHANGED",
              details:   { label: item.label, prevScore, newScore, prevRisk, newRisk, threshold: item.threshold },
            });
            alertsFired++;
          }
        }

        // Small delay between IPs
        await new Promise(r => setTimeout(r, 100));
      } catch (err) {
        console.error(`[watchlistWorker] Error scoring ${item.ip}:`, err.message);
      }
    }

    console.log(`[watchlistWorker] Polled ${items.length} IPs, ${alertsFired} alerts fired`);
    return { checked: items.length, alerts: alertsFired };
  }, {
    connection:  redis,
    concurrency: 1, // watchlist polls run one at a time
  });

  worker.on("failed", (job, err) => {
    console.error(`[watchlistWorker] Job ${job?.id} failed:`, err.message);
  });

  console.log("✓ Watchlist worker started");
  return worker;
}

// Start all workers 
function startWorkers() {
  const redis = getRedis();
  if (!redis) {
    console.warn("[workers] Redis not available — workers not started");
    return {};
  }

  return {
    alertWorker:     startAlertWorker(),
    batchWorker:     startBatchWorker(),
    watchlistWorker: startWatchlistWorker(),
  };
}

module.exports = { startWorkers, startAlertWorker, startBatchWorker, startWatchlistWorker };