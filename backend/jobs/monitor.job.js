/**
 * monitor.job.js
 * Place in: backend/jobs/monitor.job.js
 *
 * Polls all watched IPs on a schedule and fires alerts on changes.
 * Runs in-process — no external job queue needed.
 */

const { getWatchlist, updateWatchlistEntry } = require("../store/watchlist.store");
const { getFullIntel } = require("../services/ipIntel.service");
const { alertIfCritical } = require("../services/alerts.service");
const logger              = require("../utils/logger");

const POLL_INTERVAL = parseInt(process.env.WATCHLIST_POLL_MS || String(1000 * 60 * 60 * 6)); // 6h default
const BATCH_SIZE    = 5;   // score N IPs at a time to avoid hammering APIs
const BATCH_DELAY   = 2000; // ms between batches

let monitorTimer = null;
let isRunning    = false;

// ── Custom alert for watchlist changes ────────────────────────────────────────
async function sendWatchlistAlert(ip, prev, curr) {
  const axios = require("axios");
  const direction = curr.score > prev.score ? "📈 INCREASED" : "📉 DECREASED";
  const urgent    = curr.riskLevel === "CRITICAL" || curr.score >= 80;

  const msg = [
    `${urgent ? "🚨" : "👁"} *Watchlist Alert* — ${ip}`,
    `Score: ${prev.score} → ${curr.score} (${direction})`,
    `Risk:  ${prev.last_risk} → ${curr.riskLevel}`,
    `Action: ${curr.action}`,
    curr.geo?.country ? `Location: ${curr.geo.city || "—"}, ${curr.geo.country}` : null,
    curr.network?.isp ? `ISP: ${curr.network.isp}` : null
  ].filter(Boolean).join("\n");

  // Slack
  if (process.env.SLACK_WEBHOOK) {
    try {
      await axios.post(process.env.SLACK_WEBHOOK, {
        text: msg,
        attachments: [{
          color: curr.riskLevel === "CRITICAL" ? "#ff3355" :
                 curr.riskLevel === "HIGH"     ? "#ff7700" :
                 curr.riskLevel === "MEDIUM"   ? "#ffcc00" : "#00e87c"
        }]
      }, { timeout: 5000 });
    } catch (err) {
      logger.error("Watchlist Slack alert failed:", err.message);
    }
  }

  // Discord
  if (process.env.DISCORD_WEBHOOK) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK, {
        embeds: [{
          title:       `👁 Watchlist Alert: ${ip}`,
          description: msg.replace(/\*/g, "**"),
          color:       curr.riskLevel === "CRITICAL" ? 0xff3355 :
                       curr.riskLevel === "HIGH"     ? 0xff7700 :
                       curr.riskLevel === "MEDIUM"   ? 0xffcc00 : 0x00e87c,
          timestamp:   new Date().toISOString()
        }]
      }, { timeout: 5000 });
    } catch (err) {
      logger.error("Watchlist Discord alert failed:", err.message);
    }
  }
}

// ── Core poll function ────────────────────────────────────────────────────────
async function pollWatchlist() {
  if (isRunning) {
    logger.warn("Monitor: previous run still active, skipping");
    return;
  }

  const items = getWatchlist();
  if (!items.length) return;

  isRunning = true;
  logger.info(`Monitor: polling ${items.length} watched IPs`);

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  // Process in small batches to avoid API hammering
  for (let i = 0; i < items.length; i += BATCH_SIZE) {
    const batch = items.slice(i, i + BATCH_SIZE);

    await Promise.allSettled(batch.map(async (item) => {
      try {
        // Bypass cache for monitoring — always fetch fresh
        const result = await getFullIntel(item.ip, { bypassCache: true });
        const prevScore = item.last_score;
        const prevRisk  = item.last_risk;

        const scoreChanged = Math.abs(result.score - prevScore) >= 10;
        const riskChanged  = result.riskLevel !== prevRisk && prevRisk !== "UNKNOWN";

        // Update stored values
        updateWatchlistEntry(item.ip, {
          last_score:   result.score,
          last_risk:    result.riskLevel,
          last_checked: Date.now()
        });

        // Alert conditions
        const shouldAlert =
          (item.alert_on_change && (scoreChanged || riskChanged)) ||
          result.score >= item.threshold;

        if (shouldAlert && prevRisk !== "UNKNOWN") {
          logger.info(`Monitor: alert triggered for ${item.ip} — score ${prevScore}→${result.score}`);
          await sendWatchlistAlert(item.ip, item, result);
          await alertIfCritical(result);
        }

      } catch (err) {
        logger.error(`Monitor: failed to score ${item.ip}:`, err.message);
      }
    }));

    // Delay between batches
    if (i + BATCH_SIZE < items.length) await sleep(BATCH_DELAY);
  }

  isRunning = false;
  logger.info("Monitor: poll complete");
}

// ── Scheduler ─────────────────────────────────────────────────────────────────
function startMonitor() {
  if (monitorTimer) return;

  logger.info(`Monitor: started — polling every ${Math.round(POLL_INTERVAL / 1000 / 60)} minutes`);

  // First poll after 30s (let server fully start)
  setTimeout(pollWatchlist, 30000);

  // Then on schedule
  monitorTimer = setInterval(pollWatchlist, POLL_INTERVAL);
}

function stopMonitor() {
  if (monitorTimer) { clearInterval(monitorTimer); monitorTimer = null; }
  logger.info("Monitor: stopped");
}

function getMonitorStatus() {
  return {
    running:       isRunning,
    active:        !!monitorTimer,
    intervalMins:  Math.round(POLL_INTERVAL / 1000 / 60),
    watchlistSize: getWatchlist().length
  };
}

// Keep Render free tier alive — pings health every 14 minutes
if (process.env.NODE_ENV === "production" && process.env.RENDER_EXTERNAL_URL) {
  const axios = require("axios");
  setInterval(() => {
    axios.get(`${process.env.RENDER_EXTERNAL_URL}/api/health`, { timeout: 5000 })
      .catch(() => {});
  }, 1000 * 60 * 14);
}

module.exports = { startMonitor, stopMonitor, pollWatchlist, getMonitorStatus };