const cron = require("node-cron");
const { getWatchlistQueue } = require("./queues");

let cronTask = null;

function startWatchlistCron() {
  const intervalMins = parseInt(process.env.WATCHLIST_POLL_INTERVAL_MINS || "5");

  // node-cron doesn't support arbitrary minute intervals natively,
  // so we map common values to cron expressions.
  const cronExpression = intervalMins <= 1  ? "* * * * *"          // every minute
                       : intervalMins <= 5  ? "*/5 * * * *"        // every 5 min
                       : intervalMins <= 10 ? "*/10 * * * *"       // every 10 min
                       : intervalMins <= 15 ? "*/15 * * * *"       // every 15 min
                       : intervalMins <= 30 ? "*/30 * * * *"       // every 30 min
                       :                      "0 * * * *";         // every hour

  const queue = getWatchlistQueue();
  if (!queue) {
    console.warn("[watchlistCron] Redis not available — cron not started");
    return null;
  }

  cronTask = cron.schedule(cronExpression, async () => {
    try {
      const job = await queue.add(
        "scheduled-poll",
        { triggeredBy: "cron", ts: Date.now() },
        { jobId: `watchlist-poll-${Date.now()}` }
      );
      console.log(`[watchlistCron] Poll enqueued — job ${job.id}`);
    } catch (err) {
      console.error("[watchlistCron] Failed to enqueue poll:", err.message);
    }
  });

  console.log(`✓ Watchlist cron started — polling every ${intervalMins} min (${cronExpression})`);
  return cronTask;
}

function stopWatchlistCron() {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
    console.log("[watchlistCron] Stopped");
  }
}

module.exports = { startWatchlistCron, stopWatchlistCron };