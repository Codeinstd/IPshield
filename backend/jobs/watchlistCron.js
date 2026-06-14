const cron = require("node-cron");
const { getWatchlistQueue } = require("./queues");

let cronTask = null;

function startWatchlistCron() {
  const intervalMins = parseInt(
    process.env.WATCHLIST_POLL_INTERVAL_MINS || "5"
  );

  const cronExpression =
    intervalMins <= 1
      ? "* * * * *"
      : intervalMins <= 5
      ? "*/5 * * * *"
      : intervalMins <= 10
      ? "*/10 * * * *"
      : intervalMins <= 15
      ? "*/15 * * * *"
      : intervalMins <= 30
      ? "*/30 * * * *"
      : "0 * * * *";

  cronTask = cron.schedule(cronExpression, async () => {
    try {
      const queue = getWatchlistQueue();

      if (!queue) {
        console.warn(
          "[watchlistCron] Redis unavailable — skipping tick"
        );
        return;
      }

      const job = await queue.add(
        "scheduled-poll",
        {
          triggeredBy: "cron",
          ts: Date.now(),
        },
        {
          jobId: `watchlist-${Date.now()}`,
        }
      );

      console.log(
        `[watchlistCron] queued job ${job.id}`
      );
    } catch (err) {
      console.error(
        "[watchlistCron] failed:",
        err.message
      );
    }
  });

  console.log(
    `✓ watchlist cron running (${cronExpression})`
  );

  return cronTask;
}

function stopWatchlistCron() {
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
    console.log("[watchlistCron] stopped");
  }
}

module.exports = {
  startWatchlistCron,
  stopWatchlistCron,
};