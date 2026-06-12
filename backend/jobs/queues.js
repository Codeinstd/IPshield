const { Queue } = require("bullmq");
const { getRedis } = require("../store/redis");

const DEFAULT_JOB_OPTIONS = {
  attempts:    3,
  backoff: { type: "exponential", delay: 2000 },
  removeOnComplete: { count: 100 },
  removeOnFail:     { count: 50  },
};

let alertQueue    = null;
let batchQueue    = null;
let watchlistQueue = null;

function getAlertQueue() {
  if (alertQueue) return alertQueue;
  const redis = getRedis();
  if (!redis) return null;
  alertQueue = new Queue("alerts", { connection: redis, defaultJobOptions: DEFAULT_JOB_OPTIONS });
  return alertQueue;
}

function getBatchQueue() {
  if (batchQueue) return batchQueue;
  const redis = getRedis();
  if (!redis) return null;
  batchQueue = new Queue("batch-score", { connection: redis, defaultJobOptions: DEFAULT_JOB_OPTIONS });
  return batchQueue;
}

function getWatchlistQueue() {
  if (watchlistQueue) return watchlistQueue;
  const redis = getRedis();
  if (!redis) return null;
  watchlistQueue = new Queue("watchlist-poll", { connection: redis, defaultJobOptions: DEFAULT_JOB_OPTIONS });
  return watchlistQueue;
}

module.exports = { getAlertQueue, getBatchQueue, getWatchlistQueue };