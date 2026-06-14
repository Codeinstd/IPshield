const { Queue } = require("bullmq");
const { getRedis } = require("../store/redis");

const DEFAULT_JOB_OPTIONS = {
  attempts: 3,
  backoff: { type: "exponential", delay: 2000 },
  removeOnComplete: { count: 100 },
  removeOnFail: { count: 50 },
};

const PREFIX = process.env.BULLMQ_PREFIX || "ipshield";

const queues = {};

function createQueue(name) {
  const redis = getRedis();

  if (!redis) {
    console.warn(
      `[queues] Redis unavailable — ${name} queue disabled`
    );
    return null;
  }

  if (queues[name]) return queues[name];

  queues[name] = new Queue(name, {
    connection: redis,
    prefix: PREFIX,
    defaultJobOptions: DEFAULT_JOB_OPTIONS,
  });

  return queues[name];
}

const getAlertQueue = () => createQueue("alerts");
const getBatchQueue = () => createQueue("batch-score");
const getWatchlistQueue = () => createQueue("watchlist-poll");

module.exports = {
  getAlertQueue,
  getBatchQueue,
  getWatchlistQueue,
};