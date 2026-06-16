const { Worker, Queue } = require("bullmq");
const { getRedis } = require("../store/redis");
const scanStore = require("../store/scan.store.js");
const { processNmap } = require("./nmapProcessor");
const { processNuclei } = require("./nucleiProcessor");
const logger = require("../utils/logger");

const QUEUE_NAME = "active-scans";

let scanQueue;

// Queue
function getScanQueue() {
  if (!scanQueue) {
    const redis = getRedis();

    scanQueue = new Queue(QUEUE_NAME, {
      connection: redis,
      defaultJobOptions: {
        attempts: 2,
        backoff: { type: "exponential", delay: 5000 },
        removeOnComplete: { count: 200 },
        removeOnFail: { count: 100 },
      },
    });
  }
  return scanQueue;
}

async function enqueueScan({ jobId, ip, requestedBy }) {
  const q = getScanQueue();

  await q.add(
    "scan",
    { jobId, ip, requestedBy },
    { jobId }
  );

  logger.info(`[scanWorker] enqueued scan ${jobId} for ${ip}`);
}

// Worker
function startScanWorker() {
  const worker = new Worker(
    QUEUE_NAME,
    async (job) => {
      const { jobId, ip } = job.data;

      logger.info(`[scanWorker] processing job ${jobId} for ${ip}`);

      await scanStore.setJobRunning(jobId);

      const [nmapResult, nucleiResult] = await Promise.allSettled([
        processNmap(job),
        processNuclei(job),
      ]);

      if (
        nmapResult.status === "rejected" &&
        nucleiResult.status === "rejected"
      ) {
        await scanStore.setJobFailed(jobId, "both scanners failed");
        throw new Error("both scanners failed");
      }

      await scanStore.setJobDone(jobId);

      return {
        nmap:
          nmapResult.status === "fulfilled"
            ? nmapResult.value
            : { error: nmapResult.reason?.message },

        nuclei:
          nucleiResult.status === "fulfilled"
            ? nucleiResult.value
            : { error: nucleiResult.reason?.message },
      };
    },
    {
      connection: getRedis(),
      concurrency: 2,
      lockDuration: 360000,
    }
  );

  worker.on("completed", (job, result) => {
    logger.info(`[scanWorker] job ${job.id} completed`, result);
  });

  worker.on("failed", (job, err) => {
    logger.error(`[scanWorker] job ${job?.id} failed: ${err.message}`);

    if (job?.data?.jobId) {
      scanStore.setJobFailed(job.data.jobId, err.message).catch(() => {});
    }
  });

  logger.info("[scanWorker] started — queue: " + QUEUE_NAME);

  return worker;
}

module.exports = {
  startScanWorker,
  enqueueScan,
  getScanQueue,
};