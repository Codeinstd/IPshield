const { Worker } = require("bullmq");
const { getRedis } = require("../store/redis");
const { spawn } = require("child_process");

function runCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    const child = spawn(cmd, args);

    child.stdout.on("data", d => {
      stdout += d.toString();
    });

    child.stderr.on("data", d => {
      stderr += d.toString();
    });

    child.on("close", code => {
      if (code !== 0) {
        return reject(new Error(stderr));
      }

      resolve(stdout);
    });
  });
}

function startScanWorker() {
  return new Worker(
    "scan-jobs",
    async (job) => {
      const { target } = job.data;

      // Validate target before scanning
      // Reject localhost/private ranges/etc.

      const nmapOutput = await runCommand(
        "nmap",
        [
          "-sV",
          "-oX",
          "-",
          target
        ]
      );

      await job.updateProgress(50);

      const nucleiOutput = await runCommand(
        "nuclei",
        [
          "-u",
          target,
          "-json"
        ]
      );

      await job.updateProgress(100);

      return {
        target,
        nmap: nmapOutput,
        nuclei: nucleiOutput
      };
    },
    {
      connection: getRedis(),
      concurrency: 2
    }
  );
}

module.exports = { startScanWorker };