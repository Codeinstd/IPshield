const { spawn }     = require("child_process");
const scan          = require("../store/scan.store.js");
const logger        = require("../utils/logger");

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

function highestSeverity(findings) {
  const normalised = findings.map((f) => (f.info?.severity ?? f.severity ?? "unknown").toLowerCase());
  for (const sev of SEV_ORDER) {
    if (normalised.includes(sev)) return sev.toUpperCase();
  }
  return "NONE";
}

// Run nuclei, collect JSONL lines
function runNuclei(ip) {
  return new Promise((resolve, reject) => {
    const args = [
      "-u",    `http://${ip}`,  // nuclei wants a URL; it probes both http/https
      "-u",    `https://${ip}`,
      "-u",    ip,              // raw IP for network templates
      "-t",    "network/",
      "-t",    "ssl/",
      "-t",    "http/",
      "-tags", "network,ssl,tls,misconfig,exposure,default-login,takeover,tech",
      "-exclude-tags", "fuzzing,dos,code,intrusive",
      "-severity", "critical,high,medium,low,info",
      "-jsonl",
      "-timeout", "8",
      "-c",    "20",
      "-silent",
      "-no-interactsh",
      "-duc",
      "-rl",   "50",           // rate limit: 50 req/s max
    ];

    logger.info(`[nuclei] starting: nuclei ${args.slice(0, 8).join(" ")} …`);

    const proc    = spawn("nuclei", args, { timeout: 300_000 }); // 5 min hard cap
    const lines   = [];
    let   stderr  = "";

    proc.stdout.on("data", (chunk) => {
      // nuclei emits one JSON object per line
      chunk.toString().split("\n").forEach((line) => {
        line = line.trim();
        if (line.startsWith("{")) lines.push(line);
      });
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      logger.info(`[nuclei] exited with code ${code}, lines collected: ${lines.length}`);
      resolve(lines); // nuclei exits non-zero when findings exist — that's fine
    });

    proc.on("error", (err) => {
      reject(new Error(`nuclei spawn error: ${err.message}\nstderr: ${stderr}`));
    });
  });
}

// Parse JSONL → structured findings 
function parseFindings(jsonLines) {
  const findings = [];

  for (const line of jsonLines) {
    try {
      const f = JSON.parse(line);

      findings.push({
        templateId:   f["template-id"] ?? f.templateID ?? "unknown",
        templateName: f.info?.name     ?? f["template-id"] ?? "unknown",
        severity:     (f.info?.severity ?? "info").toUpperCase(),
        type:         f.type           ?? "unknown",
        host:         f.host           ?? "",
        matched:      f["matched-at"]  ?? f.matched ?? "",
        description:  f.info?.description ?? "",
        tags:         f.info?.tags     ?? [],
        reference:    f.info?.reference ?? [],
        cvss:         f.info?.classification?.["cvss-score"]     ?? null,
        cve:          f.info?.classification?.["cve-id"]?.[0]    ?? null,
        cwe:          f.info?.classification?.["cwe-id"]?.[0]    ?? null,
        remediation:  f.info?.remediation ?? "",
        timestamp:    f.timestamp      ?? new Date().toISOString(),
        // Raw curl-style request/response for analyst review
        request:      f.request        ?? null,
        response:     f.response       ?? null,
      });
    } catch {
      // skip malformed lines
    }
  }

  // Sort by severity
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, UNKNOWN: 5 };
  return findings.sort((a, b) => (sevRank[a.severity] ?? 5) - (sevRank[b.severity] ?? 5));
}

function buildSummary(findings) {
  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    const s = f.severity?.toUpperCase();
    if (s in bySev) bySev[s]++;
  }

  const uniqueTemplates = [...new Set(findings.map((f) => f.templateId))];
  const cves            = [...new Set(findings.map((f) => f.cve).filter(Boolean))];

  return {
    total:     findings.length,
    bySeverity: bySev,
    cves,
    uniqueTemplates: uniqueTemplates.length,
    // Only expose top 20 to keep summary lean; full list is in raw
    topFindings: findings.slice(0, 20).map((f) => ({
      templateId:   f.templateId,
      templateName: f.templateName,
      severity:     f.severity,
      matched:      f.matched,
      cve:          f.cve,
      cvss:         f.cvss,
      description:  f.description,
      tags:         f.tags,
    })),
  };
}

// Main processor (called by BullMQ worker) 
async function processNuclei(job) {
  const { jobId, ip } = job.data;

  try {
    await job.updateProgress(5);
    const jsonLines = await runNuclei(ip);

    await job.updateProgress(80);
    const findings = parseFindings(jsonLines);
    const summary  = buildSummary(findings);
    const severity = highestSeverity(findings);

    await scanStore.saveResult({
      jobId,
      ip,
      scanner:  "nuclei",
      raw:      { findings },   // full dataset — can be large
      summary,
      severity,
    });

    await job.updateProgress(100);
    logger.info(`[nuclei] done for ${ip} — ${findings.length} findings, severity: ${severity}`);

    return {
      scanner:  "nuclei",
      findings: findings.length,
      cves:     summary.cves.length,
      severity,
    };

  } catch (err) {
    logger.error(`[nuclei] failed for ${ip}: ${err.message}`);
    throw err;
  }
}

module.exports = { processNuclei };