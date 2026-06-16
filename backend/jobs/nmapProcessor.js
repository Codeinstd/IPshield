const { execFile }  = require("child_process");
const { promisify } = require("util");
const xml2js        = require("xml2js");   
const scan          = require("../store/scan.store.js");
const logger        = require("../utils/logger");

const execFileAsync = promisify(execFile);
const parseXml      = promisify(new xml2js.Parser({ explicitArray: false }).parseString);

// Severity thresholds by CVSS (from vulners NSE output)
function cvssSeverity(score) {
  if (!score) return "INFO";
  const n = parseFloat(score);
  if (n >= 9.0) return "CRITICAL";
  if (n >= 7.0) return "HIGH";
  if (n >= 4.0) return "MEDIUM";
  if (n >= 0.1) return "LOW";
  return "INFO";
}

// Highest severity across all findings
function highestSeverity(findings) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"];
  for (const sev of order) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return "NONE";
}

async function runNmap(ip) {
  // -O removed for Render compatibility; add it back on a VPS with CAP_NET_RAW
  const args = [
    "-sV",
    "-sC",
    "--script", "vulners",
    "-oX", "-",
    "-T4",
    "--open",
    "-p", "1-10000",
    "--host-timeout", "120s",
    ip,
  ];

  logger.info(`[nmap] starting scan: nmap ${args.join(" ")}`);

  const { stdout, stderr } = await execFileAsync("nmap", args, {
    timeout: 130_000, // ms — slightly over --host-timeout
    maxBuffer: 10 * 1024 * 1024, // 10 MB
  });

  if (!stdout || stdout.trim() === "") {
    throw new Error(`nmap produced no output. stderr: ${stderr}`);
  }

  return stdout;
}

function parseNmapXml(xmlString) {
  return new Promise((resolve, reject) => {
    xml2js.parseString(xmlString, { explicitArray: false }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

function extractPorts(parsed) {
  try {
    const host  = parsed?.nmaprun?.host;
    if (!host) return [];

    const portsNode = host?.ports?.port;
    if (!portsNode) return [];

    const portList = Array.isArray(portsNode) ? portsNode : [portsNode];

    return portList.map((p) => {
      const scripts  = p.script ? (Array.isArray(p.script) ? p.script : [p.script]) : [];
      const vulnData = extractVulners(scripts);

      return {
        port:     parseInt(p.$.portid, 10),
        protocol: p.$.protocol,
        state:    p.state?.$.state,
        service:  p.service?.$.name   ?? "unknown",
        product:  p.service?.$.product ?? "",
        version:  p.service?.$.version ?? "",
        scripts:  scripts.map((s) => ({ id: s.$.id, output: s.$.output })),
        vulns:    vulnData,
      };
    });
  } catch {
    return [];
  }
}

function extractVulners(scripts) {
  const vulnScript = scripts.find((s) => s.$.id === "vulners");
  if (!vulnScript) return [];

  // vulners NSE outputs lines like: CVE-XXXX-XXXX   9.8   https://…
  const lines = (vulnScript.$.output ?? "").split("\n");
  const vulns = [];

  for (const line of lines) {
    const match = line.match(/\s*(CVE-[\d-]+)\s+([\d.]+)\s+(https?:\/\/\S+)/);
    if (match) {
      vulns.push({
        id:       match[1],
        cvss:     parseFloat(match[2]),
        url:      match[3],
        severity: cvssSeverity(match[2]),
      });
    }
  }

  // De-duplicate and sort by CVSS descending
  const seen = new Set();
  return vulns
    .filter((v) => { if (seen.has(v.id)) return false; seen.add(v.id); return true; })
    .sort((a, b) => b.cvss - a.cvss);
}

function extractOS(parsed) {
  try {
    const osmatch = parsed?.nmaprun?.host?.os?.osmatch;
    if (!osmatch) return null;
    const first = Array.isArray(osmatch) ? osmatch[0] : osmatch;
    return {
      name:     first.$.name,
      accuracy: parseInt(first.$.accuracy, 10),
      family:   first.osclass?.$.osfamily ?? null,
    };
  } catch {
    return null;
  }
}

function buildSummary(ports, os) {
  const allVulns   = ports.flatMap((p) => p.vulns);
  const openPorts  = ports.map((p) => p.port);
  const services   = [...new Set(ports.map((p) => p.service).filter(Boolean))];
  const findings   = allVulns.map((v) => ({ id: v.id, cvss: v.cvss, severity: v.severity, port: null }));

  return {
    openPorts,
    services,
    os,
    totalVulns:       allVulns.length,
    criticalVulns:    allVulns.filter((v) => v.severity === "CRITICAL").length,
    highVulns:        allVulns.filter((v) => v.severity === "HIGH").length,
    topVulns:         allVulns.slice(0, 10),
    findings,
  };
}

// Main processor function (called by BullMQ worker) 

async function processNmap(job) {
  const { jobId, ip } = job.data;

  try {
    await job.updateProgress(5);
    const xmlOutput = await runNmap(ip);

    await job.updateProgress(70);
    const parsed = await parseNmapXml(xmlOutput);

    const ports   = extractPorts(parsed);
    const os      = extractOS(parsed);
    const summary = buildSummary(ports, os);

    // Collect all vulns across ports for severity calc
    const allVulns   = ports.flatMap((p) => p.vulns);
    const allFindings = allVulns.map((v) => ({ severity: v.severity }));
    const severity    = highestSeverity(allFindings);

    await scanStore.saveResult({
      jobId,
      ip,
      scanner:  "nmap",
      raw:      { ports, os, rawXml: xmlOutput.substring(0, 50_000) }, // cap raw XML
      summary,
      severity,
    });

    await job.updateProgress(100);
    logger.info(`[nmap] done for ${ip} — ${ports.length} open ports, ${allVulns.length} vulns, severity: ${severity}`);

    return { scanner: "nmap", ports: ports.length, vulns: allVulns.length, severity };

  } catch (err) {
    logger.error(`[nmap] failed for ${ip}: ${err.message}`);
    throw err; // BullMQ will mark job as failed
  }
}

module.exports = { processNmap };