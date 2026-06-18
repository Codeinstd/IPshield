const puppeteer = require("puppeteer");
const logger     = require("../utils/logger");

// Severity styling shared across the report 
const SEV_COLOR = {
  CRITICAL: "#ff3355",
  HIGH:     "#ff7700",
  MEDIUM:   "#ffcc00",
  LOW:      "#00e87c",
  INFO:     "#00d9ff",
  NONE:     "#6a8fa8",
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"];

function escHtml(str) {
  return String(str ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function sevColor(sev) {
  return SEV_COLOR[(sev ?? "NONE").toUpperCase()] ?? SEV_COLOR.NONE;
}

function highestOf(severities) {
  const present = severities.filter(Boolean).map((s) => s.toUpperCase());
  for (const s of SEV_ORDER) {
    if (present.includes(s)) return s;
  }
  return "NONE";
}

// Data aggregation 
async function buildCaseReportData(caseId, { caseStore, scanStore }) {
  // Confirmed store shape: caseStore.getCase(id) returns the case row already
  // merged with `ips` and `notes` arrays via formatCase() in caseStore.js.
  // There is no separate getCaseIPs — calling one would throw, since the
  // module doesn't export it.
  const caseRecord = await caseStore.getCase(caseId);

  if (!caseRecord) {
    throw new Error(`Case ${caseId} not found`);
  }

  const caseIPs = caseRecord.ips ?? []; // [{ ip, score, risk_level, note, added_at }, ...]

  const ipReports = [];

  for (const entry of caseIPs) {
    const recentScans = await scanStore.getRecentScans(entry.ip, 1);
    const latestScan   = recentScans.find((s) => s.status === "done") ?? null;

    const nmapResult   = latestScan?.results?.find((r) => r.scanner === "nmap")   ?? null;
    const nucleiResult = latestScan?.results?.find((r) => r.scanner === "nuclei") ?? null;

    const overallSeverity = highestOf([
      entry.risk_level,
      nmapResult?.severity,
      nucleiResult?.severity,
    ]);

    ipReports.push({
      ip:               entry.ip,
      caseNote:         entry.note ?? null,
      passiveScore:     entry.score ?? null,
      passiveRiskLevel: entry.risk_level ?? null,
      scanJobId:        latestScan?.job_id ?? null,
      scanCompletedAt:  latestScan?.completed_at ?? null,
      scanned:          !!latestScan,
      nmap:             nmapResult,
      nuclei:           nucleiResult,
      overallSeverity,
    });
  }

  // Sort IPs by severity, most severe first
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, NONE: 5 };
  ipReports.sort((a, b) => (sevRank[a.overallSeverity] ?? 5) - (sevRank[b.overallSeverity] ?? 5));

  return { caseRecord, ipReports };
}

// Executive summary calculations 
function buildExecutiveSummary(ipReports) {
  const total       = ipReports.length;
  const scannedCount = ipReports.filter((r) => r.scanned).length;
  const unscannedCount = total - scannedCount;

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, NONE: 0 };
  ipReports.forEach((r) => { bySeverity[r.overallSeverity]++; });

  const allCves = new Set();
  ipReports.forEach((r) => {
    (r.nmap?.summary?.topVulns ?? []).forEach((v) => allCves.add(v.id));
    (r.nuclei?.summary?.cves ?? []).forEach((c) => allCves.add(c));
  });

  const totalOpenPorts = ipReports.reduce(
    (sum, r) => sum + (r.nmap?.summary?.openPorts?.length ?? 0), 0
  );

  return {
    total,
    scannedCount,
    unscannedCount,
    bySeverity,
    uniqueCveCount: allCves.size,
    cveList: [...allCves],
    totalOpenPorts,
  };
}

// HTML template
function buildReportHTML({ caseRecord, ipReports }) {
  const summary    = buildExecutiveSummary(ipReports);
  const generatedAt = new Date().toLocaleString("en-US", {
    dateStyle: "long", timeStyle: "short",
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Assessment Report — Case #${caseRecord.id}</title>
<style>
  @page { size: A4; margin: 22mm 18mm; }
  * { box-sizing: border-box; }
  body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    color: #1a1f26;
    font-size: 11px;
    line-height: 1.6;
  }
  .cover {
    page-break-after: always;
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 240mm;
    text-align: center;
  }
  .cover-badge {
    display: inline-block;
    margin: 0 auto 24px;
    padding: 6px 18px;
    border: 1px solid #ffcc00;
    border-radius: 20px;
    color: #8a6d00;
    background: #fff8e1;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
  }
  .cover h1 {
    font-size: 30px;
    font-weight: 800;
    margin-bottom: 10px;
    color: #0d1117;
  }
  .cover .case-title { font-size: 16px; color: #4a6278; margin-bottom: 40px; }
  .cover-meta { font-size: 11px; color: #6a8fa8; }
  .cover-meta div { margin-bottom: 4px; }
  .disclaimer-box {
    margin: 40px auto 0;
    max-width: 460px;
    padding: 16px 20px;
    border: 1px solid #ffcc00;
    background: #fffbe6;
    border-radius: 8px;
    font-size: 10px;
    color: #6b5800;
    text-align: left;
    line-height: 1.7;
  }
  .disclaimer-box strong { color: #4a3b00; }

  h2 {
    font-size: 16px;
    font-weight: 800;
    color: #0d1117;
    margin: 28px 0 12px;
    padding-bottom: 6px;
    border-bottom: 2px solid #0d1117;
  }
  h3 { font-size: 13px; font-weight: 700; margin: 18px 0 8px; color: #0d1117; }

  .summary-grid {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
  }
  .summary-card {
    flex: 1;
    padding: 12px;
    border: 1px solid #e0e6eb;
    border-radius: 6px;
    text-align: center;
  }
  .summary-card .val { font-size: 22px; font-weight: 800; }
  .summary-card .lbl { font-size: 9px; color: #6a8fa8; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 10px; }
  th {
    background: #f4f6f8;
    padding: 7px 10px;
    text-align: left;
    font-size: 9px;
    letter-spacing: 0.5px;
    color: #4a6278;
    border-bottom: 1px solid #d0dae6;
  }
  td { padding: 7px 10px; border-bottom: 1px solid #eef2f5; vertical-align: top; }
  tr:last-child td { border-bottom: none; }

  .sev-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: #fff;
  }
  .ip-section { page-break-inside: avoid; margin-bottom: 22px; }
  .ip-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: #f4f6f8;
    border-radius: 6px 6px 0 0;
    border: 1px solid #e0e6eb;
  }
  .ip-header .ip { font-family: monospace; font-weight: 700; font-size: 13px; }
  .ip-body { border: 1px solid #e0e6eb; border-top: none; border-radius: 0 0 6px 6px; padding: 12px 14px; }
  .not-scanned-note {
    font-size: 10px; color: #6a8fa8; font-style: italic;
    padding: 8px 0;
  }
  .port-chip {
    display: inline-block;
    padding: 2px 8px;
    margin: 2px;
    border-radius: 4px;
    background: #eef7fb;
    color: #0099bb;
    font-family: monospace;
    font-size: 10px;
    border: 1px solid #cbe9f2;
  }
  .finding-row { border-left: 3px solid #e0e6eb; padding: 6px 10px; margin-bottom: 6px; background: #fafbfc; }
  footer-note { font-size: 9px; color: #8fa8bc; }
  .page-footer {
    position: fixed;
    bottom: 8mm;
    font-size: 8px;
    color: #8fa8bc;
  }
</style>
</head>
<body>

  <!-- Cover page -->
  <div class="cover">
    <div class="cover-badge">VULNERABILITY ASSESSMENT REPORT</div>
    <h1>IPShield Security Assessment</h1>
    <div class="case-title">Case #${caseRecord.id} — ${escHtml(caseRecord.title)}</div>
    <div class="cover-meta">
      <div>Generated: ${generatedAt}</div>
      <div>Case severity: ${escHtml(caseRecord.severity ?? "—")}  ·  Status: ${escHtml(caseRecord.status ?? "—")}</div>
      <div>Assigned analyst: ${escHtml(caseRecord.assigned_to ?? "—")}</div>
      <div>Targets assessed: ${summary.total}</div>
    </div>

    <div class="disclaimer-box">
      <strong>Scope and methodology note:</strong> This report presents results from automated
      vulnerability scanning (nmap service/version detection with CVE matching, and nuclei
      template-based detection). Findings are signature-based and have not been manually
      validated or exploited. This is <strong>not</strong> a penetration test report — it does not
      include manual testing, exploitation attempts, or business-logic analysis. Treat all findings
      as candidates for manual verification before remediation prioritisation or compliance use.
    </div>
  </div>

  <!-- Executive summary -->
  <h2>Executive Summary</h2>
  <p>This assessment covers <strong>${summary.total}</strong> IP address${summary.total !== 1 ? "es" : ""}
    attached to case <strong>#${caseRecord.id}</strong>. ${summary.scannedCount} of ${summary.total}
    target${summary.total !== 1 ? "s" : ""} have completed active scan data;
    ${summary.unscannedCount} ${summary.unscannedCount === 1 ? "has" : "have"} not yet been scanned
    and are included for completeness using passive intelligence only.</p>

  <div class="summary-grid">
    ${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => `
      <div class="summary-card">
        <div class="val" style="color:${sevColor(sev)};">${summary.bySeverity[sev]}</div>
        <div class="lbl">${sev}</div>
      </div>`).join("")}
    <div class="summary-card">
      <div class="val" style="color:#0d1117;">${summary.uniqueCveCount}</div>
      <div class="lbl">Unique CVEs</div>
    </div>
    <div class="summary-card">
      <div class="val" style="color:#0d1117;">${summary.totalOpenPorts}</div>
      <div class="lbl">Open Ports (total)</div>
    </div>
  </div>

  ${summary.cveList.length ? `
    <h3>CVEs Identified Across Assessment</h3>
    <p>${summary.cveList.map((c) => escHtml(c)).join(", ")}</p>
  ` : ""}

  <!-- Per-IP findings -->
  <h2>Detailed Findings by Target</h2>

  ${ipReports.map((r) => buildIPSection(r)).join("")}

  <!-- Methodology -->
  <h2>Methodology</h2>
  <p>Active scans were performed using two open-source tools, run in parallel per target:</p>
  <table>
    <thead><tr><th>Tool</th><th>Purpose</th><th>Scope</th></tr></thead>
    <tbody>
      <tr>
        <td><strong>nmap</strong></td>
        <td>Port scanning, service/version fingerprinting, CVE matching via the vulners NSE script</td>
        <td>Ports 1–10000, safe default scripts only</td>
      </tr>
      <tr>
        <td><strong>nuclei</strong></td>
        <td>Template-based detection of misconfigurations, exposures, outdated TLS, default credentials</td>
        <td>Tags: network, ssl, tls, misconfig, exposure, default-login, takeover, tech — excludes fuzzing, dos, code and intrusive templates</td>
      </tr>
    </tbody>
  </table>
  <p>All scans were initiated with explicit operator consent and were not run against private or
    reserved IP ranges. Findings reflect automated signature matches only.</p>

  <h2>Recommendations</h2>
  <ul>
    <li>Manually verify all CRITICAL and HIGH severity findings before remediation or disclosure.</li>
    <li>Prioritise patching for any service with a matched CVE with CVSS ≥ 7.0.</li>
    <li>Where TLS/SSL findings appear, confirm minimum protocol version and cipher suite policy.</li>
    <li>Re-scan after remediation to confirm findings are resolved.</li>
    <li>If formal compliance attestation is required, engage a certified penetration tester for
      manual validation — this report does not substitute for one.</li>
  </ul>

</body>
</html>`;
}

function buildIPSection(r) {
  const headerColor = sevColor(r.overallSeverity);

  if (!r.scanned) {
    return `
    <div class="ip-section">
      <div class="ip-header" style="border-left: 4px solid ${headerColor};">
        <span class="ip">${escHtml(r.ip)}</span>
        <span class="sev-badge" style="background:${headerColor};">${r.overallSeverity}</span>
        <span style="margin-left:auto;font-size:10px;color:#6a8fa8;">Passive score: ${r.passiveScore ?? "—"}</span>
      </div>
      <div class="ip-body">
        <div class="not-scanned-note">
          No completed active scan on record for this IP. Severity reflects passive risk score only.
          ${r.caseNote ? `<br>Case note: ${escHtml(r.caseNote)}` : ""}
        </div>
      </div>
    </div>`;
  }

  const nmapSum   = r.nmap?.summary   ?? {};
  const nucleiSum = r.nuclei?.summary ?? {};
  const ports     = nmapSum.openPorts ?? [];
  const topVulns  = nmapSum.topVulns  ?? [];
  const findings  = nucleiSum.topFindings ?? [];

  return `
    <div class="ip-section">
      <div class="ip-header" style="border-left: 4px solid ${headerColor};">
        <span class="ip">${escHtml(r.ip)}</span>
        <span class="sev-badge" style="background:${headerColor};">${r.overallSeverity}</span>
        <span style="margin-left:auto;font-size:10px;color:#6a8fa8;">
          Scanned: ${r.scanCompletedAt ? new Date(r.scanCompletedAt).toLocaleDateString() : "—"}
        </span>
      </div>
      <div class="ip-body">
        ${r.caseNote ? `<p style="font-size:10px;color:#6a8fa8;margin-bottom:10px;"><strong>Case note:</strong> ${escHtml(r.caseNote)}</p>` : ""}

        ${ports.length ? `
          <h3 style="margin-top:0;">Open Ports (${ports.length})</h3>
          <div>${ports.map((p) => `<span class="port-chip">${p}</span>`).join("")}</div>
        ` : `<p style="font-size:10px;color:#00e87c;">No open ports detected in scanned range.</p>`}

        ${nmapSum.os ? `
          <p style="font-size:10px;margin-top:8px;">
            <strong>OS fingerprint:</strong> ${escHtml(nmapSum.os.name)} (${nmapSum.os.accuracy}% confidence)
          </p>` : ""}

        ${topVulns.length ? `
          <h3>CVEs (nmap / vulners)</h3>
          <table>
            <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th></tr></thead>
            <tbody>
              ${topVulns.map((v) => `
                <tr>
                  <td style="font-family:monospace;">${escHtml(v.id)}</td>
                  <td>${v.cvss}</td>
                  <td><span class="sev-badge" style="background:${sevColor(v.severity)};">${v.severity}</span></td>
                </tr>`).join("")}
            </tbody>
          </table>
        ` : ""}

        ${findings.length ? `
          <h3>Nuclei Findings</h3>
          ${findings.map((f) => `
            <div class="finding-row" style="border-left-color:${sevColor(f.severity)};">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:3px;">
                <span class="sev-badge" style="background:${sevColor(f.severity)};">${f.severity}</span>
                <strong style="font-size:10px;">${escHtml(f.templateName)}</strong>
                ${f.cve ? `<span style="font-size:9px;color:#ff3355;font-family:monospace;">${escHtml(f.cve)}</span>` : ""}
              </div>
              ${f.matched ? `<div style="font-size:9px;color:#0099bb;font-family:monospace;">${escHtml(f.matched)}</div>` : ""}
              ${f.description ? `<div style="font-size:9px;color:#6a8fa8;margin-top:2px;">${escHtml(f.description.slice(0, 220))}</div>` : ""}
            </div>`).join("")}
        ` : ""}

        ${!topVulns.length && !findings.length ? `
          <p style="font-size:10px;color:#00e87c;margin-top:8px;">No vulnerabilities or notable findings detected for this target.</p>
        ` : ""}
      </div>
    </div>`;
}

// PDF rendering via puppeteer 
async function renderPdfFromHtml(html) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });

    const pdf = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "22mm", bottom: "18mm", left: "18mm", right: "18mm" },
    });

    return pdf;
  } finally {
    await browser.close();
  }
}

// Public entry point 
async function generateVulnReport(caseId, format, deps) {
  const { caseStore, scanStore } = deps;
  if (!caseStore || !scanStore) {
    throw new Error("generateVulnReport requires { caseStore, scanStore } in deps");
  }

  const data = await buildCaseReportData(caseId, { caseStore, scanStore });
  const html = buildReportHTML(data);

  if (format === "html") {
    return { html };
  }

  if (format === "pdf") {
    logger.info(`[vulnReport] Rendering PDF for case ${caseId}`);
    const pdf = await renderPdfFromHtml(html);
    return { pdf };
  }

  throw new Error(`Unknown format: ${format}`);
}

module.exports = { generateVulnReport };