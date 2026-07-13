
const puppeteer = require("puppeteer");
const db        = require("../store/db");

// Fetch score history for this IP from audit_log 
async function getIPHistory(ip, limit = 10) {
  try {
    const res = await db.query(
      `SELECT score, risk_level, scored_at
       FROM audit_log
       WHERE ip = $1
       ORDER BY scored_at DESC
       LIMIT $2`,
      [ip, limit]
    );
    return res.rows;
  } catch {
    return [];
  }
}

// Build the full HTML report 
function buildReportHTML(data, history) {
  const {
    ip, score, riskLevel, action,
    geo = {}, network = {}, rdns = {},
    intelligence = {}, threatFeeds = {},
    signals = [], blacklisted = null,
    meta = {},
  } = data;

  const generatedAt = new Date().toUTCString();
  const scoredAt    = meta.scoredAt ? new Date(meta.scoredAt).toUTCString() : generatedAt;

  const RISK_COLOR = {
    CRITICAL: "#ff3355",
    HIGH:     "#ff7700",
    MEDIUM:   "#ffcc00",
    LOW:      "#00e87c",
  };
  const ACTION_COLOR = {
    BLOCK:     "#ff3355",
    CHALLENGE: "#ff7700",
    MONITOR:   "#ffcc00",
    ALLOW:     "#00e87c",
  };

  const riskColor   = RISK_COLOR[riskLevel]   || "#6a8fa8";
  const actionColor = ACTION_COLOR[action]     || "#6a8fa8";

  function esc(str) {
    return String(str ?? "—")
      .replace(/&/g,"&amp;")
      .replace(/</g,"&lt;")
      .replace(/>/g,"&gt;");
  }

  function badge(val, color) {
    return `<span style="display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1px;background:${color}22;color:${color};border:1px solid ${color}44;">${esc(val)}</span>`;
  }

  function boolRow(label, value, trueColor = "#00e87c", falseColor = "#3d5a72") {
    const color = value ? trueColor : falseColor;
    const text  = value ? "YES" : "NO";
    return `<tr><td>${esc(label)}</td><td>${badge(text, color)}</td></tr>`;
  }

  function row(label, value) {
    return `<tr><td>${esc(label)}</td><td>${esc(value)}</td></tr>`;
  }

  // Score arc SVG
  const pct     = Math.min(score, 100) / 100;
  const radius  = 54;
  const circ    = 2 * Math.PI * radius;
  const offset  = circ * (1 - pct);

  // Threat feed flags
  const feeds = [
    threatFeeds.feodo            && "Feodo Tracker (C2)",
    threatFeeds.spamhaus         && "Spamhaus DROP",
    threatFeeds.emergingThreats  && "Emerging Threats",
    threatFeeds.otx?.pulseCount  && `AlienVault OTX (${threatFeeds.otx.pulseCount} pulses)`,
  ].filter(Boolean);

  // History sparkline
  const histScores = history.map(h => h.score);
  const sparkMax   = Math.max(...histScores, 100);
  const sparkW     = 280;
  const sparkH     = 48;
  const sparkPoints = histScores.length > 1
    ? histScores.map((s, i) => {
        const x = (i / (histScores.length - 1)) * sparkW;
        const y = sparkH - (s / sparkMax) * sparkH;
        return `${x},${y}`;
      }).join(" ")
    : null;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>IPShield Threat Intelligence Report — ${ip}</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-W7LXC9M274"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-W7LXC9M274');
</script>
<meta name="google-site-verification" content="WhmK3MH3Co3Wu72eOPEMMp5B8vtkFiVcoCP7Js4HGkA" />
<link rel="icon" type="image/png" sizes="32x32" href="/favicon.ico/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="96x96" href="/favicon.ico/favicon-96x96.png">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon.ico/favicon-16x16.png">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #080c0f;
    --bg1:     #0d1117;
    --bg2:     #111820;
    --border:  #1e2d3d;
    --accent:  #00d9ff;
    --text:    #c9d8e8;
    --text2:   #6a8fa8;
    --text3:   #3d5a72;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    line-height: 1.6;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  /* ── Page layout ── */
  .page {
    max-width: 900px;
    margin: 0 auto;
    padding: 48px 40px;
  }

  /* ── Header ── */
  .report-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    padding-bottom: 28px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 36px;
  }
  .logo-block { display: flex; align-items: center; gap: 12px; }
  .logo-icon {
    width: 40px; height: 40px;
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    color: var(--accent); font-size: 22px;
  }
  .logo-text { font-family: 'Syne', sans-serif; font-size: 24px; font-weight: 800; color: var(--text); }
  .logo-text span { color: var(--accent); }
  .logo-sub { font-size: 9px; color: var(--text3); letter-spacing: 3px; margin-top: 2px; }
  .report-meta { text-align: right; font-size: 11px; color: var(--text3); line-height: 1.8; }
  .report-meta strong { color: var(--text2); }

  /* ── Hero score block ── */
  .score-hero {
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 32px;
    align-items: center;
    background: var(--bg1);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px 32px;
    margin-bottom: 32px;
  }
  .score-arc { text-align: center; }
  .score-arc svg { display: block; margin: 0 auto; }
  .score-num {
    font-family: 'Syne', sans-serif;
    font-size: 42px;
    font-weight: 800;
    line-height: 1;
    color: ${riskColor};
  }
  .score-label { font-size: 10px; color: var(--text3); letter-spacing: 2px; margin-top: 4px; }
  .ip-block .ip-addr {
    font-family: 'Syne', sans-serif;
    font-size: 26px;
    font-weight: 800;
    color: var(--text);
    margin-bottom: 10px;
  }
  .ip-meta { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
  .ip-summary { font-size: 12px; color: var(--text2); line-height: 1.8; }
  .action-block { text-align: center; }
  .action-label { font-size: 9px; color: var(--text3); letter-spacing: 2px; margin-bottom: 10px; }
  .action-pill {
    display: inline-block;
    padding: 14px 22px;
    border-radius: 10px;
    font-family: 'Inter', sans-serif;
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 1px;
    color: ${actionColor};
    background: ${actionColor}18;
    border: 2px solid ${actionColor}66;
  }

  /* ── Sections ── */
  .section { margin-bottom: 32px; }
  .section-title {
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* ── Data tables ── */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .data-table td {
    padding: 9px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .data-table tr:last-child td { border-bottom: none; }
  .data-table td:first-child {
    color: var(--text3);
    width: 180px;
    font-size: 11px;
    letter-spacing: 0.5px;
  }
  .data-table td:last-child { color: var(--text); }
  .data-table tbody { background: var(--bg1); }
  .data-table tbody tr:hover { background: var(--bg2); }

  /* ── Two-column grid ── */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

  /* ── Signal cards ── */
  .signals-grid { display: flex; flex-direction: column; gap: 10px; }
  .signal-card {
    padding: 12px 16px;
    border-radius: 8px;
    border-left: 3px solid;
    background: var(--bg1);
    border-color: var(--border);
  }
  .signal-card.critical { border-color: #ff3355; background: rgba(255,51,85,0.06); }
  .signal-card.high     { border-color: #ff7700; background: rgba(255,119,0,0.06); }
  .signal-card.medium   { border-color: #ffcc00; background: rgba(255,204,0,0.05); }
  .signal-card.low      { border-color: #00e87c; background: rgba(0,232,124,0.05); }
  .signal-cat { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 3px; }
  .signal-detail { font-size: 11px; color: var(--text2); }

  /* ── Feed hit pills ── */
  .feed-hits { display: flex; flex-direction: column; gap: 8px; }
  .feed-hit {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 14px;
    background: rgba(255,51,85,0.08);
    border: 1px solid rgba(255,51,85,0.25);
    border-radius: 8px;
    font-size: 12px;
    color: #ff3355;
  }
  .feed-miss {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 14px;
    background: rgba(0,232,124,0.06);
    border: 1px solid rgba(0,232,124,0.2);
    border-radius: 8px;
    font-size: 12px;
    color: #00e87c;
  }

  /* ── History sparkline ── */
  .sparkline-wrap {
    background: var(--bg1);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
  }
  .sparkline-header {
    display: flex; justify-content: space-between;
    align-items: center; margin-bottom: 14px;
    font-size: 11px; color: var(--text3);
  }
  .history-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
  }
  .history-row:last-child { border-bottom: none; }

  /* ── Blacklist alert ── */
  .blacklist-alert {
    padding: 16px 20px;
    background: rgba(255,51,85,0.08);
    border: 1px solid rgba(255,51,85,0.3);
    border-radius: 10px;
    margin-bottom: 20px;
  }
  .blacklist-alert-title {
    font-weight: 700; color: #ff3355;
    font-size: 13px; margin-bottom: 8px;
  }

  /* ── Ports & CVEs ── */
  .port-chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .port-chip {
    padding: 3px 10px; border-radius: 4px;
    background: rgba(0,217,255,0.1);
    border: 1px solid rgba(0,217,255,0.2);
    color: var(--accent); font-size: 11px;
  }
  .cve-chip {
    padding: 3px 10px; border-radius: 4px;
    background: rgba(255,51,85,0.1);
    border: 1px solid rgba(255,51,85,0.2);
    color: #ff3355; font-size: 11px;
  }

  /* ── Footer ── */
  .report-footer {
    margin-top: 48px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    font-size: 10px;
    color: var(--text3);
  }

  /* ── Watermark / confidential ── */
  .confidential-banner {
    text-align: center;
    padding: 8px;
    background: rgba(255,204,0,0.06);
    border-bottom: 1px solid rgba(255,204,0,0.2);
    font-size: 10px;
    color: #ffcc00;
    letter-spacing: 3px;
    text-transform: uppercase;
  }

  /* ── Print styles ── */
  @media print {
    body { background: #080c0f !important; }
    .page { padding: 32px 28px; }
    .score-hero { page-break-inside: avoid; }
    .section { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<div class="confidential-banner">⚠ Confidential — For Authorised Personnel Only</div>

<div class="page">

  <!-- ── Header ── -->
  <div class="report-header">
    <div class="logo-block">
      <div class="logo-icon">⬡</div>
      <div>
        <div class="logo-text">IP<span>Shield</span></div>
        <div class="logo-sub">Threat Intelligence Report</div>
      </div>
    </div>
    <div class="report-meta">
      <div><strong>Report ID:</strong> TIR-${Date.now().toString(36).toUpperCase()}</div>
      <div><strong>Generated:</strong> ${generatedAt}</div>
      <div><strong>Scored At:</strong> ${scoredAt}</div>
      <div><strong>Source:</strong> IPShield v2 Intelligence Engine</div>
      ${meta.cached ? '<div><strong>Cache:</strong> Served from cache</div>' : ''}
      ${meta.processingMs ? `<div><strong>Processing:</strong> ${meta.processingMs}ms</div>` : ''}
    </div>
  </div>

  <!-- ── Score Hero ── -->
  <div class="score-hero">
    <div class="score-arc">
      <svg width="130" height="130" viewBox="0 0 130 130">
        <!-- Track -->
        <circle cx="65" cy="65" r="${radius}" fill="none" stroke="#1e2d3d" stroke-width="10"/>
        <!-- Score arc -->
        <circle cx="65" cy="65" r="${radius}" fill="none"
          stroke="${riskColor}" stroke-width="10"
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
          stroke-linecap="round"
          transform="rotate(-90 65 65)"/>
        <!-- Score text -->
        <text x="65" y="60" text-anchor="middle"
          font-family="Syne, sans-serif" font-size="28" font-weight="800"
          fill="${riskColor}">${score}</text>
        <text x="65" y="76" text-anchor="middle"
          font-family="JetBrains Mono, monospace" font-size="9"
          fill="#3d5a72" letter-spacing="2">/ 100</text>
      </svg>
      <div style="font-size:11px;color:${riskColor};font-weight:700;letter-spacing:2px;margin-top:6px;">${riskLevel}</div>
    </div>

    <div class="ip-block">
      <div class="ip-addr">${esc(ip)}</div>
      <div class="ip-meta">
        ${badge(riskLevel, riskColor)}
        ${geo.country ? badge(geo.country, "#6a8fa8") : ""}
        ${intelligence.isTor        ? badge("TOR EXIT", "#ff3355") : ""}
        ${intelligence.isProxy      ? badge("PROXY",    "#ff7700") : ""}
        ${intelligence.isDatacenter ? badge("DATACENTER","#6a8fa8") : ""}
        ${blacklisted ? badge("BLACKLISTED", "#ff3355") : ""}
      </div>
      <div class="ip-summary">
        ${geo.city || "—"}, ${geo.country || "—"} &nbsp;·&nbsp;
        ${network.isp || "Unknown ISP"} &nbsp;·&nbsp;
        ASN: ${network.asn || "—"}
        ${rdns.primary ? `<br>rDNS: ${esc(rdns.primary)} ${rdns.fcrdns ? "(FCrDNS ✓)" : "(FCrDNS ✗)"}` : ""}
      </div>
    </div>

    <div class="action-block">
      <div class="action-label">RECOMMENDED ACTION</div>
      <div class="action-pill">${esc(action)}</div>
    </div>
  </div>

  <!-- ── Blacklist Alert ── -->
  ${blacklisted ? `
  <div class="blacklist-alert">
    <div class="blacklist-alert-title">⚠ IP is on Internal Blacklist</div>
    <table class="data-table"><tbody>
      ${row("Severity",   blacklisted.severity)}
      ${row("Category",   blacklisted.category)}
      ${row("Reason",     blacklisted.reason)}
      ${row("Added By",   blacklisted.added_by)}
      ${row("Added At",   blacklisted.added_at ? new Date(blacklisted.added_at).toUTCString() : "—")}
      ${row("Expires",    blacklisted.expires_at ? new Date(blacklisted.expires_at).toUTCString() : "Never")}
      ${blacklisted.tags?.length ? row("Tags", blacklisted.tags.join(", ")) : ""}
    </tbody></table>
  </div>` : ""}

  <!-- ── Two column: Geo + Network ── -->
  <div class="two-col">
    <div class="section">
      <div class="section-title">🌍 Geolocation</div>
      <table class="data-table"><tbody>
        ${row("Country",  geo.country)}
        ${row("Region",   geo.region)}
        ${row("City",     geo.city)}
        ${row("Timezone", geo.timezone)}
        ${geo.lat ? row("Coordinates", `${geo.lat}, ${geo.lon}`) : ""}
      </tbody></table>
    </div>
    <div class="section">
      <div class="section-title">🔌 Network</div>
      <table class="data-table"><tbody>
        ${row("ISP",      network.isp)}
        ${row("ASN",      network.asn)}
        ${row("Type",     network.type)}
        ${rdns.primary ? row("rDNS",   rdns.primary) : ""}
        ${rdns.fcrdns != null ? row("FCrDNS", rdns.fcrdns ? "Verified ✓" : "Failed ✗") : ""}
      </tbody></table>
    </div>
  </div>

  <!-- ── Intelligence flags ── -->
  <div class="section">
    <div class="section-title">🔍 Intelligence Flags</div>
    <div class="two-col">
      <table class="data-table"><tbody>
        ${boolRow("Tor Exit Node",   intelligence.isTor,        "#ff3355", "#00e87c")}
        ${boolRow("Proxy / VPN",     intelligence.isProxy,      "#ff7700", "#00e87c")}
        ${boolRow("Datacenter IP",   intelligence.isDatacenter, "#6a8fa8", "#00e87c")}
      </tbody></table>
      <table class="data-table"><tbody>
        ${row("Velocity",  intelligence.velocity || "—")}
        ${intelligence.virusTotal ? row("VirusTotal", `${intelligence.virusTotal.malicious} malicious / ${intelligence.virusTotal.total} engines`) : ""}
        ${intelligence.shodanTags?.length ? row("Shodan Tags", intelligence.shodanTags.join(", ")) : ""}
      </tbody></table>
    </div>
  </div>

  <!-- ── Open ports & CVEs ── -->
  ${(intelligence.openPorts?.length || intelligence.vulns?.length) ? `
  <div class="section">
    <div class="section-title">⚠ Shodan — Ports & Vulnerabilities</div>
    ${intelligence.openPorts?.length ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:10px;color:var(--text3);letter-spacing:1px;margin-bottom:8px;">OPEN PORTS</div>
      <div class="port-chips">
        ${intelligence.openPorts.map(p => `<span class="port-chip">${p}</span>`).join("")}
      </div>
    </div>` : ""}
    ${intelligence.vulns?.length ? `
    <div>
      <div style="font-size:10px;color:var(--text3);letter-spacing:1px;margin-bottom:8px;">CVEs (${intelligence.vulns.length})</div>
      <div class="port-chips">
        ${intelligence.vulns.map(v => `<span class="cve-chip">${esc(v)}</span>`).join("")}
      </div>
    </div>` : ""}
  </div>` : ""}

  <!-- ── Threat feeds ── -->
  <div class="section">
    <div class="section-title">📡 Threat Feed Results</div>
    <div class="feed-hits">
      ${feeds.length > 0
        ? feeds.map(f => `<div class="feed-hit">⚠ Listed on <strong>${esc(f)}</strong></div>`).join("")
        : '<div class="feed-miss">✓ Not found on any monitored threat feed</div>'}
      ${threatFeeds.otx && !threatFeeds.otx.pulseCount
        ? '<div class="feed-miss">✓ AlienVault OTX — No pulses</div>'
        : ""}
    </div>
    ${threatFeeds.otx?.pulseNames?.length ? `
    <div style="margin-top:12px;font-size:11px;color:var(--text2);">
      <div style="color:var(--text3);letter-spacing:1px;font-size:10px;margin-bottom:6px;">OTX PULSE NAMES</div>
      ${threatFeeds.otx.pulseNames.slice(0, 5).map(n => `<div>· ${esc(n)}</div>`).join("")}
    </div>` : ""}
  </div>

  <!-- ── Risk signals ── -->
  ${signals.length ? `
  <div class="section">
    <div class="section-title">⚡ Risk Signals (${signals.length})</div>
    <div class="signals-grid">
      ${signals.map(s => `
        <div class="signal-card ${(s.severity || "").toLowerCase()}">
          <div class="signal-cat" style="color:${RISK_COLOR[s.severity?.toUpperCase()] || "#6a8fa8"};">${esc(s.category)} · ${esc(s.severity)}</div>
          <div class="signal-detail">${esc(s.detail)}</div>
        </div>`).join("")}
    </div>
  </div>` : ""}

  <!-- ── Score history ── -->
  ${history.length ? `
  <div class="section">
    <div class="section-title">📈 Score History (Last ${history.length} Scans)</div>
    <div class="sparkline-wrap">
      ${sparkPoints ? `
      <div class="sparkline-header">
        <span>Score trend</span>
        <span>Min: ${Math.min(...histScores)} · Max: ${Math.max(...histScores)} · Latest: ${histScores[0]}</span>
      </div>
      <svg width="${sparkW}" height="${sparkH}" style="display:block;margin-bottom:16px;">
        <polyline
          points="${sparkPoints}"
          fill="none"
          stroke="${riskColor}"
          stroke-width="2"
          stroke-linejoin="round"
          stroke-linecap="round"/>
        ${histScores.map((s, i) => {
          const x = (i / (histScores.length - 1)) * sparkW;
          const y = sparkH - (s / sparkMax) * sparkH;
          return `<circle cx="${x}" cy="${y}" r="3" fill="${riskColor}"/>`;
        }).join("")}
      </svg>` : ""}
      ${history.map(h => `
        <div class="history-row">
          <span style="color:var(--text2);">${new Date(h.scored_at).toUTCString()}</span>
          <span style="color:${RISK_COLOR[h.risk_level] || "#6a8fa8"};font-weight:700;">${h.score} — ${h.risk_level}</span>
        </div>`).join("")}
    </div>
  </div>` : ""}

  <!-- ── Summary / Analyst notes ── -->
  <div class="section">
    <div class="section-title">📋 Executive Summary</div>
    <div style="background:var(--bg1);border:1px solid var(--border);border-radius:10px;padding:20px;font-size:13px;color:var(--text2);line-height:1.9;">
      IP address <strong style="color:var(--text);">${esc(ip)}</strong>
      has been assigned a risk score of <strong style="color:${riskColor};">${score}/100</strong>
      with a classification of <strong style="color:${riskColor};">${riskLevel}</strong>.
      The recommended action is <strong style="color:${actionColor};">${esc(action)}</strong>.
      <br><br>
      ${geo.country ? `The IP originates from <strong style="color:var(--text);">${esc(geo.city || "")}, ${esc(geo.country)}</strong> and is operated by <strong style="color:var(--text);">${esc(network.isp || "Unknown")}</strong> (${esc(network.asn || "Unknown ASN")}).` : ""}
      ${intelligence.isTor        ? " The IP has been identified as a <strong style=\"color:#ff3355;\">Tor exit node</strong>." : ""}
      ${intelligence.isProxy      ? " The IP is flagged as a <strong style=\"color:#ff7700;\">proxy or VPN endpoint</strong>." : ""}
      ${intelligence.isDatacenter ? " The IP is hosted in a <strong style=\"color:#6a8fa8;\">datacenter</strong>." : ""}
      ${feeds.length > 0 ? ` <strong style="color:#ff3355;">Active threat feed listings were found</strong> (${feeds.join(", ")}).` : " No active threat feed listings were found."}
      ${intelligence.vulns?.length ? ` <strong style="color:#ff3355;">${intelligence.vulns.length} CVE(s)</strong> were identified on open ports via Shodan.` : ""}
      ${blacklisted ? ` This IP is currently on the <strong style="color:#ff3355;">internal blacklist</strong> (Severity: ${esc(blacklisted.severity)}).` : ""}
    </div>
  </div>

  <!-- ── Footer ── -->
  <div class="report-footer">
    <div>IPShield Threat Intelligence · ipshield.live</div>
    <div>Report ID: TIR-${Date.now().toString(36).toUpperCase()} · Generated ${generatedAt}</div>
  </div>

</div>
</body>
</html>`;
}

// Generate PDF from HTML using puppeteer 
async function generatePDF(html) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
    ],
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });

    const pdf = await page.pdf({
      format:               "A4",
      printBackground:      true,
      margin: { top: "0", right: "0", bottom: "0", left: "0" },
      displayHeaderFooter:  false,
    });

    return pdf;
  } finally {
    await browser.close();
  }
}

// Main export 
async function generateReport(scoreResult, format = "html") {
  const history = await getIPHistory(scoreResult.ip);
  const html    = buildReportHTML(scoreResult, history);

  if (format === "pdf") {
    const pdf = await generatePDF(html);
    return { pdf, html };
  }

  return { html };
}

module.exports = { generateReport };