const express = require("express");
const router  = express.Router();
const spec    = require("../config/openapi");

// Raw spec for Postman/external tools
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json(spec);
});

// Custom docs UI
router.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(buildDocsHTML(spec));
});

function buildDocsHTML(spec) {
  const endpoints = buildEndpoints(spec);
  const endpointsJSON = JSON.stringify(endpoints);
  const specJSON = JSON.stringify(spec);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPShield Docs</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:       #080c0f;
      --bg1:      #0d1117;
      --bg2:      #111820;
      --bg3:      #1a2535;
      --accent:   #00d9ff;
      --accent2:  #0099bb;
      --low:      #00e87c;
      --medium:   #ffcc00;
      --high:     #ff7700;
      --critical: #ff3355;
      --text:     #c9d8e8;
      --text2:    #8fa8bc;
      --text3:    #4a6278;
      --border:   #1e2d3d;
      --border2:  #2a3d52;
      --get:      #00e87c;
      --post:     #ffcc00;
      --put:      #00aaff;
      --delete:   #ff3355;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'JetBrains Mono', monospace;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* ── Header ── */
    .header {
      background: var(--bg1);
      border-bottom: 1px solid var(--border);
      padding: 0 32px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
      font-family: 'Syne'
    }

    .logo { display: flex; align-items: center; gap: 12px; }
    .logo-mark {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, var(--accent), #0055aa);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px; font-weight: 800; color: #000;
      font-family: 'JetBrains Mono', monospace;
    }
    .logo-text { font-size: 16px; font-weight: 700; color: var(--text); }
    .logo-text span { color: var(--accent); }
    .logo-badge {
      font-size: 10px; font-weight: 700; letter-spacing: 1px;
      padding: 2px 8px; border-radius: 3px;
      background: rgba(0,217,255,0.12); color: var(--accent);
      border: 1px solid rgba(0,217,255,0.3);
      font-family: 'JetBrains Mono', monospace;
    }

    .header-right { display: flex; align-items: center; gap: 12px; }
    .header-right a, .header-right button {
      font-size: 12px; color: var(--text2); text-decoration: none;
      padding: 6px 14px; border-radius: 6px;
      border: 1px solid var(--border); background: transparent;
      cursor: pointer; font-family: inherit; transition: all 0.2s;
    }
    .header-right a:hover, .header-right button:hover {
      color: var(--accent); border-color: var(--accent);
    }
    .header-right .btn-primary {
      background: var(--accent); color: #000; border-color: var(--accent);
      font-weight: 700;
    }
    .header-right .btn-primary:hover { background: #33e5ff; }

    /* ── Layout ── */
    .layout {
      display: grid;
      grid-template-columns: 260px 1fr;
      flex: 1;
      min-height: 0;
    }

    /* ── Sidebar ── */
    .sidebar {
      background: var(--bg1);
      border-right: 1px solid var(--border);
      padding: 24px 0;
      position: sticky;
      top: 60px;
      height: calc(100vh - 60px);
      overflow-y: auto;
    }

    .sidebar::-webkit-scrollbar { width: 4px; }
    .sidebar::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }

    .sidebar-section { margin-bottom: 8px; }

    .sidebar-label {
      font-size: 9px; font-weight: 700; letter-spacing: 2px;
      color: var(--text3); text-transform: uppercase;
      padding: 8px 20px 4px;
    }

    .sidebar-item {
      display: flex; align-items: center; gap: 10px;
      padding: 7px 20px; cursor: pointer;
      font-size: 12px; color: var(--text2);
      border-left: 2px solid transparent;
      transition: all 0.15s; text-decoration: none;
    }
    .sidebar-item:hover { color: var(--text); background: var(--bg2); }
    .sidebar-item.active {
      color: var(--accent); border-left-color: var(--accent);
      background: rgba(0,217,255,0.05);
    }
    .sidebar-item .method-dot {
      width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0;
    }
    .sidebar-item .endpoint-name {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; flex: 1; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap;
    }

    /* ── Main ── */
    .main { padding: 32px 48px; max-width: 900px; }

    /* ── Hero ── */
    .hero {
      margin-bottom: 48px;
      padding: 40px;
      background: linear-gradient(135deg, var(--bg1) 0%, var(--bg2) 100%);
      border: 1px solid var(--border);
      border-radius: 16px;
      position: relative;
      overflow: hidden;
    }
    .hero::before {
      content: '';
      position: absolute; top: -60px; right: -60px;
      width: 200px; height: 200px;
      background: radial-gradient(circle, rgba(0,217,255,0.08) 0%, transparent 70%);
      border-radius: 50%;
    }
    .hero-badge {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 11px; font-weight: 600; letter-spacing: 1px;
      padding: 4px 12px; border-radius: 20px;
      background: rgba(0,232,124,0.1); color: var(--low);
      border: 1px solid rgba(0,232,124,0.25);
      margin-bottom: 16px; font-family: 'JetBrains Mono', monospace;
    }
    .hero-badge::before { content: '●'; font-size: 8px; }

    .hero h1 {
      font-size: 32px; font-weight: 800; line-height: 1.2;
      margin-bottom: 12px; color: var(--text);
    }
    .hero h1 span { color: var(--accent); }
    .hero p { font-size: 14px; color: var(--text2); line-height: 1.7; max-width: 560px; margin-bottom: 24px; }

    .hero-stats {
      display: flex; gap: 24px; flex-wrap: wrap;
    }
    .hero-stat { text-align: center; }
    .hero-stat .num { font-size: 22px; font-weight: 800; color: var(--accent); font-family: 'JetBrains Mono', monospace; }
    .hero-stat .lbl { font-size: 10px; color: var(--text3); letter-spacing: 1px; text-transform: uppercase; }

    /* ── Auth box ── */
    .auth-box {
      padding: 20px 24px;
      background: rgba(0,217,255,0.04);
      border: 1px solid rgba(0,217,255,0.15);
      border-radius: 10px;
      margin-bottom: 32px;
      display: flex; align-items: flex-start; gap: 16px;
    }
    .auth-icon { font-size: 24px; flex-shrink: 0; margin-top: 2px; }
    .auth-title { font-size: 13px; font-weight: 700; color: var(--accent); margin-bottom: 6px; }
    .auth-desc { font-size: 12px; color: var(--text2); line-height: 1.6; }
    .auth-key {
      display: inline-block; margin-top: 8px;
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 6px; padding: 8px 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 12px;
      color: var(--accent); cursor: pointer; user-select: all;
    }

    /* ── Rate limit table ── */
    .rate-table {
      width: 100%; border-collapse: collapse;
      font-size: 12px; margin-top: 8px;
    }
    .rate-table th {
      padding: 8px 12px; text-align: left;
      color: var(--text3); font-size: 10px; letter-spacing: 1px;
      border-bottom: 1px solid var(--border);
    }
    .rate-table td {
      padding: 8px 12px; color: var(--text2);
      border-bottom: 1px solid var(--border);
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
    }
    .rate-table tr:last-child td { border-bottom: none; }

    /* ── Tag group ── */
    .tag-group { margin-bottom: 48px; }
    .tag-header {
      display: flex; align-items: center; gap: 14px;
      margin-bottom: 16px; padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
    }
    .tag-icon {
      width: 38px; height: 38px; border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px; flex-shrink: 0;
    }
    .tag-title { font-size: 20px; font-weight: 700; color: var(--text); }
    .tag-desc { font-size: 12px; color: var(--text2); margin-top: 2px; }

    /* ── Endpoint card ── */
    .endpoint {
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 12px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .endpoint:hover { border-color: var(--border2); }
    .endpoint.open { border-color: var(--border2); }

    .endpoint-header {
      display: flex; align-items: center; gap: 14px;
      padding: 14px 18px; cursor: pointer;
      background: var(--bg1); transition: background 0.15s;
    }
    .endpoint-header:hover { background: var(--bg2); }
    .endpoint.open .endpoint-header { background: var(--bg2); }

    .method-badge {
      font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
      padding: 4px 10px; border-radius: 5px;
      font-family: 'JetBrains Mono', monospace;
      min-width: 60px; text-align: center; flex-shrink: 0;
    }
    .method-GET    { background: rgba(0,232,124,0.15);  color: var(--get);      border: 1px solid rgba(0,232,124,0.3); }
    .method-POST   { background: rgba(255,204,0,0.15);  color: var(--post);     border: 1px solid rgba(255,204,0,0.3); }
    .method-PUT    { background: rgba(0,170,255,0.15);  color: var(--put);      border: 1px solid rgba(0,170,255,0.3); }
    .method-DELETE { background: rgba(255,51,85,0.15);  color: var(--delete);   border: 1px solid rgba(255,51,85,0.3); }

    .endpoint-path {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px; font-weight: 600; color: var(--text); flex: 1;
    }
    .endpoint-path .path-param { color: var(--accent); }
    .endpoint-summary { font-size: 12px; color: var(--text2); flex-shrink: 0; }

    .endpoint-lock {
      font-size: 12px; color: var(--text3); flex-shrink: 0;
    }

    .expand-icon {
      color: var(--text3); font-size: 12px; flex-shrink: 0;
      transition: transform 0.2s;
    }
    .endpoint.open .expand-icon { transform: rotate(180deg); }

    /* ── Endpoint body ── */
    .endpoint-body {
      display: none; padding: 20px 18px;
      border-top: 1px solid var(--border);
      background: var(--bg);
    }
    .endpoint.open .endpoint-body { display: block; }

    .section-label {
      font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
      color: var(--text3); text-transform: uppercase;
      margin-bottom: 10px; margin-top: 16px;
    }
    .section-label:first-child { margin-top: 0; }

    /* Description */
    .endpoint-desc { font-size: 13px; color: var(--text2); line-height: 1.7; }

    /* Parameters */
    .param-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .param-table th {
      padding: 8px 10px; text-align: left;
      color: var(--text3); font-size: 10px; letter-spacing: 1px;
      background: var(--bg2); border-bottom: 1px solid var(--border);
    }
    .param-table td {
      padding: 9px 10px; border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .param-table tr:last-child td { border-bottom: none; }
    .param-name { font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 11px; }
    .param-in   { font-size: 10px; color: var(--text3); background: var(--bg2); padding: 1px 5px; border-radius: 3px; }
    .param-type { font-family: 'JetBrains Mono', monospace; color: var(--medium); font-size: 11px; }
    .param-desc { color: var(--text2); font-size: 11px; }
    .param-req  { color: var(--critical); font-size: 10px; font-weight: 700; }

    /* Try it out */
    .try-section { margin-top: 16px; }
    .try-form { display: flex; flex-direction: column; gap: 10px; }
    .try-row { display: flex; align-items: center; gap: 10px; }
    .try-label { font-size: 11px; color: var(--text3); width: 80px; flex-shrink: 0; font-family: 'JetBrains Mono', monospace; }
    .try-input {
      flex: 1; padding: 8px 12px;
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 6px; color: var(--text);
      font-family: 'JetBrains Mono', monospace; font-size: 12px;
      outline: none; transition: border-color 0.2s;
    }
    .try-input:focus { border-color: var(--accent); }
    .try-input::placeholder { color: var(--text3); }
    textarea.try-input { resize: vertical; min-height: 80px; }

    .try-btn {
      padding: 9px 24px; border-radius: 7px;
      background: var(--accent); color: #000;
      border: none; cursor: pointer; font-weight: 700;
      font-size: 12px; font-family: inherit;
      transition: all 0.2s; letter-spacing: 0.5px;
    }
    .try-btn:hover { background: #33e5ff; transform: translateY(-1px); }
    .try-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

    /* Response */
    .response-box {
      margin-top: 14px;
      border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden;
    }
    .response-header {
      padding: 8px 14px;
      background: var(--bg2);
      display: flex; align-items: center; justify-content: space-between;
      border-bottom: 1px solid var(--border);
    }
    .response-status {
      font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700;
    }
    .status-2xx { color: var(--low); }
    .status-4xx { color: var(--high); }
    .status-5xx { color: var(--critical); }
    .response-time { font-size: 11px; color: var(--text3); font-family: 'JetBrains Mono', monospace; }
    .response-body {
      padding: 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
      color: var(--text2); line-height: 1.7;
      max-height: 320px; overflow-y: auto;
      white-space: pre-wrap; word-break: break-all;
      background: var(--bg);
    }

    /* Response codes */
    .response-codes { display: flex; flex-direction: column; gap: 6px; }
    .response-code {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 12px; border-radius: 6px;
      background: var(--bg2); border: 1px solid var(--border);
    }
    .rc-status {
      font-family: 'JetBrains Mono', monospace; font-size: 12px;
      font-weight: 700; min-width: 36px;
    }
    .rc-200 { color: var(--low); }
    .rc-201 { color: var(--low); }
    .rc-400 { color: var(--high); }
    .rc-401 { color: var(--medium); }
    .rc-404 { color: var(--medium); }
    .rc-409 { color: var(--high); }
    .rc-429 { color: var(--critical); }
    .rc-500 { color: var(--critical); }
    .rc-desc { font-size: 12px; color: var(--text2); }

    /* ── Section cards (overview) ── */
    .overview-cards {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px; margin-bottom: 32px;
    }
    .overview-card {
      padding: 16px 18px;
      background: var(--bg1); border: 1px solid var(--border);
      border-radius: 10px; cursor: pointer; transition: all 0.2s;
      text-decoration: none; display: block;
    }
    .overview-card:hover {
      border-color: var(--accent); background: rgba(0,217,255,0.03);
      transform: translateY(-2px);
    }
    .oc-icon { font-size: 22px; margin-bottom: 8px; }
    .oc-name { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
    .oc-count { font-size: 11px; color: var(--text3); }

    /* ── Copy button ── */
    .copy-btn {
      font-size: 10px; color: var(--text3);
      background: var(--bg3); border: 1px solid var(--border);
      border-radius: 4px; padding: 3px 8px; cursor: pointer;
      font-family: 'JetBrains Mono', monospace; transition: all 0.2s;
    }
    .copy-btn:hover { color: var(--accent); border-color: var(--accent); }

    /* ── Version switcher ── */
    .version-bar {
      display: flex; gap: 6px; align-items: center;
      padding: 12px 24px;
      background: var(--bg2); border-bottom: 1px solid var(--border);
      font-size: 12px;
    }
    .version-bar span { color: var(--text3); }
    .ver-btn {
      padding: 4px 12px; border-radius: 4px;
      font-size: 11px; font-weight: 700; cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      border: 1px solid var(--border); background: transparent;
      color: var(--text2); transition: all 0.2s;
    }
    .ver-btn.active {
      background: rgba(0,217,255,0.1); color: var(--accent);
      border-color: rgba(0,217,255,0.4);
    }
    .ver-btn:hover:not(.active) { color: var(--text); border-color: var(--border2); }

    /* ── Scrollbar ── */
    .response-body::-webkit-scrollbar { width: 4px; }
    .response-body::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }

    /* ── Responsive ── */
    @media (max-width: 768px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { display: none; }
      .main { padding: 20px; }
      .hero { padding: 24px; }
      .hero h1 { font-size: 22px; }
    }
  </style>
</head>
<body>

  <!-- Header -->
  <header class="header">
    <div class="logo">
      <div class="logo-mark">IP</div>
      <div class="logo-text">IP<span>Shield</span></div>
      <div class="logo-badge">API DOCS</div>
    </div>
    <div class="header-right">
      <button onclick="copyApiKey()">🔑 Copy API Key</button>
      <a href="/api/docs/openapi.json" target="_blank">↓ OpenAPI JSON</a>
      <a href="/" class="btn-primary">← Back to App</a>
    </div>
  </header>

  <!-- Version bar -->
  <div class="version-bar" id="versionBar">
    <span>API Version:</span>
    <button class="ver-btn" id="vBtn1" onclick="setVersion('v1')">v1 Stable</button>
    <button class="ver-btn active" id="vBtn2" onclick="setVersion('v2')">v2 Latest</button>
    <span style="margin-left:8px;color:#4a6278;">|</span>
    <span style="margin-left:8px;" id="versionDesc">Full platform — Scoring, WHOIS, Watchlist, Audit, SIEM, Blacklist, Cases</span>
    <span style="margin-left:auto;">
      <a href="/api/v1/docs" style="color:var(--text3);font-size:11px;text-decoration:none;margin-right:12px;">v1 Swagger ↗</a>
      <a href="/api/v2/docs" style="color:var(--accent);font-size:11px;text-decoration:none;">v2 Swagger ↗</a>
    </span>
  </div>

  <div class="layout">

    <!-- Sidebar -->
    <nav class="sidebar" id="sidebar">
      <div class="sidebar-section">
        <div class="sidebar-label">Overview</div>
        <a class="sidebar-item active" onclick="scrollTo('overview')">
          <span style="font-size:14px;">⬡</span>
          <span class="endpoint-name">Introduction</span>
        </a>
        <a class="sidebar-item" onclick="scrollTo('auth')">
          <span style="font-size:14px;">🔑</span>
          <span class="endpoint-name">Authentication</span>
        </a>
        <a class="sidebar-item" onclick="scrollTo('rates')">
          <span style="font-size:14px;">⏱</span>
          <span class="endpoint-name">Rate Limits</span>
        </a>
      </div>
      <div id="sidebarEndpoints"></div>
    </nav>

    <!-- Main content -->
    <main class="main">

      <!-- Hero -->
      <section id="overview">
        <div class="hero">
          <div class="hero-badge">v2.2.0 · Live</div>
          <h1>IP<span>Shield</span> API</h1>
          <p>Real-time IP risk intelligence combining AbuseIPDB, Shodan, VirusTotal, threat feeds, WHOIS/RDAP, reverse DNS, blacklist management and incident case tracking.</p>
          <div class="hero-stats">
            <div class="hero-stat"><div class="num">7</div><div class="lbl">Data Sources</div></div>
            <div class="hero-stat"><div class="num">20+</div><div class="lbl">Endpoints</div></div>
            <div class="hero-stat"><div class="num">v1/v2</div><div class="lbl">Versioned</div></div>
            <div class="hero-stat"><div class="num">30/min</div><div class="lbl">Rate Limit</div></div>
          </div>
        </div>

        <!-- Quick nav cards -->
        <div class="overview-cards" id="navCards"></div>
      </section>

      <!-- Auth -->
      <section id="auth" style="margin-bottom:40px;">
        <div class="auth-box">
          <div class="auth-icon">🔑</div>
          <div>
            <div class="auth-title">Authentication</div>
            <div class="auth-desc">
              All endpoints require the <code style="background:var(--bg3);padding:1px 6px;border-radius:3px;color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px;">x-api-key</code> header
              except <code style="background:var(--bg3);padding:1px 6px;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:11px;">/health</code> and
              <code style="background:var(--bg3);padding:1px 6px;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:11px;">/docs</code>.
              Set your key once using the Authorize button or paste it into any Try It request.
            </div>
            <div class="auth-key" onclick="copyApiKey()" title="Click to copy">
              x-api-key: ••••••••••••••••••••••••
            </div>
          </div>
        </div>
      </section>

      <!-- Rate limits -->
      <section id="rates" style="margin-bottom:40px;">
        <div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:12px;">Rate Limits</div>
        <div style="background:var(--bg1);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
          <table class="rate-table">
            <thead><tr><th>ENDPOINT</th><th>LIMIT</th><th>WINDOW</th></tr></thead>
            <tbody>
              <tr><td>/api/*</td><td>200 requests</td><td>15 minutes</td></tr>
              <tr><td>/api/score/*</td><td>30 requests</td><td>1 minute</td></tr>
              <tr><td>/api/whois/*</td><td>20 requests</td><td>1 minute</td></tr>
              <tr><td>/api/report/*</td><td>10 requests</td><td>1 minute</td></tr>
            </tbody>
          </table>
        </div>
        <div style="font-size:11px;color:var(--text3);margin-top:8px;">
          When rate limited you receive HTTP 429 with <code style="font-family:'JetBrains Mono',monospace;">Retry-After</code> header and countdown in seconds.
        </div>
      </section>

      <!-- Endpoints rendered by JS -->
      <div id="endpointsContainer"></div>

    </main>
  </div>

  <script>
    const API_KEY = localStorage.getItem("ipshield_api_key") || "";
    let currentVersion = localStorage.getItem("ipshield_api_version") || "v2";

    const TAG_META = {
      Scoring:      { icon: "⚡", color: "#00e87c", bg: "rgba(0,232,124,0.08)" },
      Intelligence: { icon: "🔍", color: "#00d9ff", bg: "rgba(0,217,255,0.08)" },
      Blacklist:    { icon: "🚫", color: "#ff3355", bg: "rgba(255,51,85,0.08)"  },
      Cases:        { icon: "📁", color: "#ff7700", bg: "rgba(255,119,0,0.08)"  },
      Watchlist:    { icon: "👁", color: "#ffcc00", bg: "rgba(255,204,0,0.08)"  },
      Audit:        { icon: "📋", color: "#9966ff", bg: "rgba(153,102,255,0.08)"},
      System:       { icon: "⚙️", color: "#6a8fa8", bg: "rgba(106,143,168,0.08)"}
    };

    const V1_HIDDEN_TAGS = ["Blacklist", "Cases"];

    const endpoints = ${endpointsJSON};

    function setVersion(v) {
      currentVersion = v;
      localStorage.setItem("ipshield_api_version", v);
      document.getElementById("vBtn1").classList.toggle("active", v === "v1");
      document.getElementById("vBtn2").classList.toggle("active", v === "v2");
      document.getElementById("versionDesc").textContent = v === "v1"
        ? "Core platform — Scoring, WHOIS, Watchlist, Audit, SIEM, Reports"
        : "Full platform — Scoring, WHOIS, Watchlist, Audit, SIEM, Blacklist, Cases";

      // Hide/show v2-only sections
      document.querySelectorAll(".tag-group").forEach(el => {
        const tag = el.dataset.tag;
        if (V1_HIDDEN_TAGS.includes(tag)) {
          el.style.display = v === "v1" ? "none" : "";
        }
      });
      document.querySelectorAll(".sidebar-section[data-tag]").forEach(el => {
        const tag = el.dataset.tag;
        if (V1_HIDDEN_TAGS.includes(tag)) {
          el.style.display = v === "v1" ? "none" : "";
        }
      });

      // Update base URL
      document.querySelectorAll(".base-url-display").forEach(el => {
        el.textContent = \`/api/\${v}\`;
      });
    }

    function copyApiKey() {
      const key = API_KEY || prompt("Paste your IPShield API key:");
      if (!key) return;
      localStorage.setItem("ipshield_api_key", key);
      navigator.clipboard.writeText(key).then(() => {
        const btn = event.target;
        const orig = btn.textContent;
        btn.textContent = "✓ Copied!";
        setTimeout(() => { btn.textContent = orig; }, 2000);
      });
    }

    function formatPath(path) {
      return path.replace(/\\{(\\w+)\\}/g, '<span class="path-param">{$1}</span>');
    }

    function getMethodColor(method) {
      return { GET: "#00e87c", POST: "#ffcc00", PUT: "#00aaff", DELETE: "#ff3355" }[method] || "#6a8fa8";
    }

    function buildParamsHTML(params) {
      if (!params?.length) return "";
      return \`
        <div class="section-label">Parameters</div>
        <div style="background:var(--bg1);border:1px solid var(--border);border-radius:8px;overflow:hidden;">
          <table class="param-table">
            <thead><tr><th>NAME</th><th>IN</th><th>TYPE</th><th>REQUIRED</th><th>DESCRIPTION</th></tr></thead>
            <tbody>
              \${params.map(p => \`
                <tr>
                  <td><span class="param-name">\${p.name}</span></td>
                  <td><span class="param-in">\${p.in}</span></td>
                  <td><span class="param-type">\${p.schema?.type || "string"}\${p.schema?.enum ? " (enum)" : ""}</span></td>
                  <td>\${p.required ? '<span class="param-req">required</span>' : '<span style="color:var(--text3);font-size:10px;">optional</span>'}</td>
                  <td class="param-desc">\${p.description || p.schema?.description || ""}\${p.schema?.default !== undefined ? \` <span style="color:var(--text3);">default: \${p.schema.default}</span>\` : ""}</td>
                </tr>
              \`).join("")}
            </tbody>
          </table>
        </div>\`;
    }

    function buildResponseCodesHTML(responses) {
      if (!responses) return "";
      return \`
        <div class="section-label">Response Codes</div>
        <div class="response-codes">
          \${Object.entries(responses).map(([code, resp]) => \`
            <div class="response-code">
              <span class="rc-status rc-\${code}">\${code}</span>
              <span class="rc-desc">\${resp.description || ""}</span>
            </div>
          \`).join("")}
        </div>\`;
    }

    function buildTryItHTML(ep, idx) {
      const hasBody   = ep.method === "POST" || ep.method === "PUT";
      const pathParams = (ep.parameters || []).filter(p => p.in === "path");
      const qParams    = (ep.parameters || []).filter(p => p.in === "query");

      let inputsHTML = \`
        <div class="try-row">
          <span class="try-label">API Key</span>
          <input class="try-input" id="key_\${idx}" placeholder="x-api-key value"
            value="\${API_KEY}" type="password">
        </div>\`;

      pathParams.forEach(p => {
        inputsHTML += \`
          <div class="try-row">
            <span class="try-label">\${p.name}</span>
            <input class="try-input" id="path_\${idx}_\${p.name}"
              placeholder="\${p.example || p.schema?.example || p.name}">
          </div>\`;
      });

      if (qParams.length) {
        inputsHTML += \`
          <div class="try-row">
            <span class="try-label">Query</span>
            <input class="try-input" id="query_\${idx}"
              placeholder="key=value&key2=value2">
          </div>\`;
      }

      if (hasBody) {
        const exBody = ep.exampleBody || "{}";
        inputsHTML += \`
          <div class="try-row" style="align-items:flex-start;">
            <span class="try-label" style="margin-top:8px;">Body</span>
            <textarea class="try-input" id="body_\${idx}" rows="4">\${exBody}</textarea>
          </div>\`;
      }

      return \`
        <div class="try-section">
          <div class="section-label">Try It</div>
          <div style="background:var(--bg1);border:1px solid var(--border);border-radius:8px;padding:16px;">
            <div class="try-form">\${inputsHTML}</div>
            <div style="margin-top:12px;display:flex;gap:10px;align-items:center;">
              <button class="try-btn" onclick="runRequest(\${idx})">▶ Execute</button>
              <span style="font-size:11px;color:var(--text3);">
                <span class="base-url-display">/api/\${currentVersion}</span>\${ep.path}
              </span>
            </div>
            <div id="response_\${idx}" style="display:none;" class="response-box">
              <div class="response-header">
                <span class="response-status" id="rstatus_\${idx}"></span>
                <span class="response-time" id="rtime_\${idx}"></span>
                <button class="copy-btn" onclick="copyResponse(\${idx})">Copy</button>
              </div>
              <pre class="response-body" id="rbody_\${idx}"></pre>
            </div>
          </div>
        </div>\`;
    }

    async function runRequest(idx) {
      const ep    = endpoints[idx];
      const btn   = document.querySelector(\`[onclick="runRequest(\${idx})"]\`);
      const apiKey = document.getElementById(\`key_\${idx}\`)?.value?.trim();

      if (apiKey) localStorage.setItem("ipshield_api_key", apiKey);

      // Build URL
      let path = ep.path;
      (ep.parameters || []).filter(p => p.in === "path").forEach(p => {
        const val = document.getElementById(\`path_\${idx}_\${p.name}\`)?.value?.trim();
        if (val) path = path.replace(\`{\${p.name}}\`, encodeURIComponent(val));
      });

      const qInput = document.getElementById(\`query_\${idx}\`)?.value?.trim();
      const url    = \`/api/\${currentVersion}\${path}\${qInput ? "?" + qInput : ""}\`;

      // Request options
      const opts = { method: ep.method, headers: { "x-api-key": apiKey || "" } };
      if (ep.method === "POST" || ep.method === "PUT") {
        opts.headers["Content-Type"] = "application/json";
        const bodyVal = document.getElementById(\`body_\${idx}\`)?.value?.trim();
        if (bodyVal) opts.body = bodyVal;
      }

      btn.disabled = true; btn.textContent = "⏳ Loading…";
      const start = Date.now();

      try {
        const res  = await fetch(url, opts);
        const time = Date.now() - start;
        let text;
        try { text = JSON.stringify(await res.json(), null, 2); }
        catch { text = await res.text(); }

        const statusEl = document.getElementById(\`rstatus_\${idx}\`);
        statusEl.textContent = \`HTTP \${res.status} \${res.statusText}\`;
        statusEl.className   = \`response-status \${res.ok ? "status-2xx" : res.status >= 500 ? "status-5xx" : "status-4xx"}\`;

        document.getElementById(\`rtime_\${idx}\`).textContent = \`\${time}ms\`;
        document.getElementById(\`rbody_\${idx}\`).textContent  = text;
        document.getElementById(\`response_\${idx}\`).style.display = "block";
      } catch (err) {
        document.getElementById(\`rstatus_\${idx}\`).textContent = "Network Error";
        document.getElementById(\`rstatus_\${idx}\`).className   = "response-status status-5xx";
        document.getElementById(\`rbody_\${idx}\`).textContent   = err.message;
        document.getElementById(\`response_\${idx}\`).style.display = "block";
      }

      btn.disabled = false; btn.textContent = "▶ Execute";
    }

    function copyResponse(idx) {
      navigator.clipboard.writeText(document.getElementById(\`rbody_\${idx}\`)?.textContent || "");
    }

    function toggleEndpoint(id) {
      document.getElementById(id).classList.toggle("open");
    }

    function scrollTo(id) {
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ── Build sidebar and endpoint sections ────────────────────────────────────
    function render() {
      const sidebar    = document.getElementById("sidebarEndpoints");
      const container  = document.getElementById("endpointsContainer");
      const navCards   = document.getElementById("navCards");
      const byTag      = {};

      endpoints.forEach((ep, idx) => {
        ep.tags?.forEach(tag => {
          if (!byTag[tag]) byTag[tag] = [];
          byTag[tag].push({ ...ep, idx });
        });
      });

      let sidebarHTML = "";
      let contentHTML = "";
      let cardsHTML   = "";

      Object.entries(byTag).forEach(([tag, eps]) => {
        const meta    = TAG_META[tag] || { icon: "◆", color: "#6a8fa8", bg: "rgba(106,143,168,0.08)" };
        const isV2Only = V1_HIDDEN_TAGS.includes(tag);

        // Sidebar section
        sidebarHTML += \`
          <div class="sidebar-section" data-tag="\${tag}" style="\${isV2Only && currentVersion === "v1" ? "display:none;" : ""}">
            <div class="sidebar-label" style="color:\${meta.color};">\${meta.icon} \${tag}</div>
            \${eps.map(ep => \`
              <a class="sidebar-item" onclick="toggleEndpoint('ep_\${ep.idx}');scrollTo('ep_\${ep.idx}')">
                <span class="method-dot" style="background:\${getMethodColor(ep.method)};"></span>
                <span class="endpoint-name">\${ep.path}</span>
              </a>
            \`).join("")}
          </div>\`;

        // Nav card
        cardsHTML += \`
          <div class="overview-card" onclick="scrollTo('tag_\${tag}')" style="\${isV2Only && currentVersion === "v1" ? "opacity:0.4;pointer-events:none;" : ""}">
            <div class="oc-icon">\${meta.icon}</div>
            <div class="oc-name">\${tag}</div>
            <div class="oc-count">\${eps.length} endpoint\${eps.length !== 1 ? "s" : ""}\${isV2Only ? ' <span style="color:var(--accent);font-size:9px;">v2 only</span>' : ""}</div>
          </div>\`;

        // Content section
        contentHTML += \`
          <div class="tag-group" id="tag_\${tag}" data-tag="\${tag}"
            style="\${isV2Only && currentVersion === "v1" ? "display:none;" : ""}">
            <div class="tag-header">
              <div class="tag-icon" style="background:\${meta.bg};">\${meta.icon}</div>
              <div>
                <div class="tag-title">\${tag}\${isV2Only ? ' <span style="font-size:12px;color:var(--accent);font-weight:600;">— v2 only</span>' : ""}</div>
                <div class="tag-desc">\${eps.length} endpoint\${eps.length !== 1 ? "s" : ""}</div>
              </div>
            </div>

            \${eps.map(ep => \`
              <div class="endpoint" id="ep_\${ep.idx}">
                <div class="endpoint-header" onclick="toggleEndpoint('ep_\${ep.idx}')">
                  <span class="method-badge method-\${ep.method}">\${ep.method}</span>
                  <span class="endpoint-path">\${formatPath(ep.path)}</span>
                  <span class="endpoint-summary">\${ep.summary || ""}</span>
                  \${!ep.requiresAuth ? '<span class="endpoint-lock" title="No auth required">🔓</span>' : '<span class="endpoint-lock" title="Auth required">🔒</span>'}
                  <span class="expand-icon">▼</span>
                </div>
                <div class="endpoint-body">
                  \${ep.description ? \`
                    <div class="section-label">Description</div>
                    <div class="endpoint-desc">\${ep.description}</div>
                  \` : ""}
                  \${buildParamsHTML(ep.parameters)}
                  \${buildResponseCodesHTML(ep.responses)}
                  \${buildTryItHTML(ep, ep.idx)}
                </div>
              </div>
            \`).join("")}
          </div>\`;
      });

      sidebar.innerHTML   = sidebarHTML;
      container.innerHTML = contentHTML;
      navCards.innerHTML  = cardsHTML;
    }

    // Set initial version
    setVersion(currentVersion);
    render();
  </script>
</body>
</html>`;
}

// ── Build flat endpoint list from OpenAPI spec ────────────────────────────────
function buildEndpoints(spec) {
  const endpoints = [];
  const METHOD_ORDER = ["GET","POST","PUT","DELETE","PATCH"];

  Object.entries(spec.paths || {}).forEach(([path, methods]) => {
    METHOD_ORDER.forEach(method => {
      const op = methods[method.toLowerCase()];
      if (!op) return;

      // Build example body from requestBody schema
      let exampleBody = null;
      if (op.requestBody) {
        const schema = op.requestBody.content?.["application/json"]?.schema;
        if (schema) exampleBody = JSON.stringify(buildExample(schema), null, 2);
      }

      endpoints.push({
        path,
        method,
        tags:        op.tags || ["System"],
        summary:     op.summary || "",
        description: op.description || "",
        parameters:  op.parameters || [],
        responses:   op.responses || {},
        requiresAuth:!(op.security && op.security.length === 0),
        exampleBody
      });
    });
  });

  return endpoints;
}

// Build example request body from JSON schema
function buildExample(schema) {
  if (!schema) return {};
  if (schema.example !== undefined) return schema.example;
  if (schema.type === "object" && schema.properties) {
    const obj = {};
    Object.entries(schema.properties).forEach(([key, prop]) => {
      if (prop.example !== undefined) obj[key] = prop.example;
      else if (prop.type === "array")   obj[key] = prop.items?.example !== undefined ? [prop.items.example] : [];
      else if (prop.type === "integer") obj[key] = 0;
      else if (prop.type === "boolean") obj[key] = false;
      else if (prop.type === "string")  obj[key] = prop.enum ? prop.enum[0] : "";
    });
    return obj;
  }
  return {};
}

module.exports = router;