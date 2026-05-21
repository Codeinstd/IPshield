
const express    = require("express");
const router     = express.Router();
const telemetry  = require("../store/telemetry.store");

// ── JSON endpoints 
router.get("/", (req, res) => {
  res.json(telemetry.getSummary());
});

router.get("/history", (req, res) => {
  const { route, status, limit, from, to } = req.query;
  res.json(telemetry.getHistory({ route, status, limit: parseInt(limit) || 100, from, to }));
});

router.get("/endpoint", (req, res) => {
  const { route } = req.query;
  const summary   = telemetry.getSummary();
  if (route) {
    const ep = summary.topEndpoints.find(e => e.route === route);
    return res.json(ep || { error: "Endpoint not found in telemetry" });
  }
  res.json(summary.topEndpoints);
});

// ── Live dashboard 
router.get("/dashboard", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(buildDashboard());
});

function buildDashboard() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>IPShield — API Observability </title>
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-W7LXC9M274"></script>
  <meta name="google-site-verification" content="WhmK3MH3Co3Wu72eOPEMMp5B8vtkFiVcoCP7Js4HGkA" />
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon.ico/favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="96x96" href="/favicon.ico/favicon-96x96.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon.ico/favicon-16x16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&amp;family=Syne:wght@400;600;700;800&amp;display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/leaflet.min.css">
  <style>
    :root {
      --bg:#080c0f;--bg1:#0d1117;--bg2:#111820;--bg3:#1a2535;
      --accent:#00d9ff;--low:#00e87c;--medium:#ffcc00;--high:#ff7700;--critical:#ff3355;
      --text:#c9d8e8;--text2:#8fa8bc;--text3:#4a6278;--border:#1e2d3d;
      --surface: rgba(17,24,32,0.72); --surface-hover: rgba(24,32,44,0.9);
      --shadow-lg: 0 10px 30px rgba(0,0,0,0.35),0 0 0 1px rgba(255,255,255,0.03); --blur: blur(14px); }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:var(--bg); color:var(--text); font-family:'Inter',sans-serif; min-height:100vh; }

    .header {
      background:var(--bg1); border-bottom:1px solid var(--border);
      padding:0 42px; height:72px; display:flex; align-items:center;
      justify-content:space-between; position:sticky; top:0; z-index:100;  backdrop-filter: blur(20px);;
    }

    .stat-card,
    .sparkline-wrap,
    .table-wrap {
      background: var(--surface);
      backdrop-filter: var(--blur);
      box-shadow: var(--shadow-lg);
    }

    .logo-sub {
    font-size: 10px;
    color: var(--text3);
    letter-spacing: 3px;
    margin-top: 1px;
    }

    .logo { display: flex; align-items: center; gap: 12px; }

    .logo-icon {
    width: 30px; height: 30px;
    border: 1.5px solid #00d9ff; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    color: #00d9ff; box-shadow: var(--glow-a);
    animation: pulse-border 3s ease-in-out infinite;
    }
    .logo-text { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 22px; letter-spacing: -0.5px; }
    
    .logo-text span { color: #00d9ff }
    .header-right { display:flex; align-items:center; gap:12px; font-size:12px; }
    .live-dot {
      width:8px; height:8px; border-radius:50%; background:var(--low);
      animation:pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
    .refresh-info { color:var(--text3); font-size:11px; font-family:'JetBrains Mono',monospace; }
    .back-link { color:var(--text2); text-decoration:none; padding:5px 12px; border:1px solid var(--border); border-radius:6px; }
    .back-link:hover { color:var(--accent); border-color:var(--accent); }

    .container { padding:28px 32px; max-width:1400px; margin:0 auto; }

    /* Stat cards */
    .stats-grid {
      display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
      gap:16px; margin-bottom:28px;
    }
    .stat-card {
      background:var(--bg1); border:1px solid var(--border); border-radius:12px;
      padding:18px 20px; position:relative; overflow:hidden;
    }
    .stat-card::before {
      content:''; position:absolute; top:0; left:0; right:0; height:2px;
      background:var(--card-color, var(--accent));
    }
    .stat-label { font-size:10px; color:var(--text3); letter-spacing:1.5px; text-transform:uppercase; margin-bottom:10px; }
    .stat-value { font-size:28px; font-weight:800; font-family:'JetBrains Mono',monospace; color:var(--card-color,var(--text)); }
    .stat-sub { font-size:11px; color:var(--text3); margin-top:4px; }

    /* Section */
    .section { margin-bottom:28px; }
    .section-header {
      display:flex; align-items:center; justify-content:space-between;
      margin-bottom:14px;
    }
    .section-title {font-weight:700; color:var(--text); letter-spacing:0.5px; }
    .section-sub { font-size:11px; color:var(--text3); }

    /* Table */
    .table-wrap {
      background:var(--bg1); border:1px solid var(--border);
      border-radius:10px; overflow:hidden;
    }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    thead tr { background:var(--bg2); }
    th { padding:10px 14px; text-align:left; color:var(--text3); font-size:10px; letter-spacing:1px; border-bottom:1px solid var(--border); }
    td { padding:10px 14px; border-bottom:1px solid var(--border); color:var(--text2); }
    tr:last-child td { border-bottom:none; }
    tr:hover td { background:rgba(0,217,255,0.02); }

    /* Hide hamburger on desktop */
    .hamburger {
      display: none;
      font-size: 26px;
      cursor: pointer;
    }

    /* Mobile menu hidden by default */
    .mobile-menu {
      display: none;
      flex-direction: column;
      position: absolute;
      top: 60px;
      left: 0;
      right: 0;
      background: #111;
      padding: 16px;
      gap: 12px;
      z-index: 999;
    }

    /* Links in mobile menu */
    .mobile-menu a {
      color: white;
      text-decoration: none;
      padding: 10px;
      border-radius: 6px;
      background: rgba(255,255,255,0.05);
    }

    /* Show hamburger on mobile */
    @media (max-width: 768px) {
      .header-right {
        display: none; /* hide full header actions */
      }

      .hamburger {
        display: block;
      }
    }

    .mobile-menu {
      display: none;
    }

    .mobile-menu.open {
      display: flex;
    }

    .mobile-menu {
      transition: all 0.2s ease;
    }

    .mono { font-family:'JetBrains Mono',monospace; }
    .badge {
      display:inline-block; padding:2px 7px; border-radius:3px;
      font-size:10px; font-weight:700; font-family:'JetBrains Mono',monospace;
    }
    .badge-get    { background:rgba(0,232,124,0.12); color:#00e87c; }
    .badge-post   { background:rgba(255,204,0,0.12);  color:#ffcc00; }
    .badge-put    { background:rgba(0,170,255,0.12);  color:#00aaff; }
    .badge-delete { background:rgba(255,51,85,0.12);  color:#ff3355; }

    .status-ok  { color:var(--low); font-weight:700; }
    .status-err { color:var(--critical); font-weight:700; }
    .status-warn{ color:var(--medium); font-weight:700; }

    /* Latency bar */
    .lat-bar-wrap { display:flex; align-items:center; gap:8px; }
    .lat-bar-bg { flex:1; height:4px; background:var(--bg3); border-radius:2px; }
    .lat-bar { height:4px; border-radius:2px; background:var(--accent); min-width:2px; }
    .lat-val { font-size:11px; font-family:'JetBrains Mono',monospace; color:var(--text2); width:50px; text-align:right; }

    /* Sparkline */
    .sparkline-wrap { background:var(--bg1); border:1px solid var(--border); border-radius:10px; padding:18px 20px; }
    .sparkline-title { font-size:12px; color:var(--text2); margin-bottom:12px; }
    canvas { display:block; width:100%; }

    /* Two col grid */
    .two-col { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    @media(max-width:900px) { .two-col { grid-template-columns:1fr; } }

    /* Error rate bar */
    .err-rate-bar-bg { height:6px; background:var(--bg3); border-radius:3px; overflow:hidden; }
    .err-rate-bar { height:6px; border-radius:3px; background:var(--critical); transition:width 0.3s; }

    /* Status code pills */
    .status-pills { display:flex; gap:8px; flex-wrap:wrap; }
    .status-pill {
      padding:5px 12px; border-radius:20px;
      font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:700;
    }
    .s2xx { background:rgba(0,232,124,0.1); color:var(--low); border:1px solid rgba(0,232,124,0.2); }
    .s4xx { background:rgba(255,119,0,0.1); color:var(--high); border:1px solid rgba(255,119,0,0.2); }
    .s5xx { background:rgba(255,51,85,0.1); color:var(--critical); border:1px solid rgba(255,51,85,0.2); }
    .s429 { background:rgba(255,204,0,0.1); color:var(--medium); border:1px solid rgba(255,204,0,0.2); }

    #lastUpdate { color:var(--text3); font-size:11px; font-family:'JetBrains Mono',monospace; }
  </style>
</head>
<body>

<div class="header">
  <div class="logo">
  <div class="logo-icon">⬡</div>
  <div>
  <div class="logo-text">IP<span>Shield</span></div>
  <div class="logo-sub">API Observability</div></div>
</div>
<div class="hamburger" onclick="toggleMenu()">
  ☰
</div>
<div id="mobileMenu" class="mobile-menu">
  <a href="/api/docs">Docs</a>
  <a href="/">App</a>

  <div class="mobile-status">
    <div class="live-dot"></div>
    <span>Live · refreshes every 10s</span>
  </div>

  <div id="lastUpdateMobile">14:11:32</div>
</div>
  <div class="header-right">
    <div class="live-dot"></div>
    <span class="refresh-info">Live · refreshes every 10s</span>
    <span id="lastUpdate"></span>
    <a href="/api/docs" class="back-link">← Docs</a>
    <a href="/" class="back-link">← App</a>
  </div>
</div>

<div class="container">

  <!-- Stat cards -->
  <div class="stats-grid" id="statsGrid">
    <div class="stat-card" style="--card-color:var(--accent);">
      <div class="stat-label">Total Requests</div>
      <div class="stat-value" id="totalReqs">–</div>
      <div class="stat-sub" id="rps">– req/s</div>
    </div>
    <div class="stat-card" style="--card-color:var(--critical);">
      <div class="stat-label">Error Rate</div>
      <div class="stat-value" id="errorRate">–</div>
      <div class="stat-sub" id="totalErrors">– errors</div>
    </div>
    <div class="stat-card" style="--card-color:var(--low);">
      <div class="stat-label">Uptime</div>
      <div class="stat-value" id="uptime" style="font-size:20px;">–</div>
      <div class="stat-sub" id="startedAt">–</div>
    </div>
    <div class="stat-card" style="--card-color:var(--medium);">
      <div class="stat-label">Endpoints Tracked</div>
      <div class="stat-value" id="endpointCount">–</div>
      <div class="stat-sub">unique routes</div>
    </div>
    <div class="stat-card" style="--card-color:var(--high);">
      <div class="stat-label">Consumers</div>
      <div class="stat-value" id="consumerCount">–</div>
      <div class="stat-sub">API key holders</div>
    </div>
  </div>

  <!-- Status codes + hourly sparkline -->
  <div class="two-col" style="margin-bottom:28px;">
    <div class="sparkline-wrap">
      <div class="sparkline-title">Status Code Distribution</div>
      <div id="statusPills" class="status-pills"></div>
    </div>
    <div class="sparkline-wrap">
      <div class="sparkline-title">Hourly Traffic (last 24h)</div>
      <canvas id="trafficCanvas" height="60"></canvas>
    </div>
  </div>

  <!-- Endpoint performance table -->
  <div class="section">
    <div class="section-header">
      <div>
        <div class="section-title">Endpoint Performance</div>
        <div class="section-sub">Sorted by request count · p50/p95/p99 latencies</div>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>METHOD</th>
            <th>ROUTE</th>
            <th>REQUESTS</th>
            <th>ERROR RATE</th>
            <th>AVG ms</th>
            <th>P50</th>
            <th>P95</th>
            <th>P99</th>
            <th>LATENCY DIST</th>
          </tr>
        </thead>
        <tbody id="endpointTable">
          <tr><td colspan="9" style="text-align:center;color:var(--text3);padding:32px;">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Two col: consumers + recent requests -->
  <div class="two-col">

    <!-- Top consumers -->
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Top API Consumers</div>
          <div class="section-sub">By request volume · keys masked</div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>API KEY</th><th>REQUESTS</th><th>ERROR RATE</th><th>LAST SEEN</th></tr></thead>
          <tbody id="consumerTable">
            <tr><td colspan="4" style="text-align:center;color:var(--text3);padding:24px;">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Recent requests live log -->
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Live Request Log</div>
          <div class="section-sub">Last 20 requests · real-time</div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>METHOD</th><th>ROUTE</th><th>STATUS</th><th>ms</th><th>VER</th></tr></thead>
          <tbody id="recentTable">
            <tr><td colspan="5" style="text-align:center;color:var(--text3);padding:24px;">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

</div>

<script>
  function fmt(n) { return n >= 1e6 ? (n/1e6).toFixed(1)+"M" : n >= 1e3 ? (n/1e3).toFixed(1)+"k" : String(n); }

  function methodBadge(m) {
    const cls = {GET:"get",POST:"post",PUT:"put",DELETE:"delete"}[m] || "get";
    return \`<span class="badge badge-\${cls}">\${m}</span>\`;
  }

  function statusClass(s) {
    if (s < 300) return "status-ok";
    if (s === 429) return "status-warn";
    if (s >= 400) return "status-err";
    return "";
  }

  function latBar(val, max) {
    const pct = max > 0 ? Math.round((val / max) * 100) : 0;
    const color = pct > 80 ? "var(--critical)" : pct > 50 ? "var(--medium)" : "var(--accent)";
    return \`<div class="lat-bar-wrap">
      <div class="lat-bar-bg"><div class="lat-bar" style="width:\${pct}%;background:\${color};"></div></div>
      <span class="lat-val">\${val}ms</span>
    </div>\`;
  }

  function toggleMenu() {
    document.getElementById("mobileMenu").classList.toggle("open");
  }

  function drawSparkline(hourly) {
    const canvas = document.getElementById("trafficCanvas");
    if (!canvas || !hourly?.length) return;
    const dpr = window.devicePixelRatio || 1;
    const W   = canvas.parentElement.clientWidth - 40;
    const H   = 60;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + "px";
    canvas.style.height = H + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const vals = hourly.map(h => h.count);
    const max  = Math.max(...vals, 1);
    const PAD  = { t:4, b:4, l:0, r:0 };
    const cW   = W - PAD.l - PAD.r;
    const cH   = H - PAD.t - PAD.b;

    // Gradient fill
    const grad = ctx.createLinearGradient(0, PAD.t, 0, PAD.t + cH);
    grad.addColorStop(0, "rgba(0,217,255,0.3)");
    grad.addColorStop(1, "rgba(0,217,255,0)");

    ctx.beginPath();
    vals.forEach((v, i) => {
      const x = PAD.l + (i / (vals.length - 1)) * cW;
      const y = PAD.t + cH - (v / max) * cH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(PAD.l + cW, PAD.t + cH);
    ctx.lineTo(PAD.l, PAD.t + cH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    vals.forEach((v, i) => {
      const x = PAD.l + (i / (vals.length - 1)) * cW;
      const y = PAD.t + cH - (v / max) * cH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#00d9ff";
    ctx.lineWidth   = 2;
    ctx.stroke();
  }

  async function refresh() {
    try {
      const [summary, recent] = await Promise.all([
        fetch("/api/telemetry", { headers:{"x-api-key": localStorage.getItem("ipshield_api_key")||""} }).then(r=>r.json()),
        fetch("/api/telemetry/history?limit=20", { headers:{"x-api-key": localStorage.getItem("ipshield_api_key")||""} }).then(r=>r.json())
      ]);

      // Stat cards
      document.getElementById("totalReqs").textContent   = fmt(summary.requests.total);
      document.getElementById("rps").textContent         = summary.requests.rps + " req/s";
      document.getElementById("errorRate").textContent   = summary.requests.errorRate;
      document.getElementById("totalErrors").textContent = fmt(summary.requests.errors) + " errors";
      document.getElementById("uptime").textContent      = summary.uptime.human;
      document.getElementById("startedAt").textContent   = "since " + new Date(summary.uptime.startedAt).toLocaleTimeString();
      document.getElementById("endpointCount").textContent = summary.topEndpoints.length;
      document.getElementById("consumerCount").textContent = summary.topConsumers.length;

      // Status pills
      const pills = document.getElementById("statusPills");
      pills.innerHTML = Object.entries(summary.byStatus)
        .sort(([a],[b]) => Number(a)-Number(b))
        .map(([code, count]) => {
          const cls = code.startsWith("2") ? "s2xx" : code === "429" ? "s429" : code.startsWith("4") ? "s4xx" : "s5xx";
          return \`<div class="status-pill \${cls}">\${code} <span style="opacity:0.7;">\${fmt(count)}</span></div>\`;
        }).join("");

      // Hourly sparkline
      drawSparkline(summary.hourlyTraffic);

      // Endpoint table
      const maxAvg = Math.max(...summary.topEndpoints.map(e => e.p99), 1);
      const [method, ...pathParts] = summary.topEndpoints[0]?.route?.split(" ") || [];
      document.getElementById("endpointTable").innerHTML =
        summary.topEndpoints.slice(0, 20).map(ep => {
          const [meth, ...pp] = ep.route.split(" ");
          const errPct = parseFloat(ep.errorRate);
          return \`<tr>
            <td>\${methodBadge(meth)}</td>
            <td class="mono" style="color:var(--text);font-size:11px;">\${pp.join(" ")}</td>
            <td class="mono">\${fmt(ep.count)}</td>
            <td>
              <div style="display:flex;align-items:center;gap:8px;">
                <div class="err-rate-bar-bg" style="width:60px;">
                  <div class="err-rate-bar" style="width:\${Math.min(errPct,100)}%;"></div>
                </div>
                <span style="color:\${errPct>10?"var(--critical)":errPct>2?"var(--medium)":"var(--low)"};font-size:11px;">\${ep.errorRate}</span>
              </div>
            </td>
            <td class="mono">\${ep.avgMs}ms</td>
            <td class="mono" style="color:var(--low);">\${ep.p50}ms</td>
            <td class="mono" style="color:var(--medium);">\${ep.p95}ms</td>
            <td class="mono" style="color:var(--high);">\${ep.p99}ms</td>
            <td style="min-width:120px;">\${latBar(ep.p95, maxAvg)}</td>
          </tr>\`;
        }).join("") || '<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:24px;">No data yet — make some API requests</td></tr>';

      // Consumer table
      document.getElementById("consumerTable").innerHTML =
        summary.topConsumers.slice(0,10).map(c => \`<tr>
          <td class="mono" style="color:var(--accent);font-size:11px;">\${c.key}</td>
          <td class="mono">\${fmt(c.count)}</td>
          <td style="color:\${parseFloat(c.errorRate)>10?"var(--critical)":parseFloat(c.errorRate)>2?"var(--medium)":"var(--low)"}">\${c.errorRate}</td>
          <td style="font-size:11px;color:var(--text3);">\${new Date(c.lastSeen).toLocaleTimeString()}</td>
        </tr>\`).join("") || '<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:16px;">No consumer data yet</td></tr>';

      // Recent requests
      const rows = Array.isArray(recent) ? recent : (recent.results || recent);
      document.getElementById("recentTable").innerHTML =
        rows.slice(0,20).map(r => \`<tr>
          <td>\${methodBadge(r.method)}</td>
          <td class="mono" style="font-size:10px;color:var(--text2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">\${r.route||r.path}</td>
          <td class="\${statusClass(r.status)} mono">\${r.status}</td>
          <td class="mono" style="color:\${r.durationMs>1000?"var(--critical)":r.durationMs>300?"var(--medium)":"var(--text2)"}">\${r.durationMs}</td>
          <td style="font-size:10px;color:var(--text3);">\${r.apiVersion||"v2"}</td>
        </tr>\`).join("") || '<tr><td colspan="5" style="text-align:center;color:var(--text3);padding:16px;">No requests yet</td></tr>';

      document.getElementById("lastUpdate").textContent = new Date().toLocaleTimeString();
    } catch(err) {
      console.error("Telemetry refresh error:", err);
    }
  }

  // Initial + auto-refresh every 10 seconds
  refresh();
  setInterval(refresh, 10000);
</script>
</body>
</html>`;
}

module.exports = router;