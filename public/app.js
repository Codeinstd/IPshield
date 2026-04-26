/* IPShield v2.1 — Watchlist & Monitoring */
(() => {
  const API     = "/api";
  const API_KEY = "b2bc8fe074823d37e59d57a80bbb67f6558bc145e8d6f6ef5111133a0159f020";

  const ipInput    = document.getElementById("ipInput");
  const scoreBtn   = document.getElementById("scoreBtn");
  const clearBtn   = document.getElementById("clearBtn");
  const resultBody = document.getElementById("resultBody");
  const procTime   = document.getElementById("processingTime");
  const auditList  = document.getElementById("auditList");
  const auditCount = document.getElementById("auditCount");

  const sessionStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let auditEntries   = [];
  let map            = null;
  let mapMarker      = null;
  let isDark         = true;
  let currentIP      = null; // last scored IP

  injectExtraUI();
  initMap();
  loadStats();
  loadWatchlist();
  setupEventListeners();

  // ── Extra UI ───────────────────────────────────────────────────────────────
  function injectExtraUI() {
    // Theme toggle
    const headerRight = document.querySelector(".header-right");
    if (headerRight) {
      const toggle = document.createElement("button");
      toggle.className     = "btn btn-ghost";
      toggle.id            = "themeToggle";
      toggle.textContent   = "☀ LIGHT";
      toggle.style.cssText = "padding:6px 12px;font-size:11px;";
      toggle.addEventListener("click", toggleTheme);
      headerRight.prepend(toggle);
    }

    // Bulk tools
    const searchSection = document.querySelector(".search-section");
    if (searchSection) {
      const bulk = document.createElement("div");
      bulk.id = "bulkSection";
      bulk.style.cssText = "margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;";
      bulk.innerHTML = `
        <label style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;">Bulk:</label>
        <input type="file" id="csvUpload" accept=".csv,.txt" style="display:none">
        <button class="btn btn-ghost" id="csvBtn"    style="padding:8px 14px;font-size:11px;">↑ UPLOAD CSV</button>
        <button class="btn btn-ghost" id="exportBtn" style="padding:8px 14px;font-size:11px;">↓ EXPORT LOG</button>
        <span id="bulkStatus" style="font-size:11px;color:var(--text2);"></span>`;
      searchSection.appendChild(bulk);
    }

    // Map panel
   
const mainGrid = document.querySelector(".main-grid");
if (mainGrid) {
  // Wrapper to hold map + watchlist side by side
  const row = document.createElement("div");
  row.id = "mapWatchRow";
  row.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:24px;";

  // Map panel
  const mapWrap = document.createElement("div");
  mapWrap.id = "mapSection";
  mapWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;";
  mapWrap.innerHTML = `
    <div class="panel-header">
      <div class="panel-title">// Geo Map</div>
      <div id="mapLabel" style="font-size:11px;color:var(--text3);">Score an IP to see location</div>
    </div>
    <div id="mapContainer" style="height:320px;background:var(--bg2);display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;">Loading map…</div>`;

  // Watchlist panel
  const watchWrap = document.createElement("div");
  watchWrap.id = "watchlistSection";
  watchWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;";
  watchWrap.innerHTML = `
    <div class="panel-header" style="justify-content:space-between;">
      <div class="panel-title">// Watchlist</div>
      <div style="display:flex;gap:8px;align-items:center;">
        <span id="watchlistCount" style="font-size:11px;color:var(--text3);">0 IPs</span>
        <button id="addWatchBtn" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" title="Add current IP to watchlist">+ WATCH</button>
        <button id="pollBtn"     class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" title="Re-score all watched IPs">↻ POLL</button>
      </div>
    </div>
    <div id="watchlistBody" style="flex:1;overflow-y:auto;max-height:260px;">
      <div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No IPs being watched</div>
    </div>
    <div id="monitorStatus" style="padding:8px 16px;font-size:10px;color:var(--text3);border-top:1px solid var(--border);letter-spacing:1px;"></div>`;

  row.appendChild(mapWrap);
  row.appendChild(watchWrap);
  mainGrid.after(row);
}
  }

  // ── Map ────────────────────────────────────────────────────────────────────
  function initMap() {
    const container = document.getElementById("mapContainer");
    if (!container || typeof L === "undefined") return;
    container.innerHTML     = "";
    container.style.cssText = "height:280px;";
    map = L.map("mapContainer", { zoomControl: true, attributionControl: false });
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
    map.setView([20, 0], 2);
  }

  function updateMap(geo, ip, riskLevel) {
    if (!map || geo.lat == null || geo.lon == null) return;
    const color = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c" }[riskLevel] || "#00d9ff";
    const icon  = L.divIcon({
      className: "", iconSize: [14, 14], iconAnchor: [7, 7],
      html: `<div style="width:14px;height:14px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 0 8px ${color};"></div>`
    });
    if (mapMarker) map.removeLayer(mapMarker);
    mapMarker = L.marker([geo.lat, geo.lon], { icon })
      .addTo(map)
      .bindPopup(`<b style="font-family:monospace">${ip}</b><br>${geo.city || ""}, ${geo.country || ""}<br>Risk: ${riskLevel}`)
      .openPopup();
    map.flyTo([geo.lat, geo.lon], 6, { duration: 1.2 });
    const label = document.getElementById("mapLabel");
    if (label) label.textContent = `${geo.city || "—"}, ${geo.country || "—"}`;
  }

  // ── Events ─────────────────────────────────────────────────────────────────
  function setupEventListeners() {
    scoreBtn.addEventListener("click", scoreIP);
    clearBtn.addEventListener("click", clearPanel);
    ipInput.addEventListener("keydown", e => { if (e.key === "Enter") scoreIP(); });

    document.querySelectorAll(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => { ipInput.value = chip.dataset.ip; scoreIP(); });
    });

    document.addEventListener("click", e => {
      if (e.target.id === "csvBtn")     document.getElementById("csvUpload").click();
      if (e.target.id === "exportBtn")  exportLog();
      if (e.target.id === "addWatchBtn") addCurrentToWatchlist();
      if (e.target.id === "pollBtn")    triggerPoll();
    });

    document.addEventListener("change", e => {
      if (e.target.id === "csvUpload") handleCSVUpload(e.target.files[0]);
    });
  }

  // ── Theme ──────────────────────────────────────────────────────────────────
  function toggleTheme() {
    isDark = !isDark;
    const root = document.documentElement;
    const btn  = document.getElementById("themeToggle");
    if (isDark) {
      ["--bg","--bg1","--bg2","--bg3","--text","--text2","--text3","--border","--border2"]
        .forEach(v => root.style.removeProperty(v));
      if (btn) btn.textContent = "☀ LIGHT";
    } else {
      root.style.setProperty("--bg",      "#f0f4f8");
      root.style.setProperty("--bg1",     "#ffffff");
      root.style.setProperty("--bg2",     "#e8edf2");
      root.style.setProperty("--bg3",     "#dce3ea");
      root.style.setProperty("--text",    "#1a2332");
      root.style.setProperty("--text2",   "#4a6278");
      root.style.setProperty("--text3",   "#7a95a8");
      root.style.setProperty("--border",  "#c8d8e4");
      root.style.setProperty("--border2", "#b0c4d4");
      if (btn) btn.textContent = "☾ DARK";
    }
    if (map) {
      map.eachLayer(l => { if (l._url) map.removeLayer(l); });
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
    }
  }

  // ── Score ──────────────────────────────────────────────────────────────────
  async function scoreIP() {
    const ip = ipInput.value.trim();
    if (!ip) return;
    if (!isValidIP(ip)) { showError("Invalid IP address format."); return; }
    setLoading(true);
    try {
      const res  = await fetch(`${API}/score/${encodeURIComponent(ip)}`, {
        headers: { "x-api-key": API_KEY }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scoring failed");
      currentIP = ip;
      renderResult(data);
      addAuditEntry(data);
      updateStats(data.riskLevel);
      updateMap(data.geo || {}, data.ip, data.riskLevel);
    } catch (err) {
      showError(err.message || "Service temporarily unavailable.");
    } finally {
      setLoading(false);
    }
  }

  // ── Watchlist ──────────────────────────────────────────────────────────────
  async function loadWatchlist() {
    try {
      const res  = await fetch(`${API}/watchlist`, { headers: { "x-api-key": API_KEY } });
      if (!res.ok) return;
      const data = await res.json();
      renderWatchlist(data.watchlist || [], data.monitor);
    } catch (_) {}
  }

  async function addCurrentToWatchlist() {
    const ip = currentIP || ipInput.value.trim();
    if (!ip || !isValidIP(ip)) {
      setBulkStatus("Score an IP first, then click + WATCH");
      return;
    }

    const label     = prompt(`Label for ${ip} (optional):`, ip) ?? ip;
    const threshold = parseInt(prompt("Alert threshold (0-100):", "30") || "30");

    try {
      const res  = await fetch(`${API}/watchlist`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body:    JSON.stringify({ ip, label, threshold, alertOnChange: true })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setBulkStatus(`✓ ${ip} added to watchlist`);
      loadWatchlist();
    } catch (err) {
      setBulkStatus(`Error: ${err.message}`);
    }
  }

  async function removeFromWatchlist(ip) {
    try {
      const res = await fetch(`${API}/watchlist/${encodeURIComponent(ip)}`, {
        method:  "DELETE",
        headers: { "x-api-key": API_KEY }
      });
      if (!res.ok) throw new Error("Failed to remove");
      loadWatchlist();
    } catch (err) {
      setBulkStatus(`Error: ${err.message}`);
    }
  }

  async function triggerPoll() {
    const btn = document.getElementById("pollBtn");
    if (btn) { btn.disabled = true; btn.textContent = "↻ POLLING…"; }
    try {
      await fetch(`${API}/watchlist/poll`, { method: "POST", headers: { "x-api-key": API_KEY } });
      setBulkStatus("Poll triggered — watchlist will update shortly");
      setTimeout(loadWatchlist, 5000); // reload after 5s
    } catch (_) {
      setBulkStatus("Poll failed");
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "↻ POLL"; }
    }
  }

  function renderWatchlist(items, monitor) {
    const count = document.getElementById("watchlistCount");
    const body  = document.getElementById("watchlistBody");
    const mStat = document.getElementById("monitorStatus");

    if (count) count.textContent = `${items.length} IP${items.length !== 1 ? "s" : ""}`;

    if (monitor && mStat) {
      mStat.textContent = `Monitor: ${monitor.active ? "● ACTIVE" : "○ INACTIVE"} · polls every ${monitor.intervalMins}min`;
    }

    if (!items.length) {
      if (body) body.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
        No IPs being watched.<br>Score an IP then click <strong>+ WATCH</strong>.
      </div>`;
      return;
    }

    if (!body) return;
    body.innerHTML = items.map(item => {
      const riskColor = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c", UNKNOWN: "#6a8fa8" };
      const color     = riskColor[item.last_risk] || "#6a8fa8";
      const lastCheck = item.last_checked
        ? new Date(item.last_checked).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        : "never";
      const scoreBar  = item.last_score > 0
        ? `<div style="height:2px;background:var(--bg3);border-radius:2px;margin-top:4px;">
             <div style="height:2px;width:${item.last_score}%;background:${color};border-radius:2px;"></div>
           </div>` : "";

      return `
        <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;"
             onclick="document.getElementById('ipInput').value='${escHtml(item.ip)}';scoreIP && scoreIP()">
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:var(--text);font-family:monospace;">${escHtml(item.ip)}</div>
            <div style="font-size:10px;color:var(--text3);">${escHtml(item.label !== item.ip ? item.label : "")} · checked ${lastCheck}</div>
            ${scoreBar}
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="font-size:16px;font-weight:700;color:${color};">${item.last_score}</div>
            <div style="font-size:9px;font-weight:700;color:${color};letter-spacing:1px;">${item.last_risk}</div>
          </div>
          <div style="font-size:10px;color:var(--text3);">
            ⚑ ${item.threshold}
          </div>
          <button onclick="event.stopPropagation();removeFromWatchlist('${escHtml(item.ip)}')"
            style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;padding:4px;"
            title="Remove from watchlist">✕</button>
        </div>`;
    }).join("");
  }

  // expose removeFromWatchlist for inline onclick
  window.removeFromWatchlist = removeFromWatchlist;
  window.scoreIP = scoreIP;

  // ── Bulk CSV ───────────────────────────────────────────────────────────────
  async function handleCSVUpload(file) {
    if (!file) return;
    const text = await file.text();
    const ips  = text.split(/[\n,]+/).map(s => s.trim()).filter(isValidIP);
    if (!ips.length)     { setBulkStatus("No valid IPs found."); return; }
    if (ips.length > 50) { setBulkStatus("Trimming to 50 IPs."); ips.length = 50; }
    setBulkStatus(`Scoring ${ips.length} IPs…`);
    try {
      const res  = await fetch(`${API}/score/batch`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body:    JSON.stringify({ ips })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      data.results.forEach(r => { if (r.score != null) { addAuditEntry(r); updateStats(r.riskLevel); } });
      const failed = data.results.filter(r => r.error).length;
      setBulkStatus(`✓ ${data.results.length - failed} scored${failed ? `, ${failed} failed` : ""}.`);
      const last = data.results.find(r => r.score != null);
      if (last) { renderResult(last); updateMap(last.geo || {}, last.ip, last.riskLevel); }
    } catch (err) { setBulkStatus(`Error: ${err.message}`); }
  }

  function setBulkStatus(msg) {
    const el = document.getElementById("bulkStatus");
    if (el) el.textContent = msg;
  }

  // ── Export ─────────────────────────────────────────────────────────────────
  function exportLog() {
    if (!auditEntries.length) { setBulkStatus("No entries to export."); return; }
    const headers = ["IP","Score","Risk Level","Action","Country","City","ISP","Feodo","Spamhaus","ET Intel","Scored At"];
    const rows    = auditEntries.map(e => [
      e.ip, e.score, e.riskLevel, e.action,
      e.geo?.country || "—", e.geo?.city || "—", e.network?.isp || "—",
      e.threatFeeds?.feodo           ? "Yes" : "No",
      e.threatFeeds?.spamhaus        ? "Yes" : "No",
      e.threatFeeds?.emergingThreats ? "Yes" : "No",
      e.meta?.scoredAt ? new Date(e.meta.scoredAt).toISOString() : new Date().toISOString()
    ]);
    const csv  = [headers, ...rows].map(r => r.map(v => `"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: `ipshield-${Date.now()}.csv` });
    a.click();
    URL.revokeObjectURL(url);
    setBulkStatus(`✓ Exported ${auditEntries.length} entries.`);
  }

  // ── Threat feed badges ─────────────────────────────────────────────────────
  function threatFeedBadges(tf) {
    if (!tf) return "";
    const badges = [];
    if (tf.feodo)           badges.push({ label: "FEODO C2",      color: "#ff3355", bg: "rgba(255,51,85,0.15)",  tip: "Active C2 botnet — Feodo Tracker" });
    if (tf.spamhaus)        badges.push({ label: "SPAMHAUS DROP", color: "#ff3355", bg: "rgba(255,51,85,0.15)",  tip: "Do not route or peer — Spamhaus" });
    if (tf.emergingThreats) badges.push({ label: "ET INTEL",      color: "#ff7700", bg: "rgba(255,119,0,0.15)", tip: "Emerging Threats compromised list" });
    if (tf.otx?.pulseCount > 0) badges.push({ label: `OTX ×${tf.otx.pulseCount}`, color: "#ffcc00", bg: "rgba(255,204,0,0.15)", tip: `${tf.otx.pulseCount} OTX threat pulse(s)` });
    if (!badges.length) return `<div style="font-size:11px;color:var(--low);margin-bottom:16px;">✓ Not listed on any threat feed</div>`;
    return `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px;align-items:center;">
      <span style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;">Threat Feeds:</span>
      ${badges.map(b => `<span title="${escHtml(b.tip)}" style="font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:4px;background:${b.bg};color:${b.color};border:1px solid ${b.color};cursor:help;">${b.label}</span>`).join("")}
    </div>`;
  }

  // ── Render result ──────────────────────────────────────────────────────────
  function renderResult(d) {
    const score     = d.score        ?? 0;
    const riskLevel = d.riskLevel    ?? "LOW";
    const action    = d.action       ?? "ALLOW";
    const geo       = d.geo          ?? {};
    const network   = d.network      ?? {};
    const intel     = d.intelligence ?? {};
    const meta      = d.meta         ?? {};
    const signals   = d.signals      || buildFallbackSignals(d);

    const circ        = 2 * Math.PI * 52;
    const offset      = circ - (score / 100) * circ;
    const strokeColor = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c" }[riskLevel] || "#00e87c";

    procTime.textContent = meta.processingMs ? `${meta.processingMs}ms${meta.cached ? " · cached" : ""}` : "";

    resultBody.innerHTML = `
      <div class="score-header">
        <div class="score-ring-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="score-bg" cx="60" cy="60" r="52"/>
            <circle class="score-fill" cx="60" cy="60" r="52"
              stroke="${strokeColor}" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/>
          </svg>
          <div class="score-center">
            <div class="score-num" style="color:${strokeColor}">${score}</div>
            <div class="score-max">/100</div>
          </div>
        </div>
        <div class="score-meta">
          <div class="score-ip">${escHtml(d.ip)}</div>
          <div class="risk-badge ${riskLevel}"><span>${riskIcon(riskLevel)}</span><span>${riskLevel}</span></div>
          <div class="action-badge ${action}">RECOMMENDED ACTION: <span class="action-val">${action}</span></div>
          ${d.scoreBoost > 0 ? `<div style="font-size:10px;color:var(--text3);margin-top:6px;">Base: ${d.baseScore} + Feed boost: +${d.scoreBoost}</div>` : ""}
          ${intel.shodanTags?.length ? `<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
            ${intel.shodanTags.map(t => `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,217,255,0.1);color:var(--accent);border:1px solid rgba(0,217,255,0.3);">${escHtml(t)}</span>`).join("")}
          </div>` : ""}
          <div style="margin-top:10px;">
            <button onclick="addCurrentToWatchlist()" class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">+ Add to Watchlist</button>
          </div>
        </div>
      </div>

      ${threatFeedBadges(d.threatFeeds)}

      <div class="signals-title">// Threat Signals</div>
      <div class="signal-list">
        ${signals.map(s => `
          <div class="signal-item ${s.severity}">
            <span class="sig-cat">${escHtml(s.category)}</span>
            <span class="sig-detail">${escHtml(s.detail)}</span>
            <span class="sig-sev">${s.severity.toUpperCase()}</span>
          </div>`).join("")}
      </div>

      <div class="detail-grid">
        <div class="detail-card">
          <div class="detail-card-title">// Geolocation</div>
          ${kv("Country",  geo.country  || "—")}
          ${kv("Region",   geo.region   || "—")}
          ${kv("City",     geo.city     || "—")}
          ${kv("Timezone", geo.timezone || "—")}
          ${kv("Lat / Lon", geo.lat != null ? `${geo.lat}, ${geo.lon}` : "N/A (private)")}
        </div>
        <div class="detail-card">
          <div class="detail-card-title">// Network</div>
          ${kv("ISP",        network.isp  || "—")}
          ${kv("ASN",        network.asn  || "—")}
          ${kv("Type",       network.type || "—")}
          ${kv("Datacenter", intel.isDatacenter ? "Yes" : "No")}
          ${kv("Proxy",      intel.isProxy ? "⚠ Detected" : "No")}
          ${kv("Tor",        intel.isTor   ? "⚠ Exit Node" : "No")}
          ${intel.openPorts?.length ? kv("Open Ports", intel.openPorts.slice(0,6).join(", ")) : ""}
          ${intel.vulns?.length     ? kv("CVEs", `${intel.vulns.length} found`) : ""}
        </div>
      </div>

      ${intel.virusTotal ? `
        <div class="detail-card" style="margin-top:16px;">
          <div class="detail-card-title">// VirusTotal</div>
          <div style="display:flex;gap:16px;margin-top:4px;">
            ${vtBar("Malicious",  intel.virusTotal.malicious,  intel.virusTotal.total, "#ff3355")}
            ${vtBar("Suspicious", intel.virusTotal.suspicious, intel.virusTotal.total, "#ff7700")}
            ${vtBar("Harmless",   intel.virusTotal.harmless,   intel.virusTotal.total, "#00e87c")}
          </div>
        </div>` : ""}

      ${d.threatFeeds?.otx?.pulseNames?.length ? `
        <div class="detail-card" style="margin-top:16px;">
          <div class="detail-card-title">// OTX Pulses</div>
          ${d.threatFeeds.otx.pulseNames.map(n => `<div class="kv"><span class="kv-key">Pulse</span><span class="kv-val">${escHtml(n)}</span></div>`).join("")}
        </div>` : ""}`;
  }

  window.addCurrentToWatchlist = addCurrentToWatchlist;

  function vtBar(label, count, total, color) {
    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
    return `<div style="flex:1;text-align:center;">
      <div style="font-size:10px;color:var(--text3);margin-bottom:4px;">${label}</div>
      <div style="font-size:18px;font-weight:700;color:${color};">${count}</div>
      <div style="height:3px;background:var(--bg3);border-radius:2px;margin-top:4px;">
        <div style="height:3px;width:${pct}%;background:${color};border-radius:2px;transition:width 0.5s;"></div>
      </div>
    </div>`;
  }

  function buildFallbackSignals(d) {
    const score = d.score ?? 0;
    const intel = d.intelligence ?? {};
    const sigs  = [];
    sigs.push({ category: "ABUSE",    detail: `Confidence score: ${score}/100`, severity: score > 80 ? "critical" : score > 60 ? "high" : score > 30 ? "medium" : "low" });
    if (intel.isProxy)      sigs.push({ category: "PROXY",   detail: "Proxy detected",        severity: "high" });
    if (intel.isTor)        sigs.push({ category: "TOR",     detail: "Tor exit node",          severity: "critical" });
    if (intel.isDatacenter) sigs.push({ category: "HOSTING", detail: "Datacenter / cloud IP", severity: "medium" });
    sigs.push({ category: "VELOCITY", detail: `Velocity: ${intel.velocity || "LOW"}`,          severity: "info" });
    return sigs;
  }

  // ── Audit log ──────────────────────────────────────────────────────────────
  function addAuditEntry(d) {
    auditEntries.unshift(d);
    if (auditEntries.length > 100) auditEntries.pop();
    renderAudit();
  }

  function renderAudit() {
    auditCount.textContent = `${auditEntries.length} ${auditEntries.length === 1 ? "entry" : "entries"}`;
    if (!auditEntries.length) {
      auditList.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No queries yet</div>`;
      return;
    }
    auditList.innerHTML = auditEntries.map(e => {
      const feedHits = [
        e.threatFeeds?.feodo           && "F",
        e.threatFeeds?.spamhaus        && "S",
        e.threatFeeds?.emergingThreats && "E",
        e.threatFeeds?.otx?.pulseCount > 0 && "O"
      ].filter(Boolean).join("");
      return `
        <div class="audit-item" data-ip="${escHtml(e.ip)}">
          <span class="audit-ip">${escHtml(e.ip)}</span>
          ${feedHits ? `<span style="font-size:9px;color:#ff3355;font-weight:700;">[${feedHits}]</span>` : ""}
          <span class="audit-badge ${e.riskLevel}">${e.riskLevel}</span>
          <span class="audit-score ${e.riskLevel}">${e.score}</span>
          <span class="audit-ts">${fmtTime(new Date(e.meta?.scoredAt || Date.now()))}</span>
        </div>`;
    }).join("");
    auditList.querySelectorAll(".audit-item").forEach(item => {
      item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
    });
  }

  // ── Stats ──────────────────────────────────────────────────────────────────
  function updateStats(riskLevel) {
    if (riskLevel in sessionStats) {
      sessionStats[riskLevel]++;
      const map = { CRITICAL: "stat-critical", HIGH: "stat-high", MEDIUM: "stat-medium", LOW: "stat-low" };
      const el  = document.getElementById(map[riskLevel]);
      if (el) el.textContent = sessionStats[riskLevel];
    }
  }

  async function loadStats() {
    try {
      const res  = await fetch(`${API}/stats`, { headers: { "x-api-key": API_KEY } });
      if (!res.ok) return;
      const data = await res.json();
      if (data.riskDistribution) {
        const map = { CRITICAL: "stat-critical", HIGH: "stat-high", MEDIUM: "stat-medium", LOW: "stat-low" };
        Object.entries(map).forEach(([risk, id]) => {
          const el = document.getElementById(id);
          if (el && data.riskDistribution[risk] != null) {
            el.textContent     = data.riskDistribution[risk];
            sessionStats[risk] = data.riskDistribution[risk];
          }
        });
      }
      if (data.threatFeeds) showFeedStatus(data.threatFeeds);
    } catch (_) {}
  }

  function showFeedStatus(feeds) {
    let bar = document.getElementById("feedStatusBar");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "feedStatusBar";
      bar.style.cssText = "display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:6px 32px;background:var(--bg1);border-bottom:1px solid var(--border);font-size:10px;letter-spacing:1px;";
      const header = document.querySelector("header");
      if (header?.nextSibling) header.parentNode.insertBefore(bar, header.nextSibling);
    }
    const feedList = [
      { label: "FEODO",    data: feeds.feodo },
      { label: "SPAMHAUS", data: feeds.spamhaus },
      { label: "ET INTEL", data: feeds.emergingThreats },
      { label: "OTX",      data: feeds.otx }
    ];
    bar.innerHTML = `
      <span style="color:var(--text3);text-transform:uppercase;letter-spacing:2px;">Threat Feeds:</span>
      ${feedList.map(f => {
        const loaded = f.label === "OTX" ? f.data?.enabled : f.data?.loaded;
        const count  = f.data?.count ? ` (${Number(f.data.count).toLocaleString()})` : "";
        return `<span style="color:${loaded ? "var(--low)" : "var(--text3)"};">${loaded ? "●" : "○"} ${f.label}${count}</span>`;
      }).join("")}`;
  }

  // ── UI helpers ─────────────────────────────────────────────────────────────
  function setLoading(on) {
    scoreBtn.disabled = on;
    if (on) {
      resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><span>Analyzing ${escHtml(ipInput.value.trim())}…</span></div>`;
      procTime.textContent = "";
    }
  }

  function clearPanel() {
    currentIP     = null;
    ipInput.value = "";
    resultBody.innerHTML = `
      <div class="placeholder">
        <div class="placeholder-icon">⬡</div>
        <div class="placeholder-text">
          Enter an IP address above to begin analysis.<br>
          Risk scoring includes geo, threat intel,<br>
          network classification &amp; behavioral signals.
        </div>
      </div>`;
    procTime.textContent = "";
  }

  function showError(msg) {
    resultBody.innerHTML = `<div class="error-msg">⚠ ${escHtml(msg)}</div>`;
    procTime.textContent = "";
  }

  function kv(key, val) {
    return `<div class="kv"><span class="kv-key">${key}</span><span class="kv-val" title="${escHtml(String(val))}">${escHtml(String(val))}</span></div>`;
  }

  function riskIcon(l) { return { CRITICAL: "■", HIGH: "▲", MEDIUM: "◆", LOW: "●" }[l] || "●"; }

  function fmtTime(d) {
    return d instanceof Date && !isNaN(d)
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
  }

  function escHtml(str) {
    return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function isValidIP(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip);
  }

  // Auto-refresh watchlist every 2 minutes
  setInterval(loadWatchlist, 1000 * 60 * 2);
})();