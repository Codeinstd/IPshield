/**
 * app.js — IPShield frontend
 * Place in: public/app.js
 */
(() => {
  const API     = "/api";
  const API_KEY = "b2bc8fe074823d37e59d57a80bbb67f6558bc145e8d6f6ef5111133a0159f020";

  // ── DOM refs ───────────────────────────────────────────────
  const ipInput    = document.getElementById("ipInput");
  const scoreBtn   = document.getElementById("scoreBtn");
  const clearBtn   = document.getElementById("clearBtn");
  const resultBody = document.getElementById("resultBody");
  const procTime   = document.getElementById("processingTime");
  const auditList  = document.getElementById("auditList");
  const auditCount = document.getElementById("auditCount");

  // ── State ──────────────────────────────────────────────────
  const sessionStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let auditEntries   = [];
  let map            = null;
  let mapMarker      = null;
  let isDark         = true;

  // ── Init ───────────────────────────────────────────────────
  injectExtraUI();
  initMap();
  loadStats();
  setupEventListeners();

  // ── Extra UI injection ─────────────────────────────────────
  function injectExtraUI() {
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

    const mainGrid = document.querySelector(".main-grid");
    if (mainGrid) {
      const mapWrap = document.createElement("div");
      mapWrap.id = "mapSection";
      mapWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;";
      mapWrap.innerHTML = `
        <div class="panel-header">
          <div class="panel-title">// Geo Map</div>
          <div id="mapLabel" style="font-size:11px;color:var(--text3);">Score an IP to see location</div>
        </div>
        <div id="mapContainer" style="height:280px;background:var(--bg2);display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;">
          Loading map…
        </div>`;
      mainGrid.after(mapWrap);
    }
  }

  // ── Leaflet map ────────────────────────────────────────────
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
      className:  "",
      html:       `<div style="width:14px;height:14px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 0 8px ${color};"></div>`,
      iconSize:   [14, 14],
      iconAnchor: [7, 7]
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

  // ── Event listeners ────────────────────────────────────────
  function setupEventListeners() {
    scoreBtn.addEventListener("click", scoreIP);
    clearBtn.addEventListener("click", clearPanel);
    ipInput.addEventListener("keydown", e => { if (e.key === "Enter") scoreIP(); });

    document.querySelectorAll(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => { ipInput.value = chip.dataset.ip; scoreIP(); });
    });

    document.addEventListener("click", e => {
      if (e.target.id === "csvBtn")    document.getElementById("csvUpload").click();
      if (e.target.id === "exportBtn") exportLog();
    });

    document.addEventListener("change", e => {
      if (e.target.id === "csvUpload") handleCSVUpload(e.target.files[0]);
    });
  }

  // ── Theme toggle ───────────────────────────────────────────
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

  // ── Score single IP ────────────────────────────────────────
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

  // ── Bulk CSV upload ────────────────────────────────────────
  async function handleCSVUpload(file) {
    if (!file) return;
    const text = await file.text();
    const ips  = text.split(/[\n,]+/).map(s => s.trim()).filter(isValidIP);

    if (!ips.length)     { setBulkStatus("No valid IPs found in file."); return; }
    if (ips.length > 50) { setBulkStatus("Max 50 IPs per batch. Trimming to 50."); ips.length = 50; }

    setBulkStatus(`Scoring ${ips.length} IPs…`);
    try {
      const res  = await fetch(`${API}/score/batch`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body:    JSON.stringify({ ips })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      data.results.forEach(r => {
        if (r.score != null) { addAuditEntry(r); updateStats(r.riskLevel); }
      });

      const failed = data.results.filter(r => r.error).length;
      setBulkStatus(`✓ ${data.results.length - failed} scored${failed ? `, ${failed} failed` : ""}.`);

      const last = data.results.find(r => r.score != null);
      if (last) { renderResult(last); updateMap(last.geo || {}, last.ip, last.riskLevel); }
    } catch (err) {
      setBulkStatus(`Error: ${err.message}`);
    }
  }

  function setBulkStatus(msg) {
    const el = document.getElementById("bulkStatus");
    if (el) el.textContent = msg;
  }

  // ── Export audit log ───────────────────────────────────────
  function exportLog() {
    if (!auditEntries.length) { setBulkStatus("No entries to export."); return; }

    const headers = ["IP","Score","Risk Level","Action","Country","City","ISP","Proxy","Tor","Datacenter","Scored At"];
    const rows    = auditEntries.map(e => [
      e.ip, e.score, e.riskLevel, e.action,
      e.geo?.country || "—", e.geo?.city || "—",
      e.network?.isp || "—",
      e.intelligence?.isProxy      ? "Yes" : "No",
      e.intelligence?.isTor        ? "Yes" : "No",
      e.intelligence?.isDatacenter ? "Yes" : "No",
      e.meta?.scoredAt ? new Date(e.meta.scoredAt).toISOString() : new Date().toISOString()
    ]);

    const csv  = [headers, ...rows].map(r => r.map(v => `"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: `ipshield-audit-${Date.now()}.csv` });
    a.click();
    URL.revokeObjectURL(url);
    setBulkStatus(`✓ Exported ${auditEntries.length} entries.`);
  }

  // ── Render result panel ────────────────────────────────────
  function renderResult(d) {
    const score     = d.score        ?? 0;
    const riskLevel = d.riskLevel    ?? "LOW";
    const action    = d.action       ?? "ALLOW";
    const geo       = d.geo          ?? {};
    const network   = d.network      ?? {};
    const intel     = d.intelligence ?? {};
    const meta      = d.meta         ?? {};
    const signals   = d.signals      || buildFallbackSignals(d);

    const circumference = 2 * Math.PI * 52;
    const offset      = circumference - (score / 100) * circumference;
    const strokeColor = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c" }[riskLevel] || "#00e87c";

    procTime.textContent = meta.processingMs
      ? `${meta.processingMs}ms${meta.cached ? " · cached" : ""}` : "";

    resultBody.innerHTML = `
      <div class="score-header">
        <div class="score-ring-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="score-bg" cx="60" cy="60" r="52"/>
            <circle class="score-fill" cx="60" cy="60" r="52"
              stroke="${strokeColor}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${offset}"/>
          </svg>
          <div class="score-center">
            <div class="score-num" style="color:${strokeColor}">${score}</div>
            <div class="score-max">/100</div>
          </div>
        </div>
        <div class="score-meta">
          <div class="score-ip">${escHtml(d.ip)}</div>
          <div class="risk-badge ${riskLevel}">
            <span>${riskIcon(riskLevel)}</span><span>${riskLevel}</span>
          </div>
          <div class="action-badge ${action}">
            RECOMMENDED ACTION: <span class="action-val">${action}</span>
          </div>
          ${intel.shodanTags?.length ? `<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
            ${intel.shodanTags.map(t => `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,217,255,0.1);color:var(--accent);border:1px solid rgba(0,217,255,0.3);">${escHtml(t)}</span>`).join("")}
          </div>` : ""}
        </div>
      </div>

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
          ${intel.vulns?.length     ? kv("CVEs",       `${intel.vulns.length} found`)         : ""}
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
        </div>` : ""}`;
  }

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

  // ── Audit log ──────────────────────────────────────────────
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
    auditList.innerHTML = auditEntries.map(e => `
      <div class="audit-item" data-ip="${escHtml(e.ip)}">
        <span class="audit-ip">${escHtml(e.ip)}</span>
        <span class="audit-badge ${e.riskLevel}">${e.riskLevel}</span>
        <span class="audit-score ${e.riskLevel}">${e.score}</span>
        <span class="audit-ts">${fmtTime(new Date(e.meta?.scoredAt || Date.now()))}</span>
      </div>`).join("");

    auditList.querySelectorAll(".audit-item").forEach(item => {
      item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
    });
  }

  // ── Stats ──────────────────────────────────────────────────
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
      const res  = await fetch(`${API}/stats`, {
        headers: { "x-api-key": API_KEY }
      });
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
    } catch (_) {}
  }

  // ── UI helpers ─────────────────────────────────────────────
  function setLoading(on) {
    scoreBtn.disabled = on;
    if (on) {
      resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><span>Analyzing ${escHtml(ipInput.value.trim())}…</span></div>`;
      procTime.textContent = "";
    }
  }

  function clearPanel() {
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
    return `<div class="kv">
      <span class="kv-key">${key}</span>
      <span class="kv-val" title="${escHtml(String(val))}">${escHtml(String(val))}</span>
    </div>`;
  }

  function riskIcon(level) {
    return { CRITICAL: "■", HIGH: "▲", MEDIUM: "◆", LOW: "●" }[level] || "●";
  }

  function fmtTime(d) {
    return d instanceof Date && !isNaN(d)
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : "—";
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g,  "&lt;")
      .replace(/>/g,  "&gt;")
      .replace(/"/g,  "&quot;");
  }

  function isValidIP(ip) {
    const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const v6 = /^[0-9a-fA-F:]+$/;
    return v4.test(ip) || v6.test(ip);
  }
})();