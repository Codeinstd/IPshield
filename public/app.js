(() => {
  const API_BASE = "/api";

  const ipInput    = document.getElementById("ipInput");
  const scoreBtn   = document.getElementById("scoreBtn");
  const clearBtn   = document.getElementById("clearBtn");
  const resultBody = document.getElementById("resultBody");
  const procTime   = document.getElementById("processingTime");
  const auditList  = document.getElementById("auditList");
  const auditCount = document.getElementById("auditCount");

  const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let auditEntries = [];

  // ── Quick test chips ──────────────────────────────────────
  document.querySelectorAll(".quick-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      ipInput.value = chip.dataset.ip;
      scoreIP();
    });
  });

  // ── Buttons ───────────────────────────────────────────────
  scoreBtn.addEventListener("click", scoreIP);
  clearBtn.addEventListener("click", () => {
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
  });

  ipInput.addEventListener("keydown", e => {
    if (e.key === "Enter") scoreIP();
  });

  // ── Main score function ───────────────────────────────────
  async function scoreIP() {
    const ip = ipInput.value.trim();
    if (!ip) return;

    if (!isValidIP(ip)) {
      showError("Invalid IP address format.");
      return;
    }

    setLoading(true);

    try {
      const res  = await fetch(`${API_BASE}/score/${encodeURIComponent(ip)}`);
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Scoring failed");

      renderResult(data);
      addAuditEntry(data);
      updateStats(data.riskLevel);

    } catch (err) {
      showError(err.message || "Service temporarily unavailable. Please retry.");
    } finally {
      setLoading(false);
    }
  }

  // ── Render result panel ───────────────────────────────────
  function renderResult(d) {
    const score      = d.score ?? 0;
    const riskLevel  = d.riskLevel ?? "LOW";
    const action     = d.action ?? "ALLOW";
    const geo        = d.geo    ?? {};
    const network    = d.network ?? {};
    const intel      = d.intelligence ?? {};
    const meta       = d.meta ?? {};

    const circumference = 2 * Math.PI * 52;
    const offset = circumference - (score / 100) * circumference;
    const strokeColor = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c" }[riskLevel] || "#00e87c";

    const signals = buildSignals(d);

    procTime.textContent = meta.processingMs ? `${meta.processingMs}ms` : "";

    resultBody.innerHTML = `
      <div class="score-header">
        <div class="score-ring-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="score-bg" cx="60" cy="60" r="52"/>
            <circle class="score-fill"
              cx="60" cy="60" r="52"
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
            <span>${riskIcon(riskLevel)}</span>
            <span>${riskLevel}</span>
          </div>
          <div class="action-badge ${action}">
            RECOMMENDED ACTION: <span class="action-val">${action}</span>
          </div>
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
          ${kv("Lat / Lon", geo.lat != null ? `${geo.lat}, ${geo.lon}` : "—")}
        </div>
        <div class="detail-card">
          <div class="detail-card-title">// Network</div>
          ${kv("ISP",  network.isp  || "—")}
          ${kv("ASN",  network.asn  || "—")}
          ${kv("Type", network.type || "—")}
          ${kv("Datacenter", intel.isDatacenter ? "Yes" : "No")}
          ${kv("Proxy / Tor", `${intel.isProxy ? "Proxy" : "—"} / ${intel.isTor ? "Tor" : "—"}`)}
        </div>
      </div>`;
  }

  // ── Build signals from API response ──────────────────────
  function buildSignals(d) {
    const signals = [];
    const score   = d.score ?? 0;
    const intel   = d.intelligence ?? {};
    const network = d.network ?? {};

    signals.push({
      category: "ABUSE",
      detail:   `Confidence score: ${score}/100`,
      severity: score > 80 ? "critical" : score > 60 ? "high" : score > 30 ? "medium" : "low"
    });

    if (intel.isDatacenter) signals.push({ category: "NETWORK", detail: "Datacenter / hosting provider", severity: "medium" });
    if (intel.isProxy)      signals.push({ category: "PROXY",   detail: "Proxy detected",               severity: "high" });
    if (intel.isTor)        signals.push({ category: "TOR",     detail: "Tor exit node detected",       severity: "critical" });

    const vel = intel.velocity ?? "LOW";
    signals.push({
      category: "VELOCITY",
      detail:   `Abuse report velocity: ${vel}`,
      severity: vel === "HIGH" ? "high" : vel === "MEDIUM" ? "medium" : "info"
    });

    if (network.type === "hosting") signals.push({ category: "HOSTING", detail: "Cloud / hosting IP range", severity: "medium" });

    return signals;
  }

  // ── Audit log ─────────────────────────────────────────────
  function addAuditEntry(d) {
    const entry = { ip: d.ip, score: d.score ?? 0, riskLevel: d.riskLevel ?? "LOW", ts: new Date() };
    auditEntries.unshift(entry);
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
        <span class="audit-ts">${fmtTime(e.ts)}</span>
      </div>`).join("");

    // Click audit item to re-score
    auditList.querySelectorAll(".audit-item").forEach(item => {
      item.addEventListener("click", () => {
        ipInput.value = item.dataset.ip;
        scoreIP();
      });
    });
  }

  // ── Stats ─────────────────────────────────────────────────
  function updateStats(riskLevel) {
    if (riskLevel in stats) {
      stats[riskLevel]++;
      const map = { CRITICAL: "stat-critical", HIGH: "stat-high", MEDIUM: "stat-medium", LOW: "stat-low" };
      const el = document.getElementById(map[riskLevel]);
      if (el) el.textContent = stats[riskLevel];
    }
  }

  // ── UI helpers ────────────────────────────────────────────
  function setLoading(on) {
    scoreBtn.disabled = on;
    if (on) {
      resultBody.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Analyzing ${escHtml(ipInput.value.trim())}…</span>
        </div>`;
      procTime.textContent = "";
    }
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
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function isValidIP(ip) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6  = /^[0-9a-fA-F:]+$/;
    return ipv4.test(ip) || ipv6.test(ip);
  }

  // ── Load initial stats from API ───────────────────────────
  async function loadStats() {
    try {
      const res  = await fetch(`${API_BASE}/stats`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.riskDistribution) {
        const map = { CRITICAL: "stat-critical", HIGH: "stat-high", MEDIUM: "stat-medium", LOW: "stat-low" };
        Object.entries(map).forEach(([risk, id]) => {
          const el = document.getElementById(id);
          if (el && data.riskDistribution[risk] != null) {
            el.textContent = data.riskDistribution[risk];
            stats[risk] = data.riskDistribution[risk];
          }
        });
      }
    } catch (_) {}
  }

  loadStats();
})();