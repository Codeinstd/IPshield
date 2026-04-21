console.log("JS LOADED"); // sanity check

window.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("ipInput");
  const searchBtn = document.getElementById("searchBtn");
  const scoreBtn = document.getElementById("scoreBtn");
  const clearBtn = document.getElementById("clearBtn");

  function scoreIP() {
    const ip = input.value.trim();
    console.log("Searching:", ip);
  }

  function clearResult() {
    input.value = "";
    console.log("Cleared");
  }

  searchBtn.addEventListener("click", scoreIP);
  scoreBtn.addEventListener("click", scoreIP);
  clearBtn.addEventListener("click", clearResult);

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") scoreIP();
  });
});

document.querySelectorAll(".quick-chip").forEach(el => {
  el.addEventListener("click", () => {
    const ip = el.dataset.ip;
    setIP(ip);
  });
});

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("scoreBtn").addEventListener("click", scoreIP);
  document.getElementById("clearBtn").addEventListener("click", clearResult);

  document.querySelectorAll(".quick-chip").forEach(el => {
    el.addEventListener("click", () => {
      setIP(el.dataset.ip);
    });
  });
});


  const API_BASE = '';
  let auditEntries = [];

  async function scoreIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;

    const btn = document.getElementById('scoreBtn');
    btn.disabled = true;
    btn.textContent = '...';
    document.getElementById('resultBody').innerHTML = '<div class="loading"><div class="spinner"></div><span>Analyzing ' + ip + '...</span></div>';
    document.getElementById('processingTime').textContent = '';

    try {
      const res = await fetch(`${API_BASE}/api/score/${encodeURIComponent(ip)}`);
      const data = await res.json();

      if (!res.ok) {
        document.getElementById('resultBody').innerHTML = `<div class="error-msg">Error: ${data.error || 'Unknown error'}</div>`;
        return;
      }

      renderResult(data);
      addAuditEntry(data);
      refreshStats();
    } catch (e) {
      document.getElementById('resultBody').innerHTML = `<div class="error-msg">Connection failed. Is the server running?<br><br>Start it with: <code>node index.js</code></div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'ANALYZE';
    }
  }

  function renderResult(d) {
    const scoreColor = d.riskLevel === 'CRITICAL' ? '#ff3355' : d.riskLevel === 'HIGH' ? '#ff7700' : d.riskLevel === 'MEDIUM' ? '#ffcc00' : '#00e87c';
    const circumference = 2 * Math.PI * 52;
    const offset = circumference * (1 - d.score / 100);

    const signalsHTML = d.signals.map((s, i) => `
      <div class="signal-item ${s.severity}" style="animation-delay:${i*0.05}s">
        <span class="sig-cat">${s.category}</span>
        <span class="sig-detail">${s.detail}</span>
        <span class="sig-sev">${s.severity}</span>
      </div>
    `).join('');

    const geoFlag = d.geo.country && d.geo.country !== 'UNKNOWN' ? `<span class="flag">${countryToFlag(d.geo.country)}</span>` : '';

    document.getElementById('processingTime').textContent = `${d.meta.processingMs}ms`;
    document.getElementById('resultBody').innerHTML = `
      <div class="score-header">
        <div class="score-ring-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="score-bg" cx="60" cy="60" r="52"/>
            <circle class="score-fill" cx="60" cy="60" r="52"
              stroke="${scoreColor}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${circumference}"
              id="scoreArc"/>
          </svg>
          <div class="score-center">
            <div class="score-num" style="color:${scoreColor}">${d.score}</div>
            <div class="score-max">/100</div>
          </div>
        </div>
        <div class="score-meta">
          <div class="score-ip">${d.ip}</div>
          <div class="risk-badge ${d.riskLevel}">
            <span>●</span> ${d.riskLevel}
          </div><br>
          <div class="action-badge ${d.action}">
            RECOMMENDED ACTION: <span class="action-val">${d.action}</span>
          </div>
        </div>
      </div>

      <div class="signals-title">// Risk Signals (${d.signals.length})</div>
      <div class="signal-list">${signalsHTML || '<div style="color:var(--text3);font-size:12px;">No significant signals detected</div>'}</div>

      <div class="detail-grid">
        <div class="detail-card">
          <div class="detail-card-title">Geolocation</div>
          <div class="kv"><span class="kv-key">Country</span><span class="kv-val">${geoFlag} ${d.geo.country || '—'}</span></div>
          <div class="kv"><span class="kv-key">Region</span><span class="kv-val">${d.geo.region || '—'}</span></div>
          <div class="kv"><span class="kv-key">City</span><span class="kv-val">${d.geo.city || '—'}</span></div>
          <div class="kv"><span class="kv-key">Timezone</span><span class="kv-val">${d.geo.timezone || '—'}</span></div>
          <div class="kv"><span class="kv-key">Coordinates</span><span class="kv-val">${d.geo.coordinates?.join(', ') || '—'}</span></div>
        </div>
        <div class="detail-card">
          <div class="detail-card-title">Network</div>
          <div class="kv"><span class="kv-key">IP Type</span><span class="kv-val">${d.network.type}</span></div>
          <div class="kv"><span class="kv-key">Datacenter</span><span class="kv-val" style="color:${d.network.isDatacenter?'var(--medium)':'var(--low)'}">${d.network.isDatacenter ? 'YES' : 'NO'}</span></div>
          <div class="kv"><span class="kv-key">Requests/5min</span><span class="kv-val">${d.behavior.requestsLast5Min}</span></div>
          <div class="kv"><span class="kv-key">Velocity</span><span class="kv-val">${d.behavior.velocityLabel}</span></div>
          <div class="kv"><span class="kv-key">First Seen</span><span class="kv-val">${new Date(d.behavior.firstSeen).toLocaleTimeString()}</span></div>
        </div>
        ${d.threatIntel ? `
        <div class="detail-card" style="grid-column: span 2; border: 1px solid rgba(255,51,85,0.3);">
          <div class="detail-card-title" style="color:var(--critical)">⚠ Threat Intelligence Match</div>
          <div class="kv"><span class="kv-key">Type</span><span class="kv-val" style="color:var(--critical)">${d.threatIntel.type}</span></div>
          <div class="kv"><span class="kv-key">Severity</span><span class="kv-val" style="color:var(--critical)">${d.threatIntel.severity.toUpperCase()}</span></div>
          <div class="kv"><span class="kv-key">Abuse Reports</span><span class="kv-val" style="color:var(--critical)">${d.threatIntel.reports.toLocaleString()}</span></div>
        </div>` : ''}
      </div>
    `;

    // Animate arc
    requestAnimationFrame(() => {
      const arc = document.getElementById('scoreArc');
      if (arc) arc.style.strokeDashoffset = offset;
    });
  }

  function addAuditEntry(data) {
    auditEntries.unshift(data);
    if (auditEntries.length > 100) auditEntries.pop();

    const list = document.getElementById('auditList');
    const ts = new Date(data.meta.scoredAt).toLocaleTimeString();
    const item = document.createElement('div');
    item.className = 'audit-item';
    item.innerHTML = `
      <span class="audit-ip">${data.ip}</span>
      <span class="audit-badge ${data.riskLevel}">${data.riskLevel}</span>
      <span class="audit-score ${data.riskLevel}">${data.score}</span>
      <span class="audit-ts">${ts}</span>
    `;
    item.onclick = () => {
      document.getElementById('ipInput').value = data.ip;
      renderResult(data);
    };

    if (list.firstChild?.textContent?.includes('No queries')) list.innerHTML = '';
    list.insertBefore(item, list.firstChild);
    document.getElementById('auditCount').textContent = `${auditEntries.length} entries`;
  }

  async function refreshStats() {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      const data = await res.json();
      const d = data.riskDistribution;
      document.getElementById('stat-critical').textContent = d.CRITICAL || 0;
      document.getElementById('stat-high').textContent = d.HIGH || 0;
      document.getElementById('stat-medium').textContent = d.MEDIUM || 0;
      document.getElementById('stat-low').textContent = d.LOW || 0;
    } catch {}
  }

  function clearResult() {
    document.getElementById('ipInput').value = '';
    document.getElementById('resultBody').innerHTML = `
      <div class="placeholder">
        <div class="placeholder-icon">⬡</div>
        <div class="placeholder-text">
          Enter an IP address above to begin analysis.<br>
          Risk scoring includes geo, threat intel,<br>
          network classification &amp; behavioral signals.
        </div>
      </div>`;
    document.getElementById('processingTime').textContent = '';
  }

  function setIP(ip) {
    document.getElementById('ipInput').value = ip;
    scoreIP();
  }

  function countryToFlag(code) {
    if (!code || code.length !== 2) return '';
    const offset = 127397;
    return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
  }

  // Enter key
  document.getElementById('ipInput').addEventListener('keydown', e => { if (e.key === 'Enter') scoreIP(); });

  // Init stats
  refreshStats();
  setInterval(refreshStats, 10000);
