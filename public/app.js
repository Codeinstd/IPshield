(() => {
  // const API     = "/api";
  const API_KEY = "b2bc8fe074823d37e59d57a80bbb67f6558bc145e8d6f6ef5111133a0159f020";

  let apiVersion = localStorage.getItem("ipshield_api_version") || "v2";
  const getAPI   = () => `/api/${apiVersion}`;
  let API = `/api/${apiVersion}`;

  const ipInput    = document.getElementById("ipInput");
  const scoreBtn   = document.getElementById("scoreBtn");
  const clearBtn   = document.getElementById("clearBtn");
  const resultBody = document.getElementById("resultBody");
  const procTime   = document.getElementById("processingTime");
  const auditList  = document.getElementById("auditList");
  const auditCount = document.getElementById("auditCount");
  // const apiDocsBtn = document.getElementById("apiDocsBtn");
  

  const sessionStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let auditEntries   = [];
  let map            = null;
  let mapMarker      = null;
  let isDark         = localStorage.getItem("ipshield_theme") !== "light";
  let currentIP      = null;
  let lastResult     = null;

  let auditFilters  = { q:"", risk:"", minScore:0, maxScore:100, proxy:null, tor:null, datacenter:null, sort:"date_desc" };
  let auditPage     = 0;
  let auditTotal    = 0;
  let usingDB       = false; 
  const AUDIT_PAGE_SIZE = 25;

  injectExtraUI();
  applyTheme(isDark); 
  injectAuditControls();
  initMap();
  loadStats();
  loadWatchlist();
  setupEventListeners();
  detectAndFillIP();

  // ── Auto-detect system IP 
  async function detectAndFillIP() {
    try {
      const res  = await fetch("https://api.ipify.org?format=json");
      const data = await res.json();
      if (data.ip && isValidIP(data.ip)) {
        ipInput.value = data.ip;
        ipInput.style.color = "var(--accent)";
        setTimeout(() => { ipInput.style.color = ""; }, 2000);
      }
    } catch (_) {}
  }

  // Switch API version
  function switchAPIVersion(version) {
  if (version !== "v1" && version !== "v2") 
    
  return;
  apiVersion = version;
  API        = `/api/${version}`;
  localStorage.setItem("ipshield_api_version", version);
 
  // Update version badge in header
  const badge = document.getElementById("apiBadge");
  if (badge) {
    badge.textContent       = version.toUpperCase();
    badge.style.color       = version === "v2" ?   "var(--accent)" : "var(--accent2)";
    badge.style.borderColor = version === "v2" ?   "var(--accent)" : "var(--accent2)";
    badge.style.background  = version === "v2" ?   "rgba(0,217,255,0.1)" : "rgba(0,217,255,0.1)";
  }

  // update version label
  

  document.getElementById(
    "dashboard-version"
  ).textContent = `${version}.0.0`;


    // Show/hide v2-only features
    const v2Only = document.querySelectorAll(".v2-only");
    v2Only.forEach(el => {
      el.style.display = version === "v2" ? "" : "none";
    });
  
    // Reload stats with new API version
    loadStats();
    loadWatchlist();
  
    toast(
    version === "v2"
      ? "Switched to v2 — All features enabled"
      : "Switched to v1 — Core features only",
    "success"
  );

  document.getElementById("mainMobileMenu").innerHTML = "";
  buildHamburgerMenu;
}

  // responsive nav 

    var _hamburgerInitialized = false;
    function buildHamburgerMenu() {
  const hamburger   = document.getElementById("mainHamburger");
  const menu        = document.getElementById("mainMobileMenu");
  const overlay     = document.getElementById("navOverlay");
  const headerRight = document.getElementById("headerRight");
 
 
  // ── Force overlay styles so it always covers everything ──
  if (overlay) {
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      z-index: 998;
      background: rgba(0,0,0,0.55);
      backdrop-filter: blur(1px);
      display: none;
    `;
  }
 
  // ── Force menu z-index above overlay ──
  menu.style.zIndex = "999";
 
  // ── Force hamburger button z-index ──
  hamburger.style.zIndex   = "1000";
  hamburger.style.position = "relative";
 
  // ── Rebuild menu items (safe to call on v1/v2 switch) ──
  menu.innerHTML = "";
 
  headerRight.querySelectorAll("button").forEach(btn => {
    if (btn.style.display === "none") return;
 
    const clone = document.createElement("button");
    clone.textContent = btn.textContent;
    clone.className   = btn.className;
 
    // Preserve V2 badge inline styles
    if (btn.id === "apiBadge") {
      clone.style.cssText = btn.style.cssText;
    }
 
    clone.addEventListener("click", () => {
      btn.click();
      _closeMenu();
    });
 
    menu.appendChild(clone);
  });
 
  // Status row
  const statusRow = document.createElement("div");
  statusRow.className = "mob-status";
  statusRow.innerHTML = `<span class="mob-dot"></span><span>SYSTEM LIVE</span>`;
  menu.appendChild(statusRow);
 
  // ── Attach listeners ONCE only ──
  if (!_hamburgerInitialized) {
    _hamburgerInitialized = true;
 
    hamburger.addEventListener("click", (e) => {
      e.stopPropagation();
      const isOpen = hamburger.getAttribute("aria-expanded") === "true";
      isOpen ? _closeMenu() : _openMenu();
    });
 
    if (overlay) {
      overlay.addEventListener("click", _closeMenu);
    }
 
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") _closeMenu();
    });
 
    document.addEventListener("click", (e) => {
      if (
        !e.target.closest("header") &&
        !e.target.closest("#navOverlay")
      ) {
        _closeMenu();
      }
    });
 
    window.matchMedia("(min-width: 769px)").addEventListener("change", (e) => {
      if (e.matches) _closeMenu();
    });
  }

}
 
function _openMenu() {
  const hamburger = document.getElementById("mainHamburger");
  const menu      = document.getElementById("mainMobileMenu");
  const overlay   = document.getElementById("navOverlay");
  if (!hamburger || !menu) return;
 
  hamburger.setAttribute("aria-expanded", "true");
  menu.classList.add("open");
  menu.removeAttribute("aria-hidden");
 
  if (overlay) {
    overlay.style.display = "block";   // show overlay
  }
}
 
function _closeMenu() {
  const hamburger = document.getElementById("mainHamburger");
  const menu      = document.getElementById("mainMobileMenu");
  const overlay   = document.getElementById("navOverlay");
  if (!hamburger || !menu) return;
 
  hamburger.setAttribute("aria-expanded", "false");
  menu.classList.remove("open");
  menu.setAttribute("aria-hidden", "true");
  hamburger.focus(); // fixes aria-hidden focus warning
 
  if (overlay) {
    overlay.style.display = "none";    // hide overlay
  }
}
  
  // ── Extra UI 
  function injectExtraUI() {
    const headerRight = document.querySelector(".header-right");

  if (headerRight) {
 
  // Theme toggle
  const toggle = document.createElement("button");
  toggle.className     = "btn btn-ghost";
  toggle.id            = "themeToggle";
  toggle.textContent   = isDark ? "☀ LIGHT" : "☾ DARK";
  toggle.style.cssText = "padding:6px 12px;font-size:11px;";
  toggle.addEventListener("click", toggleTheme);
  headerRight.prepend(toggle);
 
  // API version badge
  const badge = document.createElement("button");
  badge.id          = "apiBadge";
  badge.textContent = apiVersion.toUpperCase();
  badge.title       = "Click to switch API version";
  badge.style.cssText = `
    padding:4px 10px; margin-left:16px; margin-top:4px; font-size:10px;font-weight:700;font-family:inherit;
    border-radius:4px;cursor:pointer;letter-spacing:1px;
    color:${apiVersion === "v2" ? "var(--accent)" : "var(--accent2)"};
    border:1px solid ${apiVersion === "v2" ? "var(--accent)" : "var(--accent2)"};
    background:rgba(0,217,255,0.12);`;
  badge.addEventListener("click", showVersionPanel);
  headerRight.prepend(badge);
 
  // SIEM button
  const siemBtn         = document.createElement("button");
  siemBtn.className     = "btn btn-ghost";
  siemBtn.id            = "siemBtn";
  siemBtn.title         = "SIEM Webhook Settings";
  siemBtn.textContent   = "📡 SIEM";
  siemBtn.style.cssText = "padding:6px 12px;font-size:11px;";
  headerRight.prepend(siemBtn);
 
  // Blacklist button
  const blBtn = document.createElement("button");
  blBtn.className     = "btn btn-ghost v2-only";
  blBtn.id            = "blacklistBtn";
  blBtn.textContent   = "🚫 Blacklist";
  blBtn.style.cssText = "padding:6px 12px;font-size:11px;";
  if (apiVersion === "v1") blBtn.style.display = "none";
  headerRight.prepend(blBtn);
 
  // Cases button
  const casesBtn = document.createElement("button");
  casesBtn.className     = "btn btn-ghost v2-only";
  casesBtn.id            = "casesBtn";
  casesBtn.textContent   = "📁 Cases";
  casesBtn.style.cssText = "padding:6px 12px;font-size:11px;font-family:'JetBrains Mono', monospace;";
  if (apiVersion === "v1") casesBtn.style.display = "none";
  headerRight.prepend(casesBtn);
 
  buildHamburgerMenu();
}

    // Quick Tests Btn - Bulk Section
    const searchSection = document.querySelector(".search-section");
    if (searchSection) {
      const bulk = document.createElement("div");
      bulk.id = "bulkSection";
      bulk.style.cssText = "margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;";
      bulk.innerHTML = `

      <label style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;">Bulk:</label>
      <input type="file" id="csvUpload" accept=".csv,.txt" style="display:none">
      <button class="btn btn-ghost" id="csvBtn"      style="padding:8px 14px;font-size:11px;">↑ UPLOAD CSV</button>
      <button class="btn btn-ghost" id="exportBtn"   style="padding:8px 14px;font-size:11px;">↓ EXPORT LOG</button>
      <button class="btn btn-ghost" id="firewallBtn" style="padding:8px 14px;font-size:11px;">🛡 FIREWALL</button>
      <span id="bulkStatus" style="font-size:11px;color:var(--text2);"></span>`;
      searchSection.appendChild(bulk);
    }

    // Map panels
    const mainGrid = document.querySelector(".main-grid");
    if (mainGrid) {
      const row = document.createElement("div");
      row.id            = "mapWatchRow";
      row.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:24px;";

      // Score IP panels
      const mapWrap = document.createElement("div");
      mapWrap.id = "mapSection";
      mapWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;";
      mapWrap.innerHTML = `
        <div class="panel-header">
          <div class="panel-title" style="font-size:11px;font-weight:700;">Geo Map</div>
          <div id="mapLabel" style="font-size:11px;color:var(--text3);">Score an IP to see location</div>
        </div>
        <div id="mapContainer" style="height:320px;background:var(--bg2);display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;">Loading map…</div>`;

      
      // Watchlist Panel
      const watchWrap = document.createElement("div");
      watchWrap.id = "watchlistSection";
      watchWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;";
      watchWrap.innerHTML = `
        <div class="panel-header" style="justify-content:space-between;">
          <div class="panel-title" style="font-size:11px;font-weight:700;">Watchlist</div>
          <div style="display:flex;gap:8px;align-items:center;">
            <span id="watchlistCount" style="font-size:11px;color:var(--text3);">0 IPs</span>
            <button id="addWatchBtn" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">+ WATCH</button>
            <button id="pollBtn"     class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">↻ POLL</button>
          </div>
        </div>
        <div id="watchlistBody" style="flex:1;overflow-y:auto;">
          <div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No IPs being watched</div>
        </div>
        <div id="monitorStatus" style="padding:8px 16px;font-size:10px;color:var(--text3);border-top:1px solid var(--border);"></div>`;

      row.appendChild(mapWrap);
      row.appendChild(watchWrap);
      mainGrid.after(row);

      const style = document.createElement("style");
      style.textContent = "@media(max-width:768px){#mapWatchRow{grid-template-columns:1fr!important}}";
      document.head.appendChild(style);
    }

    // Responsive label switching
    const mq = window.matchMedia("(max-width: 480px)");
    function updateLabels(e) {
      document.querySelectorAll(".desktop-label").forEach(el => el.style.display = e.matches ? "none" : "");
      document.querySelectorAll(".mobile-label").forEach(el => el.style.display = e.matches ? "inline" : "none");
    }
    mq.addEventListener("change", updateLabels);
    updateLabels(mq);

      // mobile responsive 
    function getWatchlistMaxHeight() {
    return window.innerWidth < 640 ? "200px" : "260px";
  }

  buildHamburgerMenu(); 


  }



  // Versioning Panel
  async function showVersionPanel() {
  document.getElementById("versionModal")?.remove();
 
  const overlay = document.createElement("div");
  overlay.id = "versionModal";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;padding:24px;";
 
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:680px;overflow:hidden;max-height:90vh;display:flex;flex-direction:column;";
 
  const features = [
    { label:"IP Scoring (single + batch)",         v1:true,  v2:true  },
    { label:"Threat Feeds (Feodo, Spamhaus, OTX)",  v1:true,  v2:true  },
    { label:"WHOIS / RDAP Deep Dive",               v1:true,  v2:true  },
    { label:"Reverse DNS + FCrDNS Verification",    v1:true,  v2:true  },
    { label:"Geo Map (CartoDB tiles)",              v1:true,  v2:true  },
    { label:"Watchlist & Score Monitoring",         v1:true,  v2:true  },
    { label:"Audit Log (search, filter, sort)",     v1:true,  v2:true  },
    { label:"Score Timeline Chart",                 v1:true,  v2:true  },
    { label:"PDF Threat Reports",                   v1:true,  v2:true  },
    { label:"Firewall Rule Export (10 formats)",    v1:true,  v2:true  },
    { label:"SIEM Webhook Integration",             v1:true,  v2:true  },
    { label:"Rate Limit Feedback UI",               v1:true,  v2:true  },
    { label:"Swagger Interactive API Docs",         v1:true,  v2:true  },
    { label:"IP Blacklist Management",              v1:false, v2:true  },
    { label:"Blacklist Export (8 formats)",         v1:false, v2:true  },
    { label:"Blacklist Status in Score Results",    v1:false, v2:true  },
    { label:"Case Management",                      v1:false, v2:true  },
    { label:"Case IP Attachments",                  v1:false, v2:true  },
    { label:"Case Investigation Notes",             v1:false, v2:true  },
    { label:"Quick Attach IP to Case",              v1:false, v2:true  },
  ];
 
  modal.innerHTML = `
    <!-- Header -->
    <div style="padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;">
      <div>
        <div style="font-size:14px;font-weight:700;color:var(--text);">IPshield Version</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px;">
          Currently using <strong style="color:${apiVersion === "v2" ? "var(--accent)" : "var(--accent2)"};">${apiVersion.toUpperCase()}</strong>
          — preference saved across sessions
        </div>
      </div>
      <button id="verClose" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
    </div>
 
    <!-- Version toggle cards -->
    <div>
 
      <!-- v1 -->
      <div id="v1Card" style="padding:20px 24px;border-right:1px solid var(--border);border-bottom:1px solid var(--border);cursor:pointer;
            background:${apiVersion === "v1" ? "rgba(61,122,107,0.08)" : "transparent"};
            border-left:3px solid ${apiVersion === "v1" ? "var(--accent2)" : "transparent"};"
            data-version="v1">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;pointer-events:none;">
          <span style="font-size:20px;font-weight:800;color:#0099cc;">v1</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,217,255,0.12);color:#0099cc;font-weight:700;">STABLE</span>
          ${apiVersion === "v1" ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,232,124,0.1);color:var(--low);font-weight:700;">ACTIVE</span>` : ""}
        </div>
        <div style="font-size:11px;color:var(--text2);line-height:1.6;pointer-events:none;">
          Core intelligence — scoring, WHOIS, watchlist, audit, SIEM and PDF reports.
        </div>
        <div style="margin-top:12px;display:flex;gap:8px;pointer-events:none;">
          <span style="font-size:10px;background:var(--bg);padding:3px 8px;border-radius:4px;color:var(--text2);border:0.8px solid var(--border);border-radius:4px;">/api/v1</span>
        </div>
      </div>
 
      <!-- v2 -->
      <div id="v2Card" style="padding:20px 24px;border-bottom:1px solid var(--border);cursor:pointer;
            background:${apiVersion === "v2" ? "rgba(0,217,255,0.06)" : "transparent"};
            border-left:3px solid ${apiVersion === "v2" ? "var(--accent)" : "transparent"};"
            data-version="v2">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;pointer-events:none;">
          <span style="font-size:20px;font-weight:800;color:var(--accent);">v2</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,217,255,0.12);color:var(--accent);font-weight:700;">LATEST</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:3px;background:var(--bg2);color:var(--text2);font-weight:700;">DEFAULT</span>
          ${apiVersion === "v2" ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,232,124,0.1);color:var(--low);font-weight:700;">ACTIVE</span>` : ""}
        </div>
        <div style="font-size:11px;color:var(--text2);line-height:1.6;pointer-events:none;">
          Full platform — everything in v1 plus Blacklist and Case Management.
        </div>
        <div style="margin-top:12px;display:flex;gap:8px;pointer-events:none;">
          <span style="font-size:10px;background:var(--bg);padding:3px 8px;border-radius:4px;color:var(--text2);border:0.8px solid var(--border);border-radius:4px;">/api/v2</span>
          <span style="font-size:10px;background:var(--bg);padding:3px 8px;border-radius:4px;color:var(--text2);border:0.8px solid var(--border);border-radius:4px;">/api</span>
        </div>
      </div>
    </div>
 
    <!-- Feature comparison -->
    <div style="overflow-y:auto;flex:1;">
      <table style="width:100%;border-collapse:collapse;font-size:11px;">
        <thead>
          <tr style="background:var(--bg2);position:sticky;top:0;z-index:1;">
            <th style="padding:10px 16px;text-align:left;color:var(--text);font-weight:700;font-size:10px;letter-spacing:1px;">FEATURE</th>
            <th style="padding:10px 20px;text-align:center;color:var(--accent2);font-weight:700;font-size:10px;width:80px;">V1</th>
            <th style="padding:10px 20px;text-align:center;color:var(--accent);font-weight:700;font-size:10px;width:80px;">V2</th>
          </tr>
        </thead>
        <tbody>
          ${features.map((f, i) => `
            <tr style="border-top:1px solid var(--border);${i % 2 !== 0 ? "background:var(--bg);" : ""}${!f.v1 ? "background:rgba(0,217,255,0.02);" : ""}">
              <td style="padding:9px 16px;color:${!f.v1 ? "var(--accent)" : "var(--text2)"};${!f.v1 ? "font-weight:600;" : ""}">
                ${!f.v1 ? '<span style="color:var(--accent);margin-right:4px;">✦</span>' : ""}${escHtml(f.label)}
              </td>
              <td style="padding:9px 16px;text-align:center;">
                ${f.v1 ? `<span style="color:var(--critical);font-size:15px;font-weight:700;">✓</span>` : `<span style="color:var(--text3);font-size:13px;">—</span>`}
              </td>
              <td style="padding:9px 16px;text-align:center;">
                ${f.v2 ? `<span style="color:var(--low);font-size:15px;font-weight:700;">✓</span>` : `<span style="color:var(--text3);font-size:13px;">—</span>`}
              </td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
 
    <!-- Footer with docs links -->
    <div style="padding:12px 24px;border-top:1px solid var(--border);background:var(--bg1);display:flex;justify-content:space-between;align-items:center;flex-shrink:0;flex-wrap:wrap;gap:8px;">
      <div style="font-size:10px;color:var(--text3);">↑ Click a version card to switch</div>
      <div style="display:flex;gap:8px;">
        <a href="/api/v1/docs" target="_blank"
          style="font-size:11px;color:var(--accent2);text-decoration:none;padding:4px 10px;border:1px solid var(--accent2);border-radius:4px;">
          v1 Docs ↗
        </a>
        <a href="/api/v2/docs" target="_blank"
          style="font-size:11px;color:var(--accent);text-decoration:none;padding:4px 10px;border:1px solid var(--accent);border-radius:4px;">
          v2 Docs ↗
        </a>
      </div>
    </div>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  // Close
  document.getElementById("verClose").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  // Version card click — switch API version
  modal.querySelectorAll("[data-version]").forEach(card => {
    card.addEventListener("mouseover", () => {
      if (card.dataset.version !== apiVersion) card.style.opacity = "0.8";
    });
    card.addEventListener("mouseout", () => { card.style.opacity = "1"; });
 
    card.addEventListener("click", () => {
      const version = card.dataset.version;
      if (version === apiVersion) return; // already active
 
      switchAPIVersion(version);
      overlay.remove();
    });
  });
}

  // apply Filter
  function applyFilters(entries) {
  return entries.filter(e => {
    const f = auditFilters;

    // Search — check ip, country, isp
    if (f.q && f.q.trim()) {
      const q = f.q.trim().toLowerCase();
      const ip      = (e.ip              || "").toLowerCase();
      const country = (e.geo?.country    || e.country || "").toLowerCase();
      const isp     = (e.network?.isp    || e.isp     || "").toLowerCase();
      if (!ip.includes(q) && !country.includes(q) && !isp.includes(q)) return false;
    }

    // Risk — handle both camelCase (session) and snake_case (DB)
    if (f.risk) {
      const risk = e.riskLevel || e.risk_level || "";
      if (risk !== f.risk) return false;
    }

    // Score
    if (f.minScore > 0   && (e.score ?? 0) < f.minScore) return false;
    if (f.maxScore < 100 && (e.score ?? 0) > f.maxScore) return false;

    // Boolean toggles — handle both formats
    if (f.proxy !== null) {
      const isProxy = e.intelligence?.isProxy ?? e.is_proxy ?? false;
      if (!!isProxy !== f.proxy) return false;
    }
    if (f.tor !== null) {
      const isTor = e.intelligence?.isTor ?? e.is_tor ?? false;
      if (!!isTor !== f.tor) return false;
    }
    if (f.datacenter !== null) {
      const isDC = e.intelligence?.isDatacenter ?? e.is_dc ?? false;
      if (!!isDC !== f.datacenter) return false;
    }

    return true;
  });
}
   // Inject audit controls
  function injectAuditControls() {
  const auditPanel = document.querySelector(".audit-panel");
  if (!auditPanel) return;
 
  const controls = document.createElement("div");
  controls.id = "auditControls";
  controls.style.cssText = "padding:12px 16px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:10px;";
  controls.innerHTML = `
    <!-- Search bar -->
    <div style="position:relative;">
      <input id="auditSearch" type="text" placeholder="Search IP, country, ISP…"
        maxlength="45"
        style="width:100%;padding:8px 36px 8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;
               color:var(--text);font-family:inherit;font-size:12px;outline:none;">
      <button id="auditSearchClear" title="Clear search"
        style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;display:none;">✕</button>
    </div>
 
    <!-- Risk filter chips -->
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
      <span style="font-size:10px;color:var(--text3);letter-spacing:1px;">RISK:</span>
      ${["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(r => `
        <button class="audit-risk-chip" data-risk="${r === "ALL" ? "" : r}"
          style="padding:3px 10px;border-radius:12px;border:1px solid ${r==="ALL"?"var(--accent)":"var(--border)"};
                 background:${r==="ALL"?"rgba(0,217,255,0.1)":"transparent"};
                 color:${r==="ALL"?"var(--accent)":"var(--text3)"};
                 font-size:10px;font-weight:600;cursor:pointer;letter-spacing:0.5px;font-family:inherit;">
          ${r}
        </button>`).join("")}
    </div>
 
    <!-- Score range + toggles row -->
    <div style="display:block;align-items:center;gap:6px;font-size:11px;color:var(--text3);">
    <span>Score:</span>
    <input id="auditMinScore" type="number" min="0" max="100" value="0"
      inputmode="numeric"
      style="width:44px;padding:3px 6px;background:var(--bg1);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
    <span>–</span>
    <input id="auditMaxScore" type="number" min="0" max="100" value="100"
      inputmode="numeric"
      style="width:50px;padding:3px 6px;background:var(--bg1);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
  
    <button class="audit-toggle" data-key="proxy" data-val="null"
          style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
          PROXY
        </button>
        <button class="audit-toggle" data-key="tor" data-val="null"
          style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
          TOR
        </button>
        <button class="audit-toggle" data-key="datacenter" data-val="null"
          style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
          DC
        </button>
      </div>
      <div style="display:flex;gap:6px;align-items:center;">
        <select id="auditSort"
          style="padding:3px 8px;background:var(--bg1);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;cursor:pointer;">
          <option value="date_desc">Newest first</option>
          <option value="date_asc">Oldest first</option>
          <option value="score_desc">Highest score</option>
          <option value="score_asc">Lowest score</option>
        </select>
        <button id="auditLoadDB" class="btn btn-ghost"
          style="padding:3px 10px;font-size:10px;letter-spacing:1px;" title="Load full history from database">
          ↓ DB
        </button>
        <button id="auditReset" class="btn btn-ghost"
          style="padding:3px 10px;font-size:10px;letter-spacing:1px;">
          RESET
        </button>
      </div>
    </div>
 
    <!-- Result count -->
    <div id="auditFilterStatus" style="font-size:10px;color:var(--text3);"></div>`;
 
  // Insert before audit list
  const auditListEl = document.getElementById("auditList");
  if (auditListEl) auditPanel.insertBefore(controls, auditListEl);
 
  // Wire up events
  let searchTimer;
  document.getElementById("auditSearch").addEventListener("input", e => {
  const val      = e.target.value;
  const clearBtn = document.getElementById("auditSearchClear");
  if (clearBtn) clearBtn.style.display = val ? "block" : "none";
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    auditFilters.q = val.trim(); 
    auditPage = 0;
    renderAudit();
  }, 300);
});
 
  document.getElementById("auditSearchClear")?.addEventListener("click", () => {
    const input = document.getElementById("auditSearch");
    if (input) { input.value = ""; document.getElementById("auditSearchClear").style.display = "none"; }
    auditFilters.q = ""; auditPage = 0; renderAudit();
  });
 
  document.querySelectorAll(".audit-risk-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    document.querySelectorAll(".audit-risk-chip").forEach(c => {
      c.style.borderColor = "var(--border)";
      c.style.background  = "transparent";
      c.style.color       = "var(--text3)";
    });
    chip.style.borderColor = "var(--accent)";
    chip.style.background  = "rgba(0,217,255,0.1)";
    chip.style.color       = "var(--accent)";
    auditFilters.risk = chip.dataset.risk; 
    auditPage = 0;
    renderAudit(); 
  });
});
 
  document.getElementById("auditMinScore")?.addEventListener("change", e => {
    auditFilters.minScore = parseInt(e.target.value) || 0; auditPage = 0; renderAudit();
  });
  document.getElementById("auditMaxScore")?.addEventListener("change", e => {
    auditFilters.maxScore = parseInt(e.target.value) ?? 100; auditPage = 0; renderAudit();
  });
 
  document.querySelectorAll(".audit-toggle").forEach(btn => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.key;
      const cur = auditFilters[key];
      // Cycle: null → true → false → null
      auditFilters[key] = cur === null ? true : cur === true ? false : null;
      btn.style.background   = auditFilters[key] === true  ? "rgba(0,232,124,0.15)" :
                               auditFilters[key] === false ? "rgba(255,51,85,0.15)" : "transparent";
      btn.style.borderColor  = auditFilters[key] === true  ? "var(--low)" :
                               auditFilters[key] === false ? "var(--critical)" : "var(--border)";
      btn.style.color        = auditFilters[key] === true  ? "var(--low)" :
                               auditFilters[key] === false ? "var(--critical)" : "var(--text3)";
      auditPage = 0; renderAudit();
    });
  });
 
  document.getElementById("auditSort")?.addEventListener("change", e => {
    auditFilters.sort = e.target.value; auditPage = 0; renderAudit();
  });
 
  document.getElementById("auditLoadDB")?.addEventListener("click", async () => {
    usingDB = true; auditPage = 0;
    await fetchAndRenderFromDB();
  });
 
  document.getElementById("auditReset")?.addEventListener("click", () => {
    auditFilters = { q:"", risk:"", minScore:0, maxScore:100, proxy:null, tor:null, datacenter:null, sort:"date_desc" };
    usingDB      = false;
    auditPage    = 0;
    // Reset UI
    const input = document.getElementById("auditSearch");
    if (input) input.value = "";
    document.querySelectorAll(".audit-risk-chip").forEach((c, i) => {
      c.style.borderColor = i===0?"var(--accent)":"var(--border)";
      c.style.background  = i===0?"rgba(0,217,255,0.1)":"transparent";
      c.style.color       = i===0?"var(--accent)":"var(--text3)";
    });
    document.querySelectorAll(".audit-toggle").forEach(b => {
      b.style.background = "transparent"; b.style.borderColor = "var(--border)"; b.style.color = "var(--text3)";
    });
    const minEl = document.getElementById("auditMinScore"); if (minEl) minEl.value = "0";
    const maxEl = document.getElementById("auditMaxScore"); if (maxEl) maxEl.value = "100";
    const sort  = document.getElementById("auditSort");     if (sort)  sort.value  = "date_desc";
    renderAudit();
  });
}

  // timeline history
  async function showTimeline(ip) {
  if (!ip || !isValidIP(ip)) { setBulkStatus("No IP to show history for."); return; }
 
  // Build modal
  const overlay = document.createElement("div");
  overlay.id = "timelineModal";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;padding:24px;";
 
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:720px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;";
 
  modal.innerHTML = `
    <div style="padding:18px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-size:13px;font-weight:700;color:var(--text);">Score Timeline</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px;font-family:'JetBrains Mono',monospace;">${escHtml(ip)}</div>
      </div>
      <button id="timelineClose" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
    </div>
    <div id="timelineContent" style="flex:1;overflow-y:auto;padding:24px;background:var(--bg2);">
      <div style="text-align:center;color:var(--text3);font-size:12px;padding:40px 0;">
        <div class="spinner" style="margin:0 auto 12px;"></div>
        Loading score history…
      </div>
    </div>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  document.getElementById("timelineClose").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  // Fetch data
  try {
    const res  = await fetch(`${API}/timeline/${encodeURIComponent(ip)}?limit=100`, {
      headers: { "x-api-key": API_KEY }
    });
    const data = await res.json();
    renderTimeline(data, document.getElementById("timelineContent"));
  } catch (err) {
    document.getElementById("timelineContent").innerHTML =
      `<div style="padding:24px;color:var(--critical);font-size:12px;">⚠ Failed to load history: ${escHtml(err.message)}</div>`;
  }
}

  // Blacklistbanner
  function blacklistBanner(bl) {
    if (!bl) return "";
    const sevColor = {
      CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c"
    }[bl.severity] || "#ff7700";

    return `
      <div style="
        display:flex;align-items:flex-start;gap:12px;
        padding:12px 16px;margin-bottom:16px;
        background:rgba(255,119,0,0.08);
        border:1px solid ${sevColor};
        border-left:4px solid ${sevColor};
        border-radius:8px;">
        <span style="font-size:20px;flex-shrink:0;">🚫</span>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
            <span style="font-size:11px;font-weight:700;color:${sevColor};letter-spacing:1px;">
              BLACKLISTED
            </span>
            <span style="font-size:10px;padding:2px 8px;border-radius:3px;
              background:${sevColor}22;color:${sevColor};font-weight:700;">
              ${escHtml(bl.severity)}
            </span>
            ${bl.category ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;
              background:var(--bg3);color:var(--text2);">${escHtml(bl.category)}</span>` : ""}
            ${(bl.tags||[]).map(t => `<span style="font-size:10px;padding:2px 6px;border-radius:3px;
              background:var(--bg3);color:var(--text3);">${escHtml(t)}</span>`).join("")}
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;">
            ${bl.reason ? `
              <div style="grid-column:1/-1;font-size:11px;color:var(--text2);margin-bottom:2px;">
                <span style="color:var(--text3);">Reason:</span> ${escHtml(bl.reason)}
              </div>` : ""}
            ${bl.added_by ? `<div style="font-size:10px;color:var(--text3);">
              Added by: <span style="color:var(--text2);">${escHtml(bl.added_by)}</span></div>` : ""}
            ${bl.added_at ? `<div style="font-size:10px;color:var(--text3);">
              Added: <span style="color:var(--text2);">${new Date(bl.added_at).toLocaleDateString()}</span></div>` : ""}
            ${bl.expires_at ? `<div style="font-size:10px;color:var(--text3);">
              Expires: <span style="color:var(--text2);">${new Date(bl.expires_at).toLocaleDateString()}</span></div>` : ""}
            <div style="font-size:10px;color:var(--text3);">
              Entry ID: <span style="color:var(--text2);">#${bl.id}</span>
            </div>
          </div>
        </div>
        <button onclick="showBlacklistPanel()" style="
          background:none;border:1px solid ${sevColor};color:${sevColor};
          border-radius:4px;padding:4px 10px;font-size:10px;cursor:pointer;
          font-family:inherit;flex-shrink:0;white-space:nowrap;">
          View List
        </button>
      </div>`;
  }

  // blacklist panel
  async function showBlacklistPanel() {
  const overlay = document.createElement("div");
  overlay.id = "blacklistModal";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;padding:16px;";
 
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:900px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden;";
 
  modal.innerHTML = `
    <div style="padding:16px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
      <div>
        <div style="font-size:14px;font-weight:700;color:var(--text);">Blacklist IP</div>
        <div id="blStats" style="font-size:11px;color:var(--text3);margin-top:2px;">Blacklisted Details</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <button id="blAddBtn"    class="btn btn-primary" style="padding:6px 14px;font-size:11px;">+ Add IP</button>
        <button id="blExportBtn" class="btn btn-ghost"   style="padding:6px 14px;font-size:11px;">↓ Export</button>
        <button id="blCloseBtn" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
      </div>
    </div>
 
    <!-- Filters -->
    <div style="padding:12px 24px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <input id="blSearch" type="text" placeholder="Search IP, reason, category…" maxlength="100"
        style="flex:1;min-width:160px;padding:7px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;">
      <select id="blSevFilter" style="padding:7px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
        <option value="">All Severities</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
      <select id="blStatusFilter" style="padding:7px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
        <option value="active">Active</option>
        <option value="expired">Expired</option>
        <option value="">All</option>
      </select>
      <button id="blBulkDeleteBtn" class="btn btn-ghost" style="padding:6px 12px;font-size:11px;color:var(--critical);border-color:var(--critical);display:none;">
        Delete Selected
      </button>
    </div>
 
    <!-- Table -->
    <div style="flex:1;overflow-y:auto;" id="blTableWrap">
      <div style="padding:40px;text-align:center;color:var(--text3);">
        <div class="spinner" style="margin:0 auto 12px;"></div>Loading blacklist…
      </div>
    </div>
 
    <!-- Add/Edit form (hidden initially) -->
    <div id="blForm" style="display:none;padding:20px 24px;border-top:1px solid var(--border);background:var(--bg2);">
      <div style="font-size:11px;font-weight:600;color:var(--text);letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;" id="blFormTitle">Add to Blacklist</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">IP ADDRESS</label>
          <input id="blFormIp" type="text" maxlength="45" placeholder="e.g. 185.220.101.1"
            style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
        <div>
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">SEVERITY</label>
          <select id="blFormSeverity" style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
            <option value="HIGH" selected>HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
        <div>
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">CATEGORY</label>
          <select id="blFormCategory" style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
            <option value="">Select category…</option>
            ${["Malware","Botnet","C2","Scanner","Spam","Proxy","Tor","Phishing","Brute Force","Manual","Other"]
              .map(c => `<option value="${c}">${c}</option>`).join("")}
          </select>
        </div>
        <div>
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">EXPIRES AT (optional)</label>
          <input id="blFormExpiry" type="datetime-local"
            style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;box-sizing:border-box;">
        </div>
        <div style="grid-column:1/-1;">
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">REASON</label>
          <input id="blFormReason" type="text" maxlength="500" placeholder="Why is this IP blacklisted?"
            style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
        <div style="grid-column:1/-1;">
          <label style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3);display:block;margin-bottom:4px;">TAGS (comma-separated)</label>
          <input id="blFormTags" type="text" maxlength="200" placeholder="e.g. fraud, scam, phishing, malware, incident-2026"
            style="width:100%;padding:8px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end;">
        <div id="blFormError" style="flex:1;font-size:11px;color:var(--critical);align-self:center;"></div>
        <button id="blFormCancel" class="btn btn-ghost" style="padding:7px 16px;font-family:'JetBrains Mono',monospace;font-size:12px;">Cancel</button>
        <button id="blFormSave"   class="btn btn-primary" style="padding:7px 16px;font-family:'JetBrains Mono',monospace;font-size:12px;">Save</button>
      </div>
    </div>
 
    <!-- Export panel (hidden) -->
    <div id="blExportPanel" style="display:none;padding:16px 24px;border-top:1px solid var(--border);background:var(--bg);">
      <div style="font-size:11px;color:var(--text3);letter-spacing:2px;margin-bottom:12px;">EXPORT FORMAT</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${["txt","csv","json","iptables","nginx","cisco","paloalto","windows"].map(fmt => `
          <button class="bl-export-fmt btn btn-ghost" data-fmt="${fmt}"
            style="padding:6px 14px;font-size:11px;text-transform:uppercase;">${fmt}</button>`).join("")}
      </div>
    </div>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  // State
  let editingId    = null;
  let selectedIds  = new Set();
  let currentQuery = { q: "", severity: "", status: "active" };
 
  // ── Load & render
  async function loadBlacklist() {
    const params = new URLSearchParams({
      limit:  200,
      status: currentQuery.status || "active"
    });
    if (currentQuery.q)        params.set("q",        currentQuery.q);
    if (currentQuery.severity) params.set("severity", currentQuery.severity);
 
    try {
      const res  = await fetch(`${API}/blacklist?${params}`, { headers: { "x-api-key": API_KEY } });
      const data = await res.json();
      renderStats(data.stats);
      renderTable(data.entries || []);
    } catch (err) {
      document.getElementById("blTableWrap").innerHTML =
        `<div style="padding:24px;color:var(--critical);font-size:12px;">Error: ${escHtml(err.message)}</div>`;
    }
  }
 
  function renderStats(stats) {
    if (!stats) return;
    const el = document.getElementById("blStats");
    if (el) el.textContent = `${stats.active || 0} active  ·  ${stats.total || 0} total  ·  ${stats.expired || 0} expired`;
  }
 
  function renderTable(entries) {
    selectedIds.clear();
    updateBulkBtn();
    const wrap = document.getElementById("blTableWrap");
 
    if (!entries.length) {
      wrap.innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-size:12px;">
        No entries found${currentQuery.q || currentQuery.severity ? " matching filters" : ""}.</div>`;
      return;
    }
 
    const sevColor = { CRITICAL:"var(--critical)", HIGH:"var(--high)", MEDIUM:"var(--medium)", LOW:"var(--low)" };
 
    wrap.innerHTML = `
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead>
          <tr style="background:var(--bg2);border-bottom:1px solid var(--border);">
            <th style="padding:10px 8px 10px 16px;text-align:left;">
              <input type="checkbox" id="blSelectAll" style="cursor:pointer;">
            </th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">IP</th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">SEVERITY</th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">CATEGORY</th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">REASON</th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">ADDED</th>
            <th style="padding:10px 8px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;">EXPIRES</th>
            <th style="padding:10px 16px 10px 8px;text-align:right;color:var(--text3);font-size:10px;letter-spacing:1px;">ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          ${entries.map((e, i) => {
            const color   = sevColor[e.severity] || "var(--text2)";
            const expired = e.expired;
            const tags    = (e.tags || []).slice(0, 3);
            const added   = e.added_at ? new Date(e.added_at).toLocaleDateString() : "—";
            const expires = e.expires_at ? new Date(e.expires_at).toLocaleDateString() : "Never";
            return `
              <tr class="bl-row" data-id="${e.id}"
                style="border-bottom:1px solid var(--border);${expired ? "opacity:0.5;" : ""}${i % 2 === 0 ? "" : "background:var(--bg);"}">
                <td style="padding:10px 8px 10px 16px;">
                  <input type="checkbox" class="bl-check" data-id="${e.id}" style="cursor:pointer;">
                </td>
                <td style="padding:10px 8px;">
                  <div style="font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--text);">${escHtml(e.ip)}</div>
                  ${tags.length ? `<div style="display:flex;gap:4px;margin-top:3px;flex-wrap:wrap;">
                    ${tags.map(t => `<span style="font-size:9px;padding:1px 5px;border-radius:2px;background:var(--bg3);color:var(--text3);">${escHtml(t)}</span>`).join("")}
                  </div>` : ""}
                </td>
                <td style="padding:10px 8px;">
                  <span style="font-size:10px;font-weight:700;color:${color};padding:2px 8px;border-radius:3px;background:${color}22;">${e.severity}</span>
                </td>
                <td style="padding:10px 8px;color:var(--text2);">${escHtml(e.category || "—")}</td>
                <td style="padding:10px 8px;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                    title="${escHtml(e.reason || "")}">${escHtml(e.reason || "—")}</td>
                <td style="padding:10px 8px;color:var(--text3);white-space:nowrap;">${added}</td>
                <td style="padding:10px 8px;color:${expired ? "var(--critical)" : "var(--text3)"};white-space:nowrap;">
                  ${expired ? "⚠ Expired" : expires}
                </td>
                <td style="padding:10px 16px 10px 8px;text-align:right;white-space:nowrap;">
                  <button class="bl-edit-btn btn btn-ghost" data-id="${e.id}"
                    style="padding:3px 10px;font-size:10px;margin-right:4px;">Edit</button>
                  <button class="bl-del-btn btn btn-ghost" data-id="${e.id}"
                    style="padding:3px 10px;font-size:10px;color:var(--critical);border-color:var(--critical);">Del</button>
                </td>
              </tr>`;
          }).join("")}
        </tbody>
      </table>`;
 
    // Select all checkbox
    document.getElementById("blSelectAll")?.addEventListener("change", e => {
      document.querySelectorAll(".bl-check").forEach(cb => {
        cb.checked = e.target.checked;
        const id   = parseInt(cb.dataset.id);
        e.target.checked ? selectedIds.add(id) : selectedIds.delete(id);
      });
      updateBulkBtn();
    });
 
    // Individual checkboxes
    document.querySelectorAll(".bl-check").forEach(cb => {
      cb.addEventListener("change", e => {
        const id = parseInt(e.target.dataset.id);
        e.target.checked ? selectedIds.add(id) : selectedIds.delete(id);
        updateBulkBtn();
      });
    });
 
    // Edit buttons
    document.querySelectorAll(".bl-edit-btn").forEach(btn => {
      btn.addEventListener("click", () => openEditForm(parseInt(btn.dataset.id), entries));
    });
 
    // Delete buttons
    document.querySelectorAll(".bl-del-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!confirm("Delete this entry?")) return;
        await fetch(`${API}/blacklist/${btn.dataset.id}`, {
          method: "DELETE", headers: { "x-api-key": API_KEY }
        });
        loadBlacklist();
      });
    });
 
    // Click IP to score it
    document.querySelectorAll(".bl-row").forEach(row => {
      row.addEventListener("click", e => {
        if (e.target.tagName === "INPUT" || e.target.tagName === "BUTTON") return;
        const ip = row.querySelector("[style*='JetBrains']")?.textContent?.trim();
        if (ip) { ipInput.value = ip; overlay.remove(); scoreIP(); }
      });
    });
  }
 
  function updateBulkBtn() {
    const btn = document.getElementById("blBulkDeleteBtn");
    if (btn) {
      btn.style.display = selectedIds.size > 0 ? "inline-flex" : "none";
      btn.textContent   = `Delete ${selectedIds.size} Selected`;
    }
  }
 
  // ── Form helpers 
  function openAddForm() {
    editingId = null;
    document.getElementById("blFormTitle").textContent      = "Add to Blacklist";
    document.getElementById("blFormIp").value               = currentIP || "";
    document.getElementById("blFormIp").disabled            = false;
    document.getElementById("blFormSeverity").value         = "HIGH";
    document.getElementById("blFormCategory").value         = "";
    document.getElementById("blFormReason").value           = "";
    document.getElementById("blFormExpiry").value           = "";
    document.getElementById("blFormTags").value             = "";
    document.getElementById("blFormError").textContent      = "";
    document.getElementById("blForm").style.display         = "block";
    document.getElementById("blExportPanel").style.display  = "none";
    document.getElementById("blFormIp").focus();
  }
 
  function openEditForm(id, entries) {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;
    editingId = id;
    document.getElementById("blFormTitle").textContent      = "Edit Blacklist";
    document.getElementById("blFormIp").value               = entry.ip;
    document.getElementById("blFormIp").disabled            = true;
    document.getElementById("blFormSeverity").value         = entry.severity;
    document.getElementById("blFormCategory").value         = entry.category || "";
    document.getElementById("blFormReason").value           = entry.reason   || "";
    document.getElementById("blFormExpiry").value        = entry.expires_at
      ? new Date(entry.expires_at).toISOString().slice(0,16) : "";
    document.getElementById("blFormTags").value             = (entry.tags || []).join(", ");
    document.getElementById("blFormError").textContent      = "";
    document.getElementById("blForm").style.display         = "block";
    document.getElementById("blExportPanel").style.display  = "none";
  }
 
  async function saveForm() {
    const ip       = document.getElementById("blFormIp").value.trim();
    const severity = document.getElementById("blFormSeverity").value;
    const category = document.getElementById("blFormCategory").value;
    const reason   = document.getElementById("blFormReason").value.trim();
    const expiry   = document.getElementById("blFormExpiry").value;
    const tagsRaw  = document.getElementById("blFormTags").value;
    const tags     = tagsRaw.split(",").map(t => t.trim()).filter(Boolean);
    const errEl    = document.getElementById("blFormError");
 
    if (!editingId && !ip) { errEl.textContent = "IP address is required."; errEl.style.display = "block"; return; }

 
    const body = { severity, category, reason, tags };
    if (!editingId) body.ip = ip;
    if (expiry) body.expires_at = new Date(expiry).toISOString();
 
    const url    = editingId ? `${API}/blacklist/${editingId}` : `${API}/blacklist`;
    const method = editingId ? "PUT" : "POST";
 
    try {
      const res  = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body:    JSON.stringify(body)
      });
      const data = await res.json();

      if (res.status === 409) {
      errEl.textContent = toast(`${ip} is already blacklisted`, "warning");;
      return;
    }

      if (!res.ok) { errEl.textContent = data.error || "Save failed."; return; }
      document.getElementById("blForm").style.display = "none";
      loadBlacklist();
    } catch (err) {
      errEl.textContent = err.message;
    }
  }
 
  // ── Wire events 
  document.getElementById("blCloseBtn").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  document.getElementById("blAddBtn").addEventListener("click", openAddForm);
  document.getElementById("blFormSave").addEventListener("click", saveForm);
  document.getElementById("blFormCancel").addEventListener("click", () => {
    document.getElementById("blForm").style.display = "none";
  });
 
  // Search & filter with debounce
  let blSearchTimer;
  document.getElementById("blSearch").addEventListener("input", e => {
    clearTimeout(blSearchTimer);
    blSearchTimer = setTimeout(() => { currentQuery.q = e.target.value.trim(); loadBlacklist(); }, 300);
  });
  document.getElementById("blSevFilter").addEventListener("change", e => {
    currentQuery.severity = e.target.value; loadBlacklist();
  });
  document.getElementById("blStatusFilter").addEventListener("change", e => {
    currentQuery.status = e.target.value; loadBlacklist();
  });
 
  // Bulk delete
  document.getElementById("blBulkDeleteBtn").addEventListener("click", async () => {
    if (!selectedIds.size || !confirm(`Delete ${selectedIds.size} entries?`)) return;
    await fetch(`${API}/blacklist/bulk`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
      body: JSON.stringify({ ids: [...selectedIds] })
    });
    selectedIds.clear();
    loadBlacklist();
  });
 
  // Export
  document.getElementById("blExportBtn").addEventListener("click", () => {
    const panel = document.getElementById("blExportPanel");
    const form  = document.getElementById("blForm");
    form.style.display  = "none";
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });
 
  document.querySelectorAll(".bl-export-fmt").forEach(btn => {
    btn.addEventListener("click", () => {
      const fmt = btn.dataset.fmt;
      const url = `${API}/blacklist/export?fmt=${fmt}`;
      const a   = Object.assign(document.createElement("a"), { href: url });
      // Must include auth header — use fetch + blob
      fetch(url, { headers: { "x-api-key": API_KEY } })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then(blob => {
        const ext  = { txt:"txt", csv:"csv", json:"json", nginx:"conf", iptables:"sh", cisco:"txt", paloalto:"txt", windows:"ps1" }[fmt] || "txt";
        const bUrl = URL.createObjectURL(blob);
        Object.assign(a, { href: bUrl, download: `ipshield-blacklist-${Date.now()}.${ext}` });
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(bUrl);
        toast(`Blacklist exported as ${fmt.toUpperCase()}`, "success");
      })
      .catch(err => toast(`Export failed: ${err.message}`, "error"));
    });
  });
 
  // Initial load
  loadBlacklist();
}

  // Cases Panel 
  // ── Status colors & icons 
  function caseStatusColor(status) {
    return { 
      Open:"var(--accent)", 
      Investigating:"var(--high)", 
      Contained:"var(--medium)", 
      Resolved:"var(--low)", 
      Closed:"var(--text3)" }[status] || "var(--text2)";
  }

  // - Severity Color
    function caseSeverityColor(sev) {
  return { 
    CRITICAL:"var(--critical)", 
    HIGH:"var(--high)", 
    MEDIUM:"var(--medium)", 
    LOW:"var(--low)" }[sev] || "var(--text2)";
}

  // - Main Cases panel 
      async function showCasesPanel() {
    document.getElementById("casesModal")?.remove();
 
  const overlay = document.createElement("div");
  overlay.id = "casesModal";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;padding:16px;";
 
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:1000px;max-height:92vh;display:flex;flex-direction:column;overflow:hidden;";
 
  modal.innerHTML = `
    <div style="padding:16px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
      <div>
        <div style="font-size:14px;font-weight:700;color:var(--text);">Manage Cases</div>
        <div id="caseStats" style="font-size:11px;color:var(--text3);margin-top:2px;">Loading…</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <button id="caseNewBtn" class="btn btn-primary" style="padding:6px 14px;font-size:11px;">+ New Case</button>
        <button id="casesCloseBtn" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
      </div>
    </div>
    <div style="padding:10px 24px;border-bottom:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
      <input id="caseSearch" type="text" placeholder="Search cases…" maxlength="100"
        style="flex:1;min-width:140px;padding:7px 12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;">
      <select id="caseStatusFilter" style="padding:7px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
        <option value="">All Statuses</option>
        <option value="Open">Open</option>
        <option value="Investigating">Investigating</option>
        <option value="Contained">Contained</option>
        <option value="Resolved">Resolved</option>
        <option value="Closed">Closed</option>
      </select>
      <select id="caseSevFilter" style="padding:7px 10px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
        <option value="">All Severities</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
    </div>
    <div style="flex:1;display:grid;grid-template-columns:320px 1fr;overflow:hidden;min-height:0;">
      <div style="border-right:1px solid var(--border);overflow-y:auto;min-height:0;" id="caseList">
        <div style="padding:32px;text-align:center;color:var(--text3);">
          <div class="spinner" style="margin:0 auto 12px;"></div>Loading…
        </div>
      </div>
      <div style="overflow-y:auto;min-height:0;" id="caseDetail">
        <div style="padding:48px 32px;text-align:center;color:var(--text3);">
          <div style="font-size:32px;margin-bottom:12px;">📁</div>
          <div style="font-size:13px;">Select a case to view details</div>
        </div>
      </div>
    </div>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  let activeCaseId = null;
  let caseQuery    = { q: "", status: "", severity: "" };
 
  // - API helpers 
  async function apiGet(path) {
    const r = await fetch(`${API}${path}`, { headers: { "x-api-key": API_KEY } });
    return r.json();
  }
  async function apiPost(path, body) {
    const r = await fetch(`${API}${path}`, { method:"POST", headers:{"Content-Type":"application/json","x-api-key":API_KEY}, body:JSON.stringify(body) });
    return { ok: r.ok, status: r.status, data: await r.json() };
  }
  async function apiPut(path, body) {
    const r = await fetch(`${API}${path}`, { method:"PUT", headers:{"Content-Type":"application/json","x-api-key":API_KEY}, body:JSON.stringify(body) });
    return { ok: r.ok, data: await r.json() };
  }
  async function apiDelete(path) {
    const r = await fetch(`${API}${path}`, { method:"DELETE", headers:{"x-api-key":API_KEY} });
    return r.ok;
  }
 
  // - Stats 
  async function refreshStats() {
    try {
      const data = await apiGet("/cases/stats");
      const el   = document.getElementById("caseStats");
      if (el) el.textContent =
        `${data.total||0} total  ·  ${data.byStatus?.Open||0} open  ·  ${data.byStatus?.Investigating||0} investigating`;
    } catch (_) {}
  }
 
  // - Case List 
  async function refreshList() {
    const params = new URLSearchParams({ limit:100 });
    if (caseQuery.q)        params.set("q",        caseQuery.q);
    if (caseQuery.status)   params.set("status",   caseQuery.status);
    if (caseQuery.severity) params.set("severity", caseQuery.severity);
    try {
      const data = await apiGet(`/cases?${params}`);
      renderCaseList(data.cases || []);
    } catch (_) {}
  }
 
  function renderCaseList(cases) {
    const el = document.getElementById("caseList");
    if (!el) return;
 
    if (!cases.length) {
      el.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text3);font-size:12px;">
        No cases found.<br><br>
        <button id="caseFirstNew" class="btn btn-primary" style="padding:8px 18px;font-size:12px;">+ Create First Case</button>
      </div>`;
      document.getElementById("caseFirstNew")?.addEventListener("click", () => showCaseForm(null));
      return;
    }
 
    el.innerHTML = cases.map(c => {
      const sc = caseStatusColor(c.status);
      const sv = caseSeverityColor(c.severity);
      const ia = c.id === activeCaseId;
      return `<div class="case-list-item" data-id="${c.id}"
        style="padding:14px 16px;border-bottom:1px solid var(--border);cursor:pointer;
               border-left:3px solid ${ia ? sc : "transparent"};
               background:${ia ? "rgba(0,217,255,0.04)" : "transparent"};">
        <div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:6px;">
          <div style="font-size:12px;font-weight:700;color:var(--text);line-height:1.3;flex:1;">${escHtml(c.title)}</div>
          <span style="font-size:9px;font-weight:700;color:${sv};padding:2px 6px;border-radius:3px;background:${sv}22;white-space:nowrap;">${c.severity}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span style="font-size:10px;font-weight:600;color:${sc};">● ${c.status}</span>
          ${c.ip_count   ? `<span style="font-size:10px;color:var(--text3);">🔗 ${c.ip_count}</span>` : ""}
          ${c.note_count ? `<span style="font-size:10px;color:var(--text3);">💬 ${c.note_count}</span>` : ""}
          <span style="font-size:10px;color:var(--text3);margin-left:auto;">${c.updated_at ? new Date(c.updated_at).toLocaleDateString() : ""}</span>
        </div>
      </div>`;
    }).join("");
 
    el.querySelectorAll(".case-list-item").forEach(item => {
      item.addEventListener("mouseover", () => { if (parseInt(item.dataset.id) !== activeCaseId) item.style.background = "rgba(0,217,255,0.03)"; });
      item.addEventListener("mouseout",  () => { if (parseInt(item.dataset.id) !== activeCaseId) item.style.background = ""; });
      item.addEventListener("click", () => {
        activeCaseId = parseInt(item.dataset.id);
        el.querySelectorAll(".case-list-item").forEach(i => {
          const ia = parseInt(i.dataset.id) === activeCaseId;
          const sc2 = cases.find(c => c.id === parseInt(i.dataset.id));
          i.style.background      = ia ? "rgba(0,217,255,0.04)" : "";
          i.style.borderLeftColor = ia ? caseStatusColor(sc2?.status || "Open") : "transparent";
        });
        loadAndRenderCase(activeCaseId);
      });
    });
 
    if (activeCaseId && cases.find(c => c.id === activeCaseId)) {
      el.querySelector(`.case-list-item[data-id="${activeCaseId}"]`)?.click();
    } else if (cases.length && !activeCaseId) {
      el.querySelector(".case-list-item")?.click();
    }
  }
 
  // - Load Case and do ONE full Render 
  async function loadAndRenderCase(id) {
    if (!id) return;
    activeCaseId = id;
    try {
      const c = await apiGet(`/cases/${id}`);
      renderCaseDetail(c);    // ← called ONCE, never again for this case
    } catch (err) {
      const el = document.getElementById("caseDetail");
      if (el) el.innerHTML = `<div style="padding:24px;color:var(--critical);font-size:12px;">⚠ ${escHtml(err.message)}</div>`;
    }
  }
 
  // - Only Update IP list Container 
  function updateIPList(ips, caseId) {
    const container = document.getElementById("caseIPList");
    const label     = document.getElementById("ipCountLabel");
    if (!container) return;
    if (label) label.textContent = `ATTACHED IPs (${ips.length})`;
 
    container.innerHTML = ips.length
      ? `<div style="border:1px solid var(--border);border-radius:8px;overflow:hidden;">
          ${ips.map((ip, i) => {
            const rc = { CRITICAL:"var(--critical)", HIGH:"var(--high)", MEDIUM:"var(--medium)", LOW:"var(--low)" }[ip.risk_level] || "var(--accent)";
            return `<div class="ci-row" style="display:flex;align-items:center;gap:10px;padding:10px 14px;
              ${i > 0 ? "border-top:1px solid var(--border);" : ""}background:${i%2===0?"var(--bg1)":"var(--bg2)"};">
              <span class="ci-score" data-ip="${escHtml(ip.ip)}"
                style="font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--accent);cursor:pointer;flex:1;"
                title="Click to score">${escHtml(ip.ip)}</span>
              ${ip.score != null ? `<span style="font-size:12px;font-weight:700;color:${rc};">${ip.score}</span>` : ""}
              ${ip.risk_level ? `<span style="font-size:9px;padding:2px 7px;border-radius:3px;background:${rc}22;color:${rc};font-weight:700;">${ip.risk_level}</span>` : ""}
              ${ip.note ? `<span style="font-size:10px;color:var(--text3);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(ip.note)}">${escHtml(ip.note)}</span>` : ""}
              <span style="font-size:10px;color:var(--text3);white-space:nowrap;">${ip.added_at ? new Date(ip.added_at).toLocaleDateString() : ""}</span>
              <button class="ci-rm" data-ip-id="${ip.id}"
                style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--text3);cursor:pointer;padding:2px 8px;font-size:10px;flex-shrink:0;">✕</button>
            </div>`;
          }).join("")}
        </div>`
      : `<div style="padding:16px;text-align:center;background:var(--bg);border-radius:8px;border:1px solid var(--border);font-size:11px;color:var(--text3);">
           No IPs attached yet — click <strong>+ Attach IP</strong> above
         </div>`;
 
    // - Wire IP row events
    container.querySelectorAll(".ci-score").forEach(span => {
      span.addEventListener("click", () => { ipInput.value = span.dataset.ip; overlay.remove(); scoreIP(); });
    });
    container.querySelectorAll(".ci-rm").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (btn._busy) return; btn._busy = true; btn.textContent = "…";
        const ok = await apiDelete(`/cases/${caseId}/ips/${btn.dataset.ipId}`);
        if (ok) {
          toast("IP removed", "info");
          const fresh = await apiGet(`/cases/${caseId}`);
          updateIPList(fresh.ips || [], caseId);
          refreshList(); refreshStats();
        } else { btn._busy = false; btn.textContent = "✕"; }
      });
    });
  }
 
  // - Only update notes list container 
  function updateNotesList(notes, caseId) {
    const container = document.getElementById("caseNotesList");
    const label     = document.getElementById("noteCountLabel");
    if (!container) return;
    if (label) label.textContent = `INVESTIGATION NOTES (${notes.length})`;
 
    container.innerHTML = notes.length
      ? notes.map(n => `
          <div style="padding:12px 14px;background:var(--bg2);border-radius:8px;border:1px solid var(--border);margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-size:10px;font-weight:600;color:var(--accent);">👤 ${escHtml(n.author||"analyst")}</span>
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:10px;color:var(--text3);">${n.created_at ? new Date(n.created_at).toLocaleString() : ""}</span>
                <button class="cn-rm" data-note-id="${n.id}"
                  style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--text3);cursor:pointer;padding:1px 7px;font-size:10px;">✕</button>
              </div>
            </div>
            <div style="font-size:12px;color:var(--text);line-height:1.7;white-space:pre-wrap;">${escHtml(n.note)}</div>
          </div>`).join("")
      : `<div style="padding:16px;text-align:center;background:var(--bg);border-radius:8px;border:1px solid var(--border);font-size:11px;color:var(--text3);">
           No notes yet — add your first note below
         </div>`;
 
    // - Wire note delete events
    container.querySelectorAll(".cn-rm").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (btn._busy) return; btn._busy = true; btn.textContent = "…";
        const ok = await apiDelete(`/cases/${caseId}/notes/${btn.dataset.noteId}`);
        if (ok) {
          toast("Note deleted", "info");
          const fresh = await apiGet(`/cases/${caseId}`);
          updateNotesList(fresh.notes || [], caseId);
          refreshList(); refreshStats();
        } else { btn._busy = false; btn.textContent = "✕"; }
      });
    });
  }
 
  // - Full case detail render — called ONCE per case 
  function renderCaseDetail(c) {
    const detailEl = document.getElementById("caseDetail");
    if (!detailEl) return;
 
    const caseId  = c.id; // primitive — never stale
    const sColor  = caseStatusColor(c.status);
    const svColor = caseSeverityColor(c.severity);
    const tags    = c.tags || [];
 
    // - Build static HTML (IPs and notes have dedicated containers)
    detailEl.innerHTML = `
      <div style="padding:20px 24px;">
        <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;flex-wrap:wrap;">
          <div style="flex:1;min-width:0;">
            <div style="font-size:15px;font-weight:700;color:var(--text);line-height:1.3;margin-bottom:8px;">${escHtml(c.title)}</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
              <span style="font-size:11px;font-weight:700;color:${sColor};border-radius:4px;background:${sColor}22;border:1px solid ${sColor}44;">● ${c.status}</span>
              <span style="font-size:10px;font-weight:700;color:${svColor};padding:3px 8px;border-radius:4px;background:${svColor}22;">${c.severity}</span>
              ${tags.map(t=>`<span style="font-size:10px;padding:2px 7px;border-radius:3px;background:var(--bg2);color:var(--text2);">${escHtml(t)}</span>`).join("")}
              <span style="font-size:10px;color:var(--text3);">Case #${caseId}</span>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0;align-items:center;flex-wrap:wrap;">
            <select id="caseStatusChange" style="padding:5px 8px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:11px;">
              ${["Open","Investigating","Contained","Resolved","Closed"].map(s=>`<option value="${s}"${s===c.status?" selected":""}>${s}</option>`).join("")}
            </select>
            <button id="caseEditBtn"   class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">Edit</button>
            <button id="caseDeleteBtn" class="btn btn-ghost" style="padding:5px 12px;font-size:11px;color:var(--critical);border-color:var(--critical);">Delete</button>
          </div>
        </div>
 
        ${c.description ? `<div style="padding:10px 14px;background:var(--bg2);border-radius:8px;border:1px solid var(--border);margin-bottom:14px;">
          <div style="font-size:11px;color:var(--text2);line-height:1.6;">${escHtml(c.description)}</div></div>` : ""}
 
        <div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px;font-size:10px;color:var(--text3);padding:8px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);">
          ${c.assigned_to ? `<span>👤 ${escHtml(c.assigned_to)}</span>` : ""}
          ${c.created_at  ? `<span>📅 ${new Date(c.created_at).toLocaleString()}</span>` : ""}
          ${c.updated_at  ? `<span>🔄 ${new Date(c.updated_at).toLocaleString()}</span>` : ""}
          ${c.closed_at   ? `<span>✅ Closed: ${new Date(c.closed_at).toLocaleString()}</span>` : ""}
        </div>
 
        <!-- IPs section -->
        <div style="margin-bottom:20px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <div id="ipCountLabel" style="font-size:10px;color:var(--text);letter-spacing:2px;font-weight:700;">ATTACHED IPs (${(c.ips||[]).length})</div>
            <button id="caseAttachIPBtn" class="btn btn-ghost" style="padding:4px 12px;font-size:11px;">+ Attach IP</button>
          </div>
          <div id="attachIPForm" style="display:none;margin-bottom:10px; background:var(--bg1);padding:14px;border-radius:8px;border:1.5px solid #0099cc;">
            <div style="font-size:10px;color:var(--text);margin-bottom:10px;letter-spacing:1px;">ATTACH IP TO THIS CASE</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <input id="attachIPInput" type="text" placeholder="IP address *" maxlength="45"
                style="flex:1;min-width:120px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;">
              <input id="attachIPNote" type="text" placeholder="Note (optional)" maxlength="200"
                style="flex:2;min-width:160px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;">
            </div>
            <div id="attachIPError" style="font-size:11px;color:var(--critical);margin-top:6px;display:none;"></div>
            <div style="display:flex;gap:8px;margin-top:10px;justify-content:flex-end;">
              <button id="attachIPCancel" class="btn btn-ghost"   style="padding:6px 14px;font-size:11px;">Cancel</button>
              <button id="attachIPSave"   class="btn btn-primary" style="padding:6px 14px;font-size:11px;">Attach</button>
            </div>
          </div>
          <div id="caseIPList"></div>
        </div>
 
        <!-- Notes section -->
        <div>
          <div id="noteCountLabel" style="font-size:10px;color:var(--text);letter-spacing:2px;font-weight:700;margin-bottom:10px;">INVESTIGATION NOTES (${(c.notes||[]).length})</div>
          
          <div id="caseNotesList" style="margin-bottom:12px;"></div>
          <div style="background:var(--bg1);border-radius:8px;border:1px solid var(--border);overflow:hidden;">
            <textarea id="caseNoteInput" placeholder="Add investigation note…" rows="3"
              style="width:100%;padding:12px 14px;background:transparent;border:none;color:var(--text);font-family:inherit;font-size:12px;outline:none;resize:vertical;box-sizing:border-box;line-height:1.6;"></textarea>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-top:1px solid var(--border);">
              <span style="font-size:10px;color:var(--text3);"></span>
              <button id="caseNoteSubmit" class="btn btn-primary" style="padding:6px 16px;font-size:11px;">Add Note</button>
            </div>
          </div>
        </div>
      </div>`;
 
    // Populate sub-sections surgically
    updateIPList(c.ips   || [], caseId);
    updateNotesList(c.notes || [], caseId);
 
    // - Wire all static events — these elements never get replaced 
 
    document.getElementById("caseStatusChange")?.addEventListener("change", async e => {
      const r = await apiPut(`/cases/${caseId}`, { status: e.target.value });
      if (r.ok) { toast(`Status → ${e.target.value}`, "success"); loadAndRenderCase(caseId); refreshList(); refreshStats(); }
    });
 
    document.getElementById("caseEditBtn")?.addEventListener("click", async () => {
      const data = await apiGet(`/cases/${caseId}`);
      showCaseForm(data);
    });
 
    document.getElementById("caseDeleteBtn")?.addEventListener("click", async () => {
      if (!confirm("Delete this case? Cannot be undone.")) return;
      const ok = await apiDelete(`/cases/${caseId}`);
      if (ok) {
        toast("Case deleted", "success");
        activeCaseId = null;
        document.getElementById("caseDetail").innerHTML = `
          <div style="padding:48px 32px;text-align:center;color:var(--text3);">
            <div style="font-size:32px;margin-bottom:12px;">📁</div><div>Case deleted.</div>
          </div>`;
        refreshList(); refreshStats();
      }
    });
 
    document.getElementById("caseAttachIPBtn")?.addEventListener("click", () => {
      const form = document.getElementById("attachIPForm");
      const show = form.style.display === "none";
      form.style.display = show ? "block" : "none";
      if (show) {
        const inp = document.getElementById("attachIPInput");
        if (inp && !inp.value && currentIP) inp.value = currentIP;
        inp?.focus();
      }
    });
 
    document.getElementById("attachIPCancel")?.addEventListener("click", () => {
      document.getElementById("attachIPForm").style.display = "none";
      document.getElementById("attachIPInput").value = "";
      document.getElementById("attachIPNote").value  = "";
      document.getElementById("attachIPError").style.display = "none";
    });
 
    // - Attach IP
    document.getElementById("attachIPSave")?.addEventListener("click", async () => {
      const ipVal   = document.getElementById("attachIPInput").value.trim();
      const noteVal = document.getElementById("attachIPNote").value.trim();
      const errEl   = document.getElementById("attachIPError");
      const saveBtn = document.getElementById("attachIPSave");
 
      errEl.style.display = "none";
      if (!ipVal) { errEl.textContent = "IP address is required."; errEl.style.display = "block"; return; }
      if (saveBtn._busy) return;
 
      saveBtn._busy = true; saveBtn.disabled = true; saveBtn.textContent = "Attaching…";
 
      const body = { ip: ipVal, note: noteVal };
      if (lastResult?.ip === ipVal) { body.score = lastResult.score; body.risk_level = lastResult.riskLevel; }
 
      const r = await apiPost(`/cases/${caseId}/ips`, body);
 
      saveBtn._busy = false; saveBtn.disabled = false; saveBtn.textContent = "Attach";
 
      if (r.status === 409) { errEl.textContent = `${ipVal} is already attached.`; errEl.style.display = "block"; return; }
      if (!r.ok)            { errEl.textContent = r.data?.error || "Failed.";       errEl.style.display = "block"; return; }
 
      // - Clear form
      document.getElementById("attachIPInput").value = "";
      document.getElementById("attachIPNote").value  = "";
      document.getElementById("attachIPForm").style.display = "none";
 
      toast(`${ipVal} attached to case`, "success");
 
      // - Fetch fresh IPs only, update only #caseIPList
      const fresh = await apiGet(`/cases/${caseId}`);
      updateIPList(fresh.ips || [], caseId);   // ← only IPs rebuilt
      refreshList();
      refreshStats();
    });
 
    // - Add Note 
    async function submitNote() {
      const textarea  = document.getElementById("caseNoteInput");
      const submitBtn = document.getElementById("caseNoteSubmit");
      const noteText  = textarea?.value.trim();
 
      if (!noteText) { toast("Note cannot be empty", "warning"); return; }
      if (submitBtn._busy) return;
 
      submitBtn._busy = true; submitBtn.disabled = true; submitBtn.textContent = "Adding…";
 
      const r = await apiPost(`/cases/${caseId}/notes`, { note: noteText, author: "analyst" });
 
      submitBtn._busy = false; submitBtn.disabled = false; submitBtn.textContent = "Add Note";
 
      if (!r.ok) { toast("Failed to add note", "error"); return; }
 
      textarea.value = ""; // clear before DOM update
      toast("Note added", "success");
 
      // - Fetch fresh notes only, update only #caseNotesList 
      const fresh = await apiGet(`/cases/${caseId}`);
      updateNotesList(fresh.notes || [], caseId); // ← only notes rebuilt
      refreshList();
      refreshStats();
 
      // - Scroll last note into view
      setTimeout(() => {
        const list = document.getElementById("caseNotesList");
        list?.lastElementChild?.scrollIntoView({ behavior:"smooth", block:"nearest" });
      }, 100);
    }
 
    document.getElementById("caseNoteSubmit")?.addEventListener("click", submitNote);
    document.getElementById("caseNoteInput")?.addEventListener("keydown", e => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submitNote();
    });
  }
 
  // - Case Create / Edit Form 
  function showCaseForm(c) {
    const isEdit = !!c;
    const fo = document.createElement("div");
    fo.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:10001;display:flex;align-items:center;justify-content:center;padding:24px;";
    const f = document.createElement("div");
    f.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:540px;padding:24px;max-height:90vh;overflow-y:auto;";
    f.innerHTML = `
      <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:20px;">${isEdit ? `✏️ Edit Case #${c.id}` : "New Investigation Case"}</div>
      <div style="display:flex;flex-direction:column;gap:14px;">
        <div>
          <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">TITLE *</label>
          <input id="cfTitle" type="text" maxlength="200" value="${isEdit?escHtml(c.title):""}" placeholder="e.g. Fraud Incident — May 2026"
            style="width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div>
            <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">SEVERITY</label>
            <select id="cfSeverity" style="width:100%;padding:9px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
              ${["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>`<option value="${s}"${isEdit&&c.severity===s?" selected":s==="MEDIUM"&&!isEdit?" selected":""}>${s}</option>`).join("")}
            </select>
          </div>
          <div>
            <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">STATUS</label>
            <select id="cfStatus" style="width:100%;padding:9px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;">
              ${["Open","Investigating","Contained","Resolved","Closed"].map(s=>`<option value="${s}"${isEdit&&c.status===s?" selected":s==="Open"&&!isEdit?" selected":""}>${s}</option>`).join("")}
            </select>
          </div>
        </div>
        <div>
          <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">ASSIGNED TO</label>
          <input id="cfAssigned" type="text" maxlength="100" value="${isEdit?escHtml(c.assigned_to||""):"analyst"}"
            style="width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
        <div>
          <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">DESCRIPTION</label>
          <textarea id="cfDesc" rows="3" maxlength="2000" placeholder="Brief description of the investigation"
            style="width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;resize:vertical;box-sizing:border-box;">${isEdit?escHtml(c.description||""):""}</textarea>
        </div>
        <div>
          <label style="font-size:10px;color:var(--text3);display:block;margin-bottom:4px;">TAGS (comma-separated)</label>
          <input id="cfTags" type="text" maxlength="200" value="${isEdit?(c.tags||[]).join(", "):""}" placeholder="e.g. fraud, botnet, tor"
            style="width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:inherit;font-size:12px;outline:none;box-sizing:border-box;">
        </div>
        <div id="cfError" style="font-size:11px;color:var(--critical);display:none;padding:8px 12px;background:rgba(255,51,85,0.08);border-radius:6px;"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button id="cfCancel" class="btn btn-ghost"   style="padding:8px 18px;font-size:12px;">Cancel</button>
          <button id="cfSave"   class="btn btn-primary" style="padding:8px 18px;font-size:12px;">${isEdit?"Save Changes":"Create Case"}</button>
        </div>
      </div>`;
 
    fo.appendChild(f);
    document.body.appendChild(fo);
    document.getElementById("cfTitle").focus();
    document.getElementById("cfCancel").addEventListener("click", () => fo.remove());
    fo.addEventListener("click", e => { if (e.target === fo) fo.remove(); });
 
    document.getElementById("cfSave").addEventListener("click", async () => {
      const title       = document.getElementById("cfTitle").value.trim();
      const severity    = document.getElementById("cfSeverity").value;
      const status      = document.getElementById("cfStatus").value;
      const assigned_to = document.getElementById("cfAssigned").value.trim();
      const description = document.getElementById("cfDesc").value.trim();
      const tags        = document.getElementById("cfTags").value.split(",").map(t=>t.trim()).filter(Boolean);
      const errEl       = document.getElementById("cfError");
 
      if (!title) { errEl.textContent = "Title is required."; errEl.style.display = "block"; return; }
 
      const r = isEdit
        ? await apiPut(`/cases/${c.id}`, { title, severity, status, assigned_to, description, tags })
        : await apiPost("/cases",         { title, severity, status, assigned_to, description, tags });
 
      if (!r.ok) { errEl.textContent = r.data?.error || "Save failed."; errEl.style.display = "block"; return; }
 
      fo.remove();
      toast(isEdit ? "Case updated" : `Case created: ${title}`, "success");
 
      const targetId = isEdit ? c.id : r.data.id;
      activeCaseId   = targetId;
      await refreshList();
      await loadAndRenderCase(targetId);
      await refreshStats();
    });
  }
 
  // - Panel Event Listeners 
  document.getElementById("caseNewBtn").addEventListener("click", () => showCaseForm(null));
  document.getElementById("casesCloseBtn").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  let searchTimer;
  document.getElementById("caseSearch").addEventListener("input", e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { caseQuery.q = e.target.value.trim(); refreshList(); }, 300);
  });
  document.getElementById("caseStatusFilter").addEventListener("change", e => { caseQuery.status   = e.target.value; refreshList(); });
  document.getElementById("caseSevFilter").addEventListener("change",    e => { caseQuery.severity = e.target.value; refreshList(); });
 
  // - Initial Load
  await refreshStats();
  await refreshList();
}

    // ── Add current IP to an existing or new case 
    async function addIPToCase(ip, result) {
  if (!ip || !isValidIP(ip)) { toast("Score an IP first", "warning"); return; }
 
  try {
    const data  = await (await fetch(`${API}/cases?limit=50`, { headers:{"x-api-key":API_KEY} })).json();
    const cases = (data.cases||[]).filter(c => c.status !== "Closed" && c.status !== "Resolved");
 
    if (!cases.length) {
      if (confirm(`No active cases found. Create a new case for ${ip}?`)) showCasesPanel();
      return;
    }
 
    const ov = document.createElement("div");
    ov.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10001;display:flex;align-items:center;justify-content:center;padding:24px;";
 
    const panel = document.createElement("div");
    panel.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:460px;max-height:60vh;display:flex;flex-direction:column;overflow:hidden;";
    panel.innerHTML = `
      <div style="padding:16px 20px;border-bottom:1px solid var(--border);font-size:13px;font-weight:700;color:var(--text);">
        📁 Attach ${escHtml(ip)} to Case
      </div>
      <div style="overflow-y:auto;flex:1;">
        ${cases.map(c=>`
          <div class="cpick" data-id="${c.id}"
            style="padding:12px 20px;border-bottom:1px solid var(--border);cursor:pointer;display:flex;align-items:center;gap:10px;">
            <span style="font-size:10px;font-weight:700;color:${caseStatusColor(c.status)};flex-shrink:0;">● ${c.status}</span>
            <span style="font-size:12px;color:var(--text);flex:1;">${escHtml(c.title)}</span>
            <span style="font-size:10px;color:var(--text3);">#${c.id}</span>
          </div>`).join("")}
        <div class="cpick" data-id="new"
          style="padding:12px 20px;cursor:pointer;display:flex;align-items:center;gap:8px;color:var(--accent);">
          <span style="font-size:14px;">+</span>
          <span style="font-size:12px;font-weight:600;">Create new case</span>
        </div>
      </div>`;
 
    ov.appendChild(panel);
    document.body.appendChild(ov);
    ov.addEventListener("click", e => { if (e.target === ov) ov.remove(); });
 
    panel.querySelectorAll(".cpick").forEach(item => {
      item.addEventListener("mouseover", () => { item.style.background = "var(--bg2)"; });
      item.addEventListener("mouseout",  () => { item.style.background = ""; });
      item.addEventListener("click", async () => {
        ov.remove();
        if (item.dataset.id === "new") { showCasesPanel(); return; }
 
        const caseId = parseInt(item.dataset.id);
        const r = await fetch(`${API}/cases/${caseId}/ips`, {
          method:"POST",
          headers:{"Content-Type":"application/json","x-api-key":API_KEY},
          body:JSON.stringify({ ip, score:result?.score??null, risk_level:result?.riskLevel??null, note:`From score result — ${result?.riskLevel||""} risk` })
        });
        const d = await r.json();
        if (r.status === 409) { toast(`${ip} already in this case`, "warning"); return; }
        if (!r.ok)            { toast(d.error || "Failed to attach", "error");  return; }
        toast(`${ip} attached to case #${caseId}`, "success");
      });
    });
  } catch (err) {
    toast(`Error: ${err.message}`, "error");
  }
}

  // toast msg
  function toast(message, type = "success", duration = 3500) {

  // Remove existing toast if any
  const existing = document.getElementById("ipshieldToast");
  if (existing) existing.remove();

  const colors = {
    success: { bg: "rgba(0,232,124,0.12)", border: "var(--low)",       icon: "✓" },
    error:   { bg: "rgba(255,51,85,0.12)", border: "var(--critical)",  icon: "⚠" },
    warning: { bg: "rgba(255,204,0,0.12)", border: "var(--medium)",    icon: "⚑" },
    info:    { bg: "rgba(0,217,255,0.12)", border: "var(--accent)",    icon: "ℹ" }
  };
  const c = colors[type] || colors.info;

  const el = document.createElement("div");
  el.id = "ipshieldToast";
  el.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:99999;
    display:flex;align-items:center;gap:10px;
    padding:12px 18px;
    background:var(--bg1);
    border:1px solid ${c.border};
    border-left:4px solid ${c.border};
    border-radius:8px;
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    font-family:'JetBrains Mono',monospace;
    font-size:12px;
    color:var(--text);
    max-width:360px;
    animation:toastIn 0.25s ease forwards;
    cursor:pointer;
  `;

  // Inject keyframes once
  if (!document.getElementById("toastStyles")) {
    const style = document.createElement("style");
    style.id = "toastStyles";
    style.textContent = `
      @keyframes toastIn {
        from { opacity:0; transform:translateY(16px); }
        to   { opacity:1; transform:translateY(0); }
      }
      @keyframes toastOut {
        from { opacity:1; transform:translateY(0); }
        to   { opacity:0; transform:translateY(16px); }
      }
    `;
    document.head.appendChild(style);
  }

  el.innerHTML = `
    <span style="font-size:16px;color:${c.border};flex-shrink:0;">${c.icon}</span>
    <span style="flex:1;line-height:1.5;">${escHtml(message)}</span>
    <button id="toastClose" style="background:none;border:none;color:var(--text3);cursor:pointer;
      font-size:16px;padding:0 0 0 8px;line-height:1;flex-shrink:0;">✕</button>`;

  document.body.appendChild(el);

  function dismiss() {
    el.style.animation = "toastOut 0.2s ease forwards";
    setTimeout(() => el.remove(), 200);
  }

  el.addEventListener("click", dismiss);
  setTimeout(dismiss, duration);
}
 
// ── Quick block from score result 
async function quickBlock(ip) {
  if (!ip || !isValidIP(ip)) { setBulkStatus("No valid IP to block."); return; }

  const reason   = prompt(`Reason for blocking ${ip}:`, "Manual block") ?? "Manual block";

  try {
    const res  = await fetch(`${API}/blacklist`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
      body:    JSON.stringify({ ip, severity: "HIGH", reason, category: "Manual", added_by: "analyst" })
    });
    const data = await res.json();

    if (res.status === 409) {
      toast(`${ip} is already blacklisted`, "warning");
      return;
    }
    if (!res.ok) throw new Error(data.error || "Failed");
    toast(`${ip} added to blacklist`, "success");
  } catch (err) {
    toast(`Blacklist error: ${err.message}`, "error");
  }
}
 
function renderTimeline(data, container) {
  if (!data.total || !data.history?.length) {
    container.innerHTML = `
      <div style="text-align:center;padding:40px 0;color:var(--text3);">
        <div style="font-size:32px;margin-bottom:12px;">📊</div>
        <div style="font-size:13px;">No scoring history found for this IP.</div>
        <div style="font-size:11px;margin-top:6px;">Score the IP a few times to build a history.</div>
      </div>`;
    return;
  }
 
  const stats   = data.stats;
  const history = data.history;
 
  // Trend indicator
  const trendIcon  = stats.trend === "increasing" ? "↑" : stats.trend === "decreasing" ? "↓" : "→";
  const trendColor = stats.trend === "increasing" ? "var(--critical)"
                   : stats.trend === "decreasing" ? "var(--low)" : "var(--text2)";
  const changeStr  = stats.change > 0 ? `+${stats.change}` : String(stats.change);
 
  container.innerHTML = `
    <!-- Stats row -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
      ${[
        { label: "Latest",   val: stats.latest, color: scoreColor(stats.latest) },
        { label: "Average",  val: stats.avg,    color: scoreColor(stats.avg)    },
        { label: "Min",      val: stats.min,    color: scoreColor(stats.min)    },
        { label: "Max",      val: stats.max,    color: scoreColor(stats.max)    }
      ].map(s => `
        <div style="background:var(--bg1);border-radius:8px;padding:14px;text-align:center;border:0.9px solid var(--border);">
          <div style="font-size:22px;font-weight:800;color:${s.color};font-family:'Syne',sans-serif;">${s.val}</div>
          <div style="font-size:10px;color:var(--text3);letter-spacing:1px;text-transform:uppercase;margin-top:2px;">${s.label}</div>
        </div>`).join("")}
    </div>
 
    <!-- Trend -->
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:10px 14px;background:var(--bg1);border-radius:8px;border:0.9px solid var(--border);">
      <span style="font-size:18px;color:${trendColor};font-weight:700;">${trendIcon}</span>
      <div>
        <span style="font-size:12px;color:var(--text);font-weight:600;">Trend: ${stats.trend.charAt(0).toUpperCase() + stats.trend.slice(1)}</span>
        <span style="font-size:11px;color:var(--text3);margin-left:8px;">Score changed ${changeStr} points over ${data.total} scoring${data.total !== 1 ? "s" : ""}</span>
      </div>
    </div>
 
    <!-- Chart canvas -->
    <div style="background:var(--bg1);border-radius:10px;border:0.9px solid var(--border);padding:16px;margin-bottom:20px;">
      <div style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">// Score Over Time</div>
      <canvas id="timelineCanvas" style="width:100%;display:block;"></canvas>
    </div>
 
    <!-- History table -->
    <div style="background:var(--bg1);border-radius:10px;border:0.9px solid var(--border);overflow:hidden;">
      <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;">// Scoring History</div>
        <div style="font-size:11px;color:var(--text3);">${data.total} record${data.total !== 1 ? "s" : ""}</div>
      </div>
      <div style="max-height:200px;overflow-y:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:11px;">
          <thead>
            <tr style="background:var(--bg1);">
              <th style="padding:8px 14px;text-align:left;color:var(--text3);font-weight:600;letter-spacing:1px;font-size:10px;">DATE</th>
              <th style="padding:8px 14px;text-align:center;color:var(--text3);font-weight:600;letter-spacing:1px;font-size:10px;">SCORE</th>
              <th style="padding:8px 14px;text-align:center;color:var(--text3);font-weight:600;letter-spacing:1px;font-size:10px;">RISK</th>
              <th style="padding:8px 14px;text-align:center;color:var(--text3);font-weight:600;letter-spacing:1px;font-size:10px;">ACTION</th>
            </tr>
          </thead>
          <tbody>
            ${[...history].reverse().map((h, i) => {
              const risk   = h.risk_level || "LOW";
              const rColor = { CRITICAL:"var(--critical)", HIGH:"var(--high)", MEDIUM:"var(--medium)", LOW:"var(--low)" }[risk] || "var(--low)";
              const date   = new Date(h.scored_at).toLocaleString([], { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
              return `<tr style="border-top:1px solid var(--border);${i === 0 ? "background:rgba(0,217,255,0.03);" : ""}">
                <td style="padding:8px 14px;color:var(--text2);">${date}</td>
                <td style="padding:8px 14px;text-align:center;font-weight:700;color:${scoreColor(h.score)};">${h.score}</td>
                <td style="padding:8px 14px;text-align:center;">
                  <span style="font-size:10px;font-weight:700;color:${rColor};padding:2px 7px;border-radius:3px;background:${rColor}22;">${risk}</span>
                </td>
                <td style="padding:8px 14px;text-align:center;color:var(--text2);">${h.action || "—"}</td>
              </tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>
    </div>`;
 
  // Draw chart after DOM renders
  requestAnimationFrame(() => drawTimelineChart(history, document.getElementById("timelineCanvas")));
}
 
function scoreColor(score) {
  if (score > 80) return "var(--critical)";
  if (score > 60) return "var(--high)";
  if (score > 30) return "var(--medium)";
  return "var(--low)";
}
 
function drawTimelineChart(history, canvas) {
  if (!canvas) return;
 
  const dpr     = window.devicePixelRatio || 1;
  const W       = canvas.parentElement.clientWidth - 32;
  const H       = 140;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width  = W + "px";
  canvas.style.height = H + "px";
 
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
 
  const PAD   = { top: 12, right: 16, bottom: 28, left: 36 };
  const chartW = W - PAD.left - PAD.right;
  const chartH = H - PAD.top  - PAD.bottom;
 
  const scores   = history.map(h => h.score);
  const minScore = 0;
  const maxScore = 100;
 
  // Background
  ctx.fillStyle = getComputedStyle(document.documentElement)
    .getPropertyValue("--bg1").trim() || "#111820";
  ctx.fillRect(0, 0, W, H);
 
  // Grid lines
  ctx.strokeStyle = getComputedStyle(document.documentElement)
    .getPropertyValue("--border").trim() || "#1e2d3d";
  ctx.lineWidth = 0.5;
 
  [0, 25, 50, 75, 100].forEach(val => {
    const y = PAD.top + chartH - (val / maxScore) * chartH;
    ctx.beginPath();
    ctx.moveTo(PAD.left, y);
    ctx.lineTo(PAD.left + chartW, y);
    ctx.stroke();
 
    // Y axis labels
    ctx.fillStyle = getComputedStyle(document.documentElement)
      .getPropertyValue("--text3").trim() || "#3d5a72";
    ctx.font = `${10 * dpr / dpr}px monospace`;
    ctx.textAlign = "right";
    ctx.fillText(String(val), PAD.left - 6, y + 3);
  });
 
  if (scores.length < 2) {
    // Single point — just draw a dot
    const x = PAD.left + chartW / 2;
    const y = PAD.top + chartH - (scores[0] / maxScore) * chartH;
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fillStyle = resolveScoreColor(scores[0]);
    ctx.fill();
    return;
  }
 
  // Compute point positions
  const pts = scores.map((s, i) => ({
    x: PAD.left + (i / (scores.length - 1)) * chartW,
    y: PAD.top + chartH - (s / maxScore) * chartH,
    score: s
  }));
 
  // Gradient fill under line
  const grad = ctx.createLinearGradient(0, PAD.top, 0, PAD.top + chartH);
  grad.addColorStop(0,   "rgba(0,217,255,0.3)");
  grad.addColorStop(1,   "rgba(0,217,255,0.0)");
 
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  pts.slice(1).forEach(p => {
    // Smooth curve using bezier
    const prev = pts[pts.indexOf(p) - 1];
    const cpX  = (prev.x + p.x) / 2;
    ctx.bezierCurveTo(cpX, prev.y, cpX, p.y, p.x, p.y);
  });
  ctx.lineTo(pts[pts.length - 1].x, PAD.top + chartH);
  ctx.lineTo(pts[0].x, PAD.top + chartH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();
 
  // Line
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  pts.slice(1).forEach(p => {
    const prev = pts[pts.indexOf(p) - 1];
    const cpX  = (prev.x + p.x) / 2;
    ctx.bezierCurveTo(cpX, prev.y, cpX, p.y, p.x, p.y);
  });
  ctx.strokeStyle = "#00d9ff";
  ctx.lineWidth   = 2;
  ctx.stroke();
 
  // Data points — color by risk
  pts.forEach((p, i) => {
    const color = resolveScoreColor(p.score);
    ctx.beginPath();
    ctx.arc(p.x, p.y, scores.length > 20 ? 2.5 : 4, 0, Math.PI * 2);
    ctx.fillStyle   = color;
    ctx.strokeStyle = "#080c0f";
    ctx.lineWidth   = 1.5;
    ctx.fill();
    ctx.stroke();
  });
 
  // X axis date labels (show ~5 evenly spaced)
  const labelCount = Math.min(5, scores.length);
  const step       = Math.floor((scores.length - 1) / (labelCount - 1)) || 1;
  ctx.fillStyle  = getComputedStyle(document.documentElement)
    .getPropertyValue("--text3").trim() || "#3d5a72";
  ctx.font       = `${9 * dpr / dpr}px monospace`;
  ctx.textAlign  = "center";
 
  for (let i = 0; i < scores.length; i += step) {
    if (i >= history.length) break;
    const x    = PAD.left + (i / (scores.length - 1)) * chartW;
    const date = new Date(history[i].scored_at);
    const label = date.toLocaleDateString([], { month: "short", day: "numeric" });
    ctx.fillText(label, x, H - 8);
  }
  // Always label last point
  const lastX = PAD.left + chartW;
  const lastDate = new Date(history[history.length - 1].scored_at);
  ctx.fillText(lastDate.toLocaleDateString([], { month:"short", day:"numeric" }), lastX, H - 8);
}
 
function resolveScoreColor(score) {
  if (score > 80) return "#ff3355";
  if (score > 60) return "#ff7700";
  if (score > 30) return "#ffcc00";
                  return "#00e87c";
}

 // Rate Limit
  function showAPIStatus(apiStatus) {

  // Remove existing banner if any
  const existing = document.getElementById("apiStatusBanner");
  if (existing) existing.remove();
 
  if (!apiStatus || apiStatus.abuseIPDB === "ok") return;
 
  const banner = document.createElement("div");
  banner.id = "apiStatusBanner";
 
  if (apiStatus.abuseIPDB === "rate_limited") {
    banner.style.cssText = `
      position:fixed;bottom:24px;right:24px;z-index:9999;
      background:#111820;border:1px solid rgba(255,204,0,0.5);border-radius:8px;
      padding:12px 16px;max-width:320px;box-shadow:0 4px 24px rgba(0,0,0,0.4);`;
    banner.innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <span style="font-size:18px;">⚠</span>
        <div>
          <div style="font-size:12px;font-weight:700;color:#ffcc00;letter-spacing:1px;margin-bottom:4px;">ABUSEIPDB RATE LIMITED</div>
          <div style="font-size:11px;color:#6a8fa8;line-height:1.5;">
            Daily quota reached. Abuse scores show 0 until reset.
            Other intel sources (Shodan, feeds, geo) are unaffected.
          </div>
          ${apiStatus.resetAt ? `<div style="font-size:10px;color:#3d5a72;margin-top:6px;">Resets: ${new Date(apiStatus.resetAt).toLocaleString()}</div>` : ""}
        </div>
        <button onclick="this.parentElement.parentElement.remove()"
          style="background:none;border:none;color:#3d5a72;cursor:pointer;font-size:16px;padding:0;flex-shrink:0;">✕</button>
      </div>`;
  } else if (apiStatus.abuseIPDB === "key_error") {
    banner.style.cssText = `
      position:fixed;bottom:24px;right:24px;z-index:9999;
      background:#111820;border:1px solid rgba(255,51,85,0.5);border-radius:8px;
      padding:12px 16px;max-width:320px;box-shadow:0 4px 24px rgba(0,0,0,0.4);`;
    banner.innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <span style="font-size:18px;">🔑</span>
        <div>
          <div style="font-size:12px;font-weight:700;color:#ff3355;letter-spacing:1px;margin-bottom:4px;">ABUSEIPDB KEY ERROR</div>
          <div style="font-size:11px;color:#6a8fa8;line-height:1.5;">
            API key is invalid or missing. Check ABUSE_IPDB_KEY in your environment variables.
          </div>
        </div>
        <button onclick="this.parentElement.parentElement.remove()"
          style="background:none;border:none;color:#3d5a72;cursor:pointer;font-size:16px;padding:0;flex-shrink:0;">✕</button>
      </div>`;
  }


  document.body.appendChild(banner);
 
  // Auto-dismiss after 10 seconds
  setTimeout(() => banner.remove(), 10000);
}

// firewall export 
function showFirewallExport() {

  // Collect CRITICAL and HIGH IPs from session
  const threats = auditEntries.filter(e => e.riskLevel === "CRITICAL" || e.riskLevel === "HIGH");
 
  if (!threats.length) {
    setBulkStatus; toast("No CRITICAL or HIGH IPs in audit log to export.", "warning");
    return;
  }
 
  // Deduplicate IPs
  const uniqueIPs = [...new Map(threats.map(e => [e.ip, e])).values()];
 
  // Build modal overlay
  const overlay = document.createElement("div");
  overlay.id = "firewallModal";
  overlay.style.cssText = `
    position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:10000;
    display:flex;align-items:center;justify-content:center;padding:24px;`;
 
  const modal = document.createElement("div");
  modal.style.cssText = `
    background:var(--bg1);border:1px solid var(--border);border-radius:12px;
    width:100%;max-width:680px;max-height:80vh;display:flex;flex-direction:column;`;
 
  // Format selector
  const formats = [
    { id:"iptables",  label:"iptables (Linux)" },
    { id:"ip6tables", label:"ip6tables (IPv6)" },
    { id:"ufw",       label:"UFW (Ubuntu)" },
    { id:"cisco",     label:"Cisco ACL" },
    { id:"pfsense",   label:"pfSense / OPNsense" },
    { id:"paloalto",  label:"Palo Alto" },
    { id:"windows",   label:"Windows Firewall" },
    { id:"nginx",     label:"Nginx deny block" },
    { id:"apache",    label:"Apache .htaccess" },
    { id:"json",      label:"JSON (API use)" }
  ];
 
  modal.innerHTML = `
    <div style="padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-size:13px;font-weight:700;color:var(--text);">🛡 Firewall Rule Export</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px;">${uniqueIPs.length} CRITICAL/HIGH IP${uniqueIPs.length!==1?"s":""} from audit log</div>
      </div>
      <button id="firewallClose" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
    </div>
    <div style="padding:16px 24px;border-bottom:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap;">
      ${formats.map(f => `
        <button class="fw-format-btn" data-format="${f.id}"
          style="padding:5px 12px;border-radius:6px;border:1px solid ${f.id==="iptables"?"var(--accent)":"var(--border)"};
                 background:${f.id==="iptables"?"rgba(0,217,255,0.1)":"transparent"};
                 color:${f.id==="iptables"?"var(--accent)":"var(--text3)"};
                 font-size:11px;cursor:pointer;font-family:inherit;">${f.label}</button>`).join("")}
    </div>
    <div style="padding:12px 24px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;">
      <label style="font-size:11px;color:var(--text3);">Action:</label>
      <select id="fwAction" style="padding:4px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
        <option value="DROP">DROP (silent block)</option>
        <option value="REJECT">REJECT (send reset)</option>
      </select>
      <label style="font-size:11px;color:var(--text3);margin-left:8px;">Risk filter:</label>
      <select id="fwRisk" style="padding:4px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
        <option value="both">CRITICAL + HIGH</option>
        <option value="critical">CRITICAL only</option>
      </select>
      <button id="fwCopy" class="btn btn-ghost" style="margin-left:auto;padding:5px 14px;font-size:11px;">Copy</button>
      <button id="fwDownload" class="btn btn-primary" style="padding:5px 14px;font-size:11px;">Download</button>
    </div>
    <pre id="fwOutput" style="flex:1;overflow-y:auto;margin:0;padding:16px 24px;font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.6;color:var(--text);background:var(--bg2);white-space:pre-wrap;word-break:break-all;"></pre>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  // Close handlers
  document.getElementById("firewallClose").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  // Format switching
  modal.querySelectorAll(".fw-format-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      modal.querySelectorAll(".fw-format-btn").forEach(b => {
        b.style.borderColor = "var(--border)"; b.style.background = "transparent"; b.style.color = "var(--text3)";
      });
      btn.style.borderColor = "var(--accent)"; btn.style.background = "rgba(0,217,255,0.1)"; btn.style.color = "var(--accent)";
      updateOutput();
    });
  });
 
  document.getElementById("fwAction").addEventListener("change", updateOutput);
  document.getElementById("fwRisk").addEventListener("change", updateOutput);
 
  document.getElementById("fwCopy").addEventListener("click", () => {
    const text = document.getElementById("fwOutput").textContent;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById("fwCopy");
      btn.textContent = "✓ Copied!";
      setTimeout(() => { btn.textContent = "Copy"; }, 2000);
    });
  });
 
  document.getElementById("fwDownload").addEventListener("click", () => {
    const fmt  = modal.querySelector(".fw-format-btn[style*='var(--accent)']")?.dataset.format || "iptables";
    const text = document.getElementById("fwOutput").textContent;
    const ext  = { iptables:"sh", ip6tables:"sh", ufw:"sh", cisco:"txt", pfsense:"txt", paloalto:"txt", windows:"ps1", nginx:"conf", apache:"htaccess", json:"json" }[fmt] || "txt";
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: `ipshield-firewall-${fmt}-${Date.now()}.${ext}` });
    a.click(); URL.revokeObjectURL(url);
    toast(`Firewall rules exported as ${fmt.toUpperCase()} (${ips.length} IPs)`, "success");
  });
 
  // Generate rules
  function updateOutput() {
    const fmt    = modal.querySelector(".fw-format-btn[style*='var(--accent)']")?.dataset.format || "iptables";
    const action = document.getElementById("fwAction").value;
    const risk   = document.getElementById("fwRisk").value;
    const ips    = uniqueIPs.filter(e => risk === "critical" ? e.riskLevel === "CRITICAL" : true).map(e => e.ip);
    document.getElementById("fwOutput").textContent = generateRules(fmt, ips, action);
  }
 
  updateOutput(); // initial render

  // mobile responsive
  const MODAL_OVERLAY_STYLE = `
  position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10000;
  display:flex;align-items:${window.innerWidth < 640 ? "flex-end" : "center"};
  justify-content:center;padding:${window.innerWidth < 640 ? "0" : "24px"};`;
 
  const MODAL_STYLE = `
    background:var(--bg1);border:1px solid var(--border);
    border-radius:${window.innerWidth < 640 ? "12px 12px 0 0" : "12px"};
    width:100%;max-width:${window.innerWidth < 640 ? "100%" : "700px"};
    max-height:${window.innerWidth < 640 ? "92vh" : "85vh"};
    display:flex;flex-direction:column;overflow:hidden;`;
}
 
function generateRules(format, ips, action = "DROP") {
  const ts      = new Date().toISOString();
  const comment = `# Generated by IPShield — ${ts}\n# ${ips.length} blocked IP(s)\n`;
  const act     = action.toLowerCase();
 
  switch (format) {
 
    case "iptables":
      return `${comment}#!/bin/bash\n\n` +
        ips.map(ip => `iptables -A INPUT  -s ${ip} -j ${action}\niptables -A OUTPUT -d ${ip} -j ${action}`).join("\n") +
        `\n\necho "✓ ${ips.length} IPs blocked"`;
 
    case "ip6tables":
      return `${comment}#!/bin/bash\n\n` +
        ips.map(ip => `ip6tables -A INPUT  -s ${ip} -j ${action}\nip6tables -A OUTPUT -d ${ip} -j ${action}`).join("\n") +
        `\n\necho "✓ ${ips.length} IPs blocked"`;
 
    case "ufw":
      return `${comment}#!/bin/bash\n\n` +
        ips.map(ip => `ufw deny from ${ip} to any\nufw deny from any to ${ip}`).join("\n") +
        `\n\nufw reload\necho "✓ ${ips.length} IPs blocked"`;
 
    case "cisco":
      return `! ${comment.replace(/#/g,"!")}` +
        `ip access-list extended IPSHIELD_BLOCK\n` +
        ips.map((ip, i) => ` ${(i+1)*10} deny ip host ${ip} any\n ${(i+1)*10+5} deny ip any host ${ip}`).join("\n") +
        `\n!\ninterface GigabitEthernet0/0\n ip access-group IPSHIELD_BLOCK in`;
 
    case "pfsense":
      return `# pfSense / OPNsense — import as alias then block\n# ${ts}\n\n` +
        `# 1. Firewall > Aliases > Add\n#    Name: IPShield_Block\n#    Type: Host(s)\n#    Network(s):\n` +
        ips.map(ip => `#    ${ip}`).join("\n") +
        `\n\n# 2. Firewall > Rules > Add rule:\n#    Action: Block, Source: IPShield_Block`;
 
    case "paloalto":
      return `# Palo Alto Networks — Dynamic Address Group\n# ${ts}\n\n` +
        `set address IPShield_Block_${Date.now()} type ip-netmask\n` +
        ips.map(ip => `set address "block_${ip.replace(/[.:]/g,"_")}" type ip-netmask ${ip}/32`).join("\n") +
        `\n\nset address-group IPShield_Block_Group static [ ${ips.map(ip=>`block_${ip.replace(/[.:]/g,"_")}`).join(" ")} ]` +
        `\nset security policy deny-ipshield from any to any source IPShield_Block_Group action deny`;
 
    case "windows":
      return `# Windows Firewall — PowerShell\n# Run as Administrator\n# ${ts}\n\n` +
        ips.map((ip, i) =>
          `New-NetFirewallRule -DisplayName "IPShield_Block_${i+1}" -Direction Inbound  -RemoteAddress ${ip} -Action Block\n` +
          `New-NetFirewallRule -DisplayName "IPShield_Block_${i+1}_Out" -Direction Outbound -RemoteAddress ${ip} -Action Block`
        ).join("\n") +
        `\n\nWrite-Host "✓ ${ips.length} IPs blocked"`;
 
    case "nginx":
      return `# Nginx — add inside http {} or server {} block\n# ${ts}\n\ngeo $blocked_ip {\n    default 0;\n` +
        ips.map(ip => `    ${ip} 1;`).join("\n") +
        `\n}\n\n# Then in server block:\n# if ($blocked_ip) { return 403; }`;
 
    case "apache":
      return `# Apache .htaccess\n# ${ts}\n\n<RequireAll>\n    Require all granted\n` +
        ips.map(ip => `    Require not ip ${ip}`).join("\n") +
        `\n</RequireAll>`;
 
    case "json":
      return JSON.stringify({
        generated:  ts,
        tool:       "IPShield",
        total:      ips.length,
        action,
        blocklist:  ips
      }, null, 2);
 
    default:
      return ips.join("\n");
  }
}
 
// ── Filter in-memory entries 
function applyFilters(entries) {
  return entries.filter(e => {
    const f = auditFilters;
    if (f.q) {
      const q = f.q.toLowerCase();
      if (!e.ip?.toLowerCase().includes(q) &&
          !e.geo?.country?.toLowerCase().includes(q) &&
          !e.network?.isp?.toLowerCase().includes(q)) return false;
    }
    if (f.risk       && e.riskLevel !== f.risk)                                  return false;
    if (f.minScore != null && (e.score??0) < f.minScore)                         return false;
    if (f.maxScore != null && (e.score??0) > f.maxScore)                         return false;
    if (f.proxy    != null && !!e.intelligence?.isProxy !== f.proxy)             return false;
    if (f.tor      != null && !!e.intelligence?.isTor   !== f.tor)               return false;
    if (f.datacenter != null && !!e.intelligence?.isDatacenter !== f.datacenter) return false;
    return true;
  });
}
 
function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    switch (auditFilters.sort) {
      case "score_desc": return (b.score??0) - (a.score??0);
      case "score_asc":  return (a.score??0) - (b.score??0);
      case "date_asc":   return new Date(a.meta?.scoredAt||0) - new Date(b.meta?.scoredAt||0);
      default:           return new Date(b.meta?.scoredAt||0) - new Date(a.meta?.scoredAt||0);
    }
  });
}
 
// ── Fetch from DB via API 
async function fetchAndRenderFromDB() {
  const params = new URLSearchParams({
    limit:  AUDIT_PAGE_SIZE,
    offset: auditPage * AUDIT_PAGE_SIZE,
    sort:   auditFilters.sort
  });
  if (auditFilters.q)                   params.set("q",           auditFilters.q);
  if (auditFilters.risk)                params.set("risk",        auditFilters.risk);
  if (auditFilters.minScore > 0)        params.set("minScore",    auditFilters.minScore);
  if (auditFilters.maxScore < 100)      params.set("maxScore",    auditFilters.maxScore);
  if (auditFilters.proxy    != null)    params.set("proxy",       auditFilters.proxy);
  if (auditFilters.tor      != null)    params.set("tor",         auditFilters.tor);
  if (auditFilters.datacenter != null)  params.set("datacenter",  auditFilters.datacenter);
 
  try {
    const res  = await fetch(`${API}/audit/search?${params}`, { headers: { "x-api-key": API_KEY } });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    auditTotal = data.total;
    renderAuditEntries(data.entries, data.total);
  } catch (err) {
    setBulkStatus(`Audit DB error: ${err.message}`);
  }
}
 
// ── Main renderAudit 
function addAuditEntry(d) {
  auditEntries.unshift(d);
  if (auditEntries.length > 200) auditEntries.pop();
  if (!usingDB) renderAudit();
}
 
function renderAudit() {
  if (usingDB) { fetchAndRenderFromDB(); return; }

  const filtered = sortEntries(applyFilters(auditEntries));
  auditTotal     = filtered.length;
  const start    = auditPage * AUDIT_PAGE_SIZE;
  const page     = filtered.slice(start, start + AUDIT_PAGE_SIZE);
  renderAuditEntries(page, filtered.length);
}
 
function renderAuditEntries(entries, total) {
  auditCount.textContent = `${total} ${total===1?"entry":"entries"}`;
 
  const status = document.getElementById("auditFilterStatus");
  const hasFilter = auditFilters.q || auditFilters.risk || auditFilters.minScore > 0 ||
                    auditFilters.maxScore < 100 || auditFilters.proxy != null ||
                    auditFilters.tor != null || auditFilters.datacenter != null;
 
  if (status) {
    status.textContent = hasFilter
      ? `Showing ${Math.min(entries.length, total)} of ${total} matching entries${usingDB ? " (DB)" : " (session)"}`
      : usingDB ? `Full database history — ${total} total entries` : "";
  }
 
  if (!entries.length) {
    auditList.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
      ${hasFilter ? "No entries match your filters" : "No queries yet"}
    </div>`;
    return;
  }
 
  auditList.innerHTML = entries.map(e => {

    // Handle both in-memory format and DB row format
    const ip        = e.ip;
    const score     = e.score       ?? 0;
    const riskLevel = e.riskLevel   || e.risk_level || "LOW";
    const scoredAt  = e.meta?.scoredAt || (e.scored_at ? new Date(e.scored_at) : new Date());
    const f = [
      (e.threatFeeds?.feodo || e.is_feodo)           && "F",
      (e.threatFeeds?.spamhaus || e.is_spamhaus)     && "S",
      (e.threatFeeds?.emergingThreats || e.is_et)    && "E",
      (e.threatFeeds?.otx?.pulseCount > 0)           && "O"
    ].filter(Boolean).join("");
 
    return `<div class="audit-item" data-ip="${escHtml(ip)}">
      <span class="audit-ip">${escHtml(ip)}</span>
      ${f ? `<span style="font-size:9px;color:#ff3355;font-weight:700;">[${f}]</span>` : ""}
      <span class="audit-badge ${riskLevel}">${riskLevel}</span>
      <span class="audit-score ${riskLevel}">${score}</span>
      <span class="audit-ts">${fmtTime(new Date(scoredAt))}</span>
    </div>`;
  }).join("");
 
  // Pagination controls
  const totalPages = Math.ceil(total / AUDIT_PAGE_SIZE);
  if (totalPages > 1) {
    const nav = document.createElement("div");
    nav.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:8px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text3);";
    nav.innerHTML = `
      <button id="auditPrev" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage===0?"disabled":""}>← Prev</button>
      <span>Page ${auditPage+1} of ${totalPages}</span>
      <button id="auditNext" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage>=totalPages-1?"disabled":""}>Next →</button>`;
    auditList.appendChild(nav);
 
    document.getElementById("auditPrev")?.addEventListener("click", () => { auditPage--; renderAudit(); });
    document.getElementById("auditNext")?.addEventListener("click", () => { auditPage++; renderAudit(); });
  }
 
  auditList.querySelectorAll(".audit-item").forEach(item => {
    item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
  });
}

  // ── Map 
 function initMap() {
  const container = document.getElementById("mapContainer");
  if (!container || typeof L === "undefined") return;
  container.innerHTML = "";
 
  // Responsive height
  const height = window.innerWidth < 480 ? "180px"
               : window.innerWidth < 640 ? "220px"
               : "320px";
  container.style.cssText = `height:${height};`;
 
  map = L.map("mapContainer", { zoomControl: window.innerWidth > 640, attributionControl: false });
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    maxZoom: 19, subdomains: "abcd"
  }).addTo(map);
  map.setView([20, 0], 2);
 
  // Update height on resize
  window.addEventListener("resize", () => {
    const newHeight = window.innerWidth < 480 ? "180px"
                    : window.innerWidth < 640 ? "220px"
                    : "320px";
    const c = document.getElementById("mapContainer");
    if (c) { c.style.height = newHeight; map.invalidateSize(); }
  });
}

  function updateMap(geo, ip, riskLevel) {
    if (!map || geo.lat == null || geo.lon == null) return;
    const color = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c" }[riskLevel] || "#00d9ff";
    const icon  = L.divIcon({
      className: "", iconSize: [14,14], iconAnchor: [7,7],
      html: `<div style="width:14px;height:14px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 0 8px ${color};"></div>`
    });
    if (mapMarker) map.removeLayer(mapMarker);
    mapMarker = L.marker([geo.lat, geo.lon], { icon })
      .addTo(map)
      .bindPopup(`<b style="font-family:monospace">${ip}</b><br>${geo.city||""}, ${geo.country||""}<br>Risk: ${riskLevel}`)
      .openPopup();
    map.flyTo([geo.lat, geo.lon], 6, { duration: 1.2 });
    const label = document.getElementById("mapLabel");
    if (label) label.textContent = `${geo.city||"—"}, ${geo.country||"—"}`;
  }

  // ── Events 
  function setupEventListeners() {
    scoreBtn.addEventListener("click", scoreIP);
    clearBtn.addEventListener("click", clearPanel);
    // apiDocsBtn.addEventListener("click", () => window.open("https://ipshield.live/api/docs", "_blank"));
    ipInput.addEventListener("keydown", e => { if (e.key === "Enter") scoreIP(); });

    document.querySelectorAll(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => { ipInput.value = chip.dataset.ip; scoreIP(); });
    });

    document.addEventListener("click", e => {
      if (e.target.id === "apiBadge")      showVersionPanel();
      if (e.target.id === "siemBtn")       showSIEMPanel();
      if (e.target.id === "blacklistBtn")  showBlacklistPanel();
      if (e.target.id === "casesBtn")      showCasesPanel();
      if (e.target.id === "firewallBtn")   showFirewallExport();
      if (e.target.id === "csvBtn")        document.getElementById("csvUpload").click();
      if (e.target.id === "exportBtn")     exportLog();
      if (e.target.id === "addWatchBtn")   addCurrentToWatchlist();
      if (e.target.id === "pollBtn")       triggerPoll();
      if (e.target.id === "addToCaseBtn")  addIPToCase(currentIP, lastResult);
      if (e.target.id === "versionBtn")    showVersionPanel();
    });

    document.addEventListener("change", e => {
      if (e.target.id === "csvUpload") handleCSVUpload(e.target.files[0]);
    });

   

    // Single unified click handler on resultBody — no inline onclick needed
    resultBody.addEventListener("click", e => {
      if (e.target.id === "watchCurrentBtn") {
        addCurrentToWatchlist();
        return;
      }

    // download pdfbtn
    if (e.target.id === "downloadPdfBtn") {
        const ip  = currentIP || ipInput.value.trim();
        if (!ip) return;
        const url = `${API}/report/${encodeURIComponent(ip)}?cached=true`;

        // Open in new tab — browser handles the PDF download
        const a = Object.assign(document.createElement("a"), {
          href:     url,
          download: `ipshield-${ip}-report.pdf`
        });
        // Must add auth header — use fetch + blob instead of direct link
        e.target.textContent = "Generating…";
        e.target.disabled    = true;
        fetch(url, { headers: { "x-api-key": API_KEY } })
          .then(r => {
            if (!r.ok) throw new Error("Report generation failed");
            return r.blob();
          })
          .then(blob => {
            const blobUrl = URL.createObjectURL(blob);
            Object.assign(a, { href: blobUrl });
            document.body.appendChild(a);
            a.click();
            toast(`PDF report downloaded for ${ip}`, "success");
            document.body.removeChild(a);
            URL.revokeObjectURL(blobUrl);
          })
          .catch(err => toast(`PDF error: ${err.message}`, "error"))
          .finally(() => {
            e.target.textContent = "↓ PDF Report";
            e.target.disabled    = false;
          });
      }

    // timelinebtn
    if (e.target.id === "timelineBtn") {
    showTimeline(currentIP || ipInput.value.trim());
   }

   // blacklistbtn
    if (e.target.id === "blockCurrentBtn") {
      if (lastResult?.blacklisted) {
        showBlacklistPanel(); // 
      } else {
        quickBlock(currentIP);
      }
    }


      // ── Tab switching
      const tabBtn = e.target.closest(".tab-btn");
      if (tabBtn) {
        const tab = tabBtn.dataset.tab;
        const ip  = tabBtn.dataset.ip;
        ["Signals","Network","WHOIS"].forEach(t => {
          const content = document.getElementById(`tabContent-${t}`);
          const btn     = resultBody.querySelector(`.tab-btn[data-tab="${t}"]`);
          if (content) content.style.display = t === tab ? "block" : "none";
          if (btn) {
            btn.style.borderBottomColor = t === tab ? "var(--accent)" : "transparent";
            btn.style.color             = t === tab ? "var(--accent)" : "var(--text3)";
          }
        });
        if (tab === "WHOIS" && ip) {
          const panel = document.getElementById("whoisPanel");
          if (panel && panel.dataset.loaded === "false") {
            panel.dataset.loaded = "true";
            loadWhois(ip);
          }
        }
      }
    });
  }

  // ── Theme 
  function toggleTheme() {
  isDark = !isDark;
  applyTheme(isDark);
  localStorage.setItem("ipshield_theme", isDark ? "dark" : "light");
}
 
function applyTheme(dark) {
  const root = document.documentElement;
  const btn  = document.getElementById("themeToggle");
 
  if (dark) {
    // Remove all overrides — CSS variables revert to dark defaults
    [
      "--bg","--bg1","--bg2","--bg3",
      "--text","--text2","--text3",
      "--border","--border2"
    ].forEach(v => root.style.removeProperty(v));
 
    if (btn) btn.textContent = "☀ LIGHT";
 
    if (map) {
      map.eachLayer(l => { if (l._url) map.removeLayer(l); });
      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 19, subdomains: "abcd"
      }).addTo(map);
    }
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
 
    if (map) {
      map.eachLayer(l => { if (l._url) map.removeLayer(l); });
      L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 19, subdomains: "abcd"
      }).addTo(map);
    }
  }
}

  // ── Score 
  async function scoreIP() {
    const ip = ipInput.value.trim();
    if (!ip) return;
    if (!isValidIP(ip)) { showError("Invalid IP address format."); return; }
    setLoading(true);
    try {
      const res  = await fetch(`${API}/score/${encodeURIComponent(ip)}`, { headers: { "x-api-key": API_KEY } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scoring failed");
      currentIP  = ip;
      lastResult = data;
      renderResult(data);
      addAuditEntry(data);
      updateStats(data.riskLevel);
      updateMap(data.geo || {}, data.ip, data.riskLevel);
      showAPIStatus(data.apiStatus);
    } 
    catch (err) {
      showError(err.message || "Service temporarily unavailable.");
    } 
    finally {
      setLoading(false);
    }
  }

  // Show Rate Limiting
  async function showSIEMPanel() {

  // Fetch current status
  let status = null;
  let formats = [];
  try {
    const [sRes, fRes] = await Promise.all([
      fetch(`${API}/siem/status`, { headers: { "x-api-key": API_KEY } }),
      fetch(`${API}/siem/formats`, { headers: { "x-api-key": API_KEY } })
    ]);
    const sData = await sRes.json();
    const fData = await fRes.json();
    status  = sData.siem;
    formats = fData.formats || [];
  } catch (_) {}
 
  const overlay = document.createElement("div");
  overlay.id = "siemModal";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:10000;display:flex;align-items:center;justify-content:center;padding:24px;";
 
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;width:100%;max-width:700px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;";
 
  const statusColor  = status?.enabled ? "var(--low)" : "var(--text3)";
  const statusLabel  = status?.enabled ? "● ACTIVE" : "○ INACTIVE";
 
  modal.innerHTML = `
    <div style="padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-size:13px;font-weight:700;color:var(--text);">SIEM Webhook Integration</div>
        <div style="font-size:11px;margin-top:3px;color:${statusColor};">${statusLabel}${status?.type ? ` — ${status.type.toUpperCase()}` : ""}</div>
      </div>
      <button id="siemClose" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:20px;padding:4px;">✕</button>
    </div>
 
    <div style="background:var(--bg2);overflow-y:auto;flex:1;padding:24px;display:flex;flex-direction:column;gap:20px;">
 
      <!-- Config status -->
      <div class="detail-card">
        <div class="detail-card-title" style="color:var(--text);font-size:11px;font-weight:400;">Current Configuration</div>
        ${kv("Status",        status?.enabled ? "Enabled" : "Disabled")}
        ${kv("Type",          status?.type?.toUpperCase() || "Not set")}
        ${kv("Webhook URL",   status?.url || "Not configured")}
        ${kv("Token",         status?.hasToken ? "Set ✓" : "Not set")}
        ${kv("Min Score",     status?.minScore ?? 0)}
        ${kv("Min Risk",      status?.minRisk  || "LOW")}
      </div>
 
      <!-- Env var instructions -->
      <div class="detail-card">
        <div class="detail-card-title" style="color:var(--text);font-size:11px;font-weight:400;">Setup — Add to Render Environment Variables</div>
        <div style="background:var(--bg1);border-radius:6px;font-size:11px;line-height:2;color:var(--text2);font-family:'JetBrains Mono',monospace;overflow-x:auto;">
          SIEM_ENABLED=true<br>
          SIEM_TYPE=<span style="color:var(--accent)">splunk|elastic|sentinel|qradar|generic</span><br>
          SIEM_WEBHOOK_URL=<span style="color:var(--accent)">https://your-siem-endpoint</span><br>
          SIEM_TOKEN=<span style="color:var(--accent)">your_token_or_api_key</span><br>
          SIEM_MIN_SCORE=<span style="color:var(--accent)">0</span>     <span style="color:var(--text3)"># 0–100, only forward above this</span><br>
          SIEM_MIN_RISK=<span style="color:var(--accent)">LOW</span>    <span style="color:var(--text3)"># LOW|MEDIUM|HIGH|CRITICAL</span>
          </div>
      </div>
 
      <!-- Supported formats -->
      <div class="detail-card">
        <div class="detail-card-title" style="color:var(--text);font-size:11px;font-weight:400;">Supported Platforms</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
          ${formats.map(f => `
            <div style="padding:10px 12px;background:var(--bg1);border-radius:6px;border:0.9px solid var(--border);">
              <div style="font-size:11px;font-weight:700;color:var(--accent);margin-bottom:3px;">${escHtml(f.label)}</div>
              <div style="font-size:10px;color:var(--text3);line-height:1.5;">${escHtml(f.description)}</div>
            </div>`).join("")}
        </div>
      </div>
 
      <!-- Test webhook -->
      <div class="detail-card">
        <div class="detail-card-title" style="color:var(--text);font-size:11px;font-weight:400;">Test Webhook</div>
        <div style="font-size:11px;color:var(--text3);margin-bottom:12px;">
          Send a sample CRITICAL IP event to your configured SIEM. Uses current env var settings.
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <button id="siemTestBtn" class="btn btn-primary" style="padding:8px 20px;font-size:12px;">
            Send Test Event
          </button>
          <span id="siemTestResult" style="font-size:12px;color:var(--text2);"></span>
        </div>
        <div id="siemTestDetail" style="margin-top:12px;font-size:11px;color:var(--text3);display:none;"></div>
      </div>
 
      <!-- Sample payload viewer -->
      <div class="detail-card">
        <div class="detail-card-title" style="color:var(--text);font-size:11px;font-weight:400;">Sample Payload</div>
        <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;">
          ${formats.map((f, i) => `
            <button class="siem-format-tab" data-format="${f.id}"
              style="padding:4px 12px;border-radius:4px;border:1px solid ${i===0?"var(--accent)":"var(--border)"};
                     background:${i===0?"rgba(0,217,255,0.1)":"transparent"};
                     color:${i===0?"var(--accent)":"var(--text3)"};
                     font-size:10px;cursor:pointer;font-family:inherit;">${f.label}</button>`).join("")}
        </div>
        <pre id="siemSamplePayload" style="background:var(--bg);border-radius:6px;padding:12px;font-size:10px;line-height:1.6;color:var(--text2);overflow:auto;max-height:200px;white-space:pre-wrap;word-break:break-all;">Loading…</pre>
        <button id="siemCopySample" class="btn btn-ghost" style="margin-top:8px;padding:5px 14px;font-size:11px;">Copy Sample</button>
      </div>
    </div>`;
 
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
 
  // Close
  document.getElementById("siemClose").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
 
  // Load first sample
  loadSIEMSample(formats[0]?.id || "generic");
 
  // Format tabs
  modal.querySelectorAll(".siem-format-tab").forEach(btn => {
    btn.addEventListener("click", () => {
      modal.querySelectorAll(".siem-format-tab").forEach(b => {
        b.style.borderColor = "var(--border)"; b.style.background = "transparent"; b.style.color = "var(--text3)";
      });
      btn.style.borderColor = "var(--accent)"; btn.style.background = "rgba(0,217,255,0.1)"; btn.style.color = "var(--accent)";
      loadSIEMSample(btn.dataset.format);
    });
  });
 
  // Test button
  document.getElementById("siemTestBtn").addEventListener("click", async () => {
    const btn    = document.getElementById("siemTestBtn");
    const result = document.getElementById("siemTestResult");
    const detail = document.getElementById("siemTestDetail");
    btn.disabled = true; btn.textContent = "Sending…";
    result.textContent = ""; detail.style.display = "none";
    try {
      const res  = await fetch(`${API}/siem/test`, {
        method: "POST", headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body: JSON.stringify({})
      });
      const data = await res.json();
      result.textContent = data.message;
      result.style.color = data.success ? "var(--low)" : "var(--critical)";
      if (!data.success && data.reason) {
        detail.textContent = `Reason: ${data.reason}`;
        detail.style.display = "block";
        detail.style.color = "var(--text3)";
      }
    } catch (err) {
      result.textContent = `Error: ${err.message}`;
      result.style.color = "var(--critical)";
    } finally {
      btn.disabled = false; btn.textContent = "Send Test Event";
    }
  });
 
  // Copy sample
  document.getElementById("siemCopySample").addEventListener("click", () => {
    const text = document.getElementById("siemSamplePayload").textContent;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById("siemCopySample");
      btn.textContent = "✓ Copied!";
      setTimeout(() => { btn.textContent = "Copy Sample"; }, 2000);
    });
  });
 
  async function loadSIEMSample(format) {
    const pre = document.getElementById("siemSamplePayload");
    pre.textContent = "Loading…";
    try {
      const res  = await fetch(`${API}/siem/sample/${format}`, { headers: { "x-api-key": API_KEY } });
      const data = await res.json();
      pre.textContent = JSON.stringify(data.sample, null, 2);
    } catch (err) {
      pre.textContent = `Error: ${err.message}`;
    }
  }

  // mobile responsive 
  const MODAL_OVERLAY_STYLE = `
  position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10000;
  display:flex;align-items:${window.innerWidth < 640 ? "flex-end" : "center"};
  justify-content:center;padding:${window.innerWidth < 640 ? "0" : "24px"};`;
 
const MODAL_STYLE = `
  background:var(--bg1);border:1px solid var(--border);
  border-radius:${window.innerWidth < 640 ? "12px 12px 0 0" : "12px"};
  width:100%;max-width:${window.innerWidth < 640 ? "100%" : "700px"};
  max-height:${window.innerWidth < 640 ? "92vh" : "85vh"};
  display:flex;flex-direction:column;overflow:hidden;`;
  }

  // rdnsCard Function
  function rdnsCard(rdns) {
  if (!rdns) return "";
 
  if (rdns.private) {
    return `
      <div class="detail-card" style="margin-top:16px;">
        <div class="detail-card-title">// Reverse DNS</div>
        <div style="font-size:11px;color:var(--text3);padding:4px 0;">Private IP — no PTR record</div>
      </div>`;
  }
 
  if (!rdns.primary && !rdns.hostnames?.length) {
    return `
      <div class="detail-card" style="margin-top:16px;">
        <div class="detail-card-title">// Reverse DNS</div>
        <div style="font-size:11px;color:var(--text3);padding:4px 0;">No PTR record found</div>
      </div>`;
  }
 
  const fcrdnsBadge = rdns.fcrdns === true
    ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,232,124,0.12);color:var(--low);border:1px solid rgba(0,232,124,0.3);margin-left:8px;">✓ FCrDNS</span>`
    : rdns.fcrdns === false
    ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(255,204,0,0.12);color:var(--medium);border:1px solid rgba(255,204,0,0.3);margin-left:8px;">⚠ Mismatch</span>`
    : "";
 
  const extraHostnames = (rdns.hostnames || []).slice(1);
 
  return `
    <div class="detail-card" style="margin-top:16px;">
      <div class="detail-card-title">// Reverse DNS (PTR)</div>
      <div class="kv" style="margin-top:6px;">
        <span class="kv-key">Primary PTR</span>
        <span style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">
          <span style="color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px;">${escHtml(rdns.primary)}</span>
          ${fcrdnsBadge}
        </span>
      </div>
      ${extraHostnames.length ? `
        <div class="kv">
          <span class="kv-key">Other PTRs</span>
          <span class="kv-val">
            ${extraHostnames.map(h => `<div style="font-size:11px;color:var(--text2);font-family:'JetBrains Mono',monospace;">${escHtml(h)}</div>`).join("")}
          </span>
        </div>` : ""}
      ${rdns.fcrdns === false ? `
        <div style="margin-top:8px;padding:8px 10px;background:rgba(255,204,0,0.07);border-radius:6px;border-left:3px solid var(--medium);">
          <div style="font-size:10px;color:var(--medium);font-weight:700;letter-spacing:1px;margin-bottom:3px;">FCrDNS MISMATCH</div>
          <div style="font-size:11px;color:var(--text3);">PTR hostname does not resolve back to this IP — common indicator of spoofed or misconfigured reverse DNS.</div>
        </div>` : ""}
      ${rdns.fcrdns === true ? `
        <div style="margin-top:6px;font-size:10px;color:var(--text3);">Forward-confirmed reverse DNS verified</div>` : ""}
    </div>`;
}



  // ── Watchlist 
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
    if (!ip || !isValidIP(ip)) { toast("Score an IP first, then click + WATCH", "warning"); return; }
    const label     = prompt(`Label for ${ip}:`, ip) ?? ip;
    const threshold = parseInt(prompt("Alert threshold (0-100):", "30") || "30");
    try {
      const res  = await fetch(`${API}/watchlist`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body: JSON.stringify({ ip, label, threshold, alertOnChange: true })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast(`${ip} added to watchlist`, "success");
      loadWatchlist();
    } catch (err) { toast(`Watchlist error: ${err.message}`, "error"); }
  }

  async function removeFromWatchlist(ip) {
    try {
      await fetch(`${API}/watchlist/${encodeURIComponent(ip)}`, {
        method: "DELETE", headers: { "x-api-key": API_KEY }
      });
      loadWatchlist();
    } catch (err) { toast(`Watchlist error: ${err.message}`, "error"); }
  }

  async function triggerPoll() {
    const btn = document.getElementById("pollBtn");
    if (btn) { btn.disabled = true; btn.textContent = "↻ POLLING…"; }
    try {
      await fetch(`${API}/watchlist/poll`, { method: "POST", headers: { "x-api-key": API_KEY } });
      toast("Watchlist poll triggered — updating shortly", "info");
      setTimeout(loadWatchlist, 5000);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "↻ POLL"; }
    }
  }

  function renderWatchlist(items, monitor) {
    const count = document.getElementById("watchlistCount");
    const body  = document.getElementById("watchlistBody");
    const mStat = document.getElementById("monitorStatus");

    if (count) count.textContent = `${items.length} IP${items.length !== 1 ? "s" : ""}`;
    if (monitor && mStat) mStat.textContent = `Monitor: ${monitor.active ? "● ACTIVE" : "○ INACTIVE"} · every ${monitor.intervalMins}min`;

    if (!items.length) {
      if (body) body.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No IPs being watched.<br>Score an IP then click <strong>+ WATCH</strong>.</div>`;
      return;
    }

    if (!body) return;

    body.innerHTML = items.map(item => {
      const clr = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c", UNKNOWN:"#6a8fa8" }[item.last_risk] || "#6a8fa8";
      const chk = item.last_checked ? new Date(item.last_checked).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}) : "never";
      return `
        <div class="watchlist-item" data-ip="${escHtml(item.ip)}"
          style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;">
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:var(--text);font-family:monospace;">${escHtml(item.ip)}</div>
            <div style="font-size:10px;color:var(--text3);">${item.label !== item.ip ? escHtml(item.label) + " · " : ""}checked ${chk}</div>
            <div style="height:2px;background:var(--bg3);border-radius:2px;margin-top:4px;">
              <div style="height:2px;width:${item.last_score}%;background:${clr};border-radius:2px;"></div>
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="font-size:16px;font-weight:700;color:${clr};">${item.last_score}</div>
            <div style="font-size:9px;font-weight:700;color:${clr};letter-spacing:1px;">${item.last_risk}</div>
          </div>
          <div style="font-size:10px;color:var(--text3);">⚑${item.threshold}</div>
          <button class="watchlist-remove" data-ip="${escHtml(item.ip)}"
            style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;padding:4px;" title="Remove">✕</button>
        </div>`;
    }).join("");

    body.querySelectorAll(".watchlist-item").forEach(row => {
      row.addEventListener("click", () => { ipInput.value = row.dataset.ip; scoreIP(); });
    });
    body.querySelectorAll(".watchlist-remove").forEach(btn => {
      btn.addEventListener("click", e => { e.stopPropagation(); removeFromWatchlist(btn.dataset.ip); });
    });
  }

  // ── WHOIS 
  async function loadWhois(ip) {
    const panel = document.getElementById("whoisPanel");
    if (!panel) return;
    panel.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text2);font-size:12px;">Loading WHOIS data for ${escHtml(ip)}…</div>`;
    try {
      const res  = await fetch(`${API}/whois/${encodeURIComponent(ip)}`, { headers: { "x-api-key": API_KEY } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "WHOIS lookup failed");
      renderWhois(data.whois, data.signals || [], panel);
    } catch (err) {
      panel.dataset.loaded = "false";
      panel.innerHTML = `<div style="padding:16px;color:var(--critical);font-size:12px;">⚠ ${escHtml(err.message)}<br><small style="color:var(--text3);">Click WHOIS tab to retry</small></div>`;
    }
  }

  function renderWhois(w, signals, panel) {
    if (!w) {
      panel.innerHTML = `<div style="padding:16px;color:var(--text3);font-size:12px;">No WHOIS data available for this IP</div>`;
      return;
    }
    const ageBadge = w.agedays !== null
      ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;margin-left:8px;
           background:${w.agedays < 30 ? "rgba(255,51,85,0.15)" : w.agedays < 90 ? "rgba(255,119,0,0.15)" : "rgba(0,232,124,0.1)"};
           color:${w.agedays < 30 ? "#ff3355" : w.agedays < 90 ? "#ff7700" : "#00e87c"};">
           ${w.agedays < 1 ? "< 1 day old" : w.agedays + " days old"}
         </span>` : "";

    panel.innerHTML = `
      ${signals.length ? `
        <div style="padding:12px 0px;">
          ${signals.map(s => `
            <div class="signal-item ${s.severity}" style="margin-bottom:6px;">
              <span class="sig-cat">${escHtml(s.category)}</span>
              <span class="sig-detail">${escHtml(s.detail)}</span>
              <span class="sig-sev">${s.severity.toUpperCase()}</span>
            </div>`).join("")}
        </div>` : ""}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="detail-card">
          <div class="detail-card-title">// Registration</div>
          ${kv("Network",  w.network  || "—")}
          ${kv("Handle",   w.handle   || "—")}
          ${kv("CIDR",     w.cidr     || "—")}
          ${kv("Type",     w.type     || "—")}
          <div class="kv">
            <span class="kv-key">Registered</span>
            <span class="kv-val">${w.registered && w.registered !== "—" ? new Date(w.registered).toLocaleDateString() : "—"}${ageBadge}</span>
          </div>
          ${kv("Last Changed", w.lastChanged && w.lastChanged !== "—" ? new Date(w.lastChanged).toLocaleDateString() : "—")}
        </div>
        <div class="detail-card">
          <div class="detail-card-title">// Organization</div>
          ${kv("Org Name",    w.orgName    || "—")}
          ${kv("Org ID",      w.orgId      || "—")}
          ${kv("Country",     w.country    || "—")}
          ${kv("Abuse Email", w.abuseEmail || "—")}
          ${kv("Registrar",   w.registrar  || "—")}
        </div>
      </div>
      ${w.remarks?.length ? `
        <div style="padding:24px 2px 16px;">
          <div class="detail-card">
            <div class="detail-card-title">// Remarks</div>
            ${w.remarks.map(r => `<div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${escHtml(r)}</div>`).join("")}
          </div>
        </div>` : ""}`;
  }


  // ── Render result 
  function renderResult(d) {
    const score     = d.score        ?? 0;
    const riskLevel = d.riskLevel    ?? "LOW";
    const action    = d.action       ?? "ALLOW";
    const geo       = d.geo          ?? {};
    const network   = d.network      ?? {};
    const intel     = d.intelligence ?? {};
    const rdns      = d.rdns         ?? {};
    const meta      = d.meta         ?? {};
    const signals   = d.signals      || buildFallbackSignals(d);

    const circ   = 2 * Math.PI * 52;
    const offset = circ - (score / 100) * circ;
    const stroke = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c" }[riskLevel] || "#00e87c";

    procTime.textContent = meta.processingMs ? `${meta.processingMs}ms${meta.cached ? " · cached" : ""}` : "";

    resultBody.innerHTML = `
      <div class="score-header">
        <div class="score-ring-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="score-bg" cx="60" cy="60" r="52"/>
            <circle class="score-fill" cx="60" cy="60" r="52"
              stroke="${stroke}" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/>
          </svg>
          <div class="score-center">
            <div class="score-num" style="color:${stroke}">${score}</div>
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
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
        <button id="watchCurrentBtn" class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">+ Watch</button>
        <button id="downloadPdfBtn"  class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">↓ PDF Report</button>
        <button id="timelineBtn"     class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">↑ History</button> 
         <button id="blockCurrentBtn" class="btn btn-ghost v2-only"
      style="padding:5px 12px;font-size:11px;${apiVersion === "v1" ? "display:none;" : ""}
             color:${d.blacklisted ? "var(--low)" : "var(--critical)"};
             border-color:${d.blacklisted ? "var(--low)" : "var(--critical)"};">
      ${d.blacklisted ? "✓ Blacklisted" : "🚫 Block"}
    </button>
         <button id="addToCaseBtn" class="btn btn-ghost v2-only"
      style="padding:5px 12px;font-size:11px;${apiVersion === "v1" ? "display:none;" : ""}">
      📁 Case
    </button>
          </div>
        </div>
      </div>

      ${threatFeedBadges(d.threatFeeds)}

      <div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px;">
        ${["Signals","Network","WHOIS"].map((tab, i) => `
          <button class="tab-btn" data-tab="${tab}" data-ip="${escHtml(d.ip)}"
            style="padding:8px 16px;background:none;border:none;border-bottom:2px solid ${i===0?"var(--accent)":"transparent"};
                   color:${i===0?"var(--accent)":"var(--text3)"};cursor:pointer;font-family:inherit;font-size:11px;letter-spacing:1px;text-transform:uppercase;">
            ${tab}
          </button>`).join("")}
      </div>

      <div id="tabContent-Signals">
       ${blacklistBanner(d.blacklisted)}
        <div class="signal-list">
          ${signals.map(s => `
            <div class="signal-item ${s.severity}">
              <span class="sig-cat">${escHtml(s.category)}</span>
              <span class="sig-detail">${escHtml(s.detail)}</span>
              <span class="sig-sev">${s.severity.toUpperCase()}</span>
            </div>`).join("")}
        </div>
      </div>

      <div id="tabContent-Network" style="display:none;">
       <div class="detail-grid">
      <div class="detail-card">
        <div class="detail-card-title">// Geolocation</div>
        ${kv("Country",   geo.country  || "—")}
        ${kv("Region",    geo.region   || "—")}
        ${kv("City",      geo.city     || "—")}
        ${kv("Timezone",  geo.timezone || "—")}
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
        ${d.threatFeeds.otx.pulseNames.map(n => `
          <div class="kv"><span class="kv-key">Pulse</span><span class="kv-val">${escHtml(n)}</span></div>`).join("")}
      </div>` : ""}
      ${rdnsCard(d.rdns)}
      </div>

      <div id="tabContent-WHOIS" style="display:none;">
        <div id="whoisPanel" data-loaded="false">
          <div style="padding:16px;text-align:center;color:var(--text3);font-size:11px;">
            Click the WHOIS tab above to load deep registration data
          </div>
        </div>
      </div>`;
  }



  // ── Helpers 
  function threatFeedBadges(tf) {
    if (!tf) return "";
    const badges = [];
    if (tf.feodo)           badges.push({ label:"FEODO C2",      color:"#ff3355", bg:"rgba(255,51,85,0.15)",  tip:"Active C2 botnet — Feodo Tracker" });
    if (tf.spamhaus)        badges.push({ label:"SPAMHAUS DROP", color:"#ff3355", bg:"rgba(255,51,85,0.15)",  tip:"Do not route or peer — Spamhaus" });
    if (tf.emergingThreats) badges.push({ label:"ET INTEL",      color:"#ff7700", bg:"rgba(255,119,0,0.15)", tip:"Emerging Threats compromised list" });
    if (tf.otx?.pulseCount > 0) badges.push({ label:`OTX ×${tf.otx.pulseCount}`, color:"#ffcc00", bg:"rgba(255,204,0,0.15)", tip:`${tf.otx.pulseCount} OTX pulse(s)` });
    if (!badges.length) return `<div style="font-size:11px;color:var(--low);margin-bottom:12px;">✓ Not listed on any threat feed</div>`;
    return `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center;">
      <span style="font-size:10px;color:var(--text3);letter-spacing:2px;">THREAT FEEDS:</span>
      ${badges.map(b => `<span title="${escHtml(b.tip)}" style="font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:4px;background:${b.bg};color:${b.color};border:1px solid ${b.color};cursor:help;">${b.label}</span>`).join("")}
    </div>`;
  }

  function vtBar(label, count, total, color) {
    const pct = total > 0 ? Math.round((count/total)*100) : 0;
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
    sigs.push({ category:"ABUSE",    detail:`Confidence score: ${score}/100`, severity: score>80?"critical":score>60?"high":score>30?"medium":"low" });
    if (intel.isProxy)      sigs.push({ category:"PROXY",     detail:"Proxy detected",          severity:"high" });
    if (intel.isTor)        sigs.push({ category:"TOR",       detail:"Tor exit node",           severity:"critical" });
    if (intel.isDatacenter) sigs.push({ category:"HOSTING",   detail:"Datacenter / cloud IP",   severity:"medium" });
    sigs.push({ category:"VELOCITY", detail:`Velocity: ${intel.velocity||"LOW"}`,               severity:"info" });
    return sigs;
  }

  async function handleCSVUpload(file) {
    if (!file) return;
    const text = await file.text();
    const ips  = text.split(/[\n,]+/).map(s => s.trim()).filter(isValidIP);
    if (!ips.length)     { setBulkStatus("No valid IPs found."); return; }
    if (ips.length > 50) { setBulkStatus("Trimming to 50 IPs."); ips.length = 50; }
    setBulkStatus(`Scoring ${ips.length} IPs…`);
    try {
      const res  = await fetch(`${API}/score/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
        body: JSON.stringify({ ips })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      data.results.forEach(r => { if (r.score != null) { addAuditEntry(r); updateStats(r.riskLevel); } });
      const failed = data.results.filter(r => r.error).length;
      toast(`${data.results.length - failed} IPs scored${failed ? `, ${failed} failed` : ""}`, failed ? "warning" : "success");
      const last = data.results.find(r => r.score != null);
      if (last) { renderResult(last); updateMap(last.geo||{}, last.ip, last.riskLevel); }
    } catch (err) { toast(`Error: ${err.message}`, "error"); }
  }

  function exportLog() {
    if (!auditEntries.length) { toast("No audit entries to export yet.", "warning"); return; }
    const headers = ["IP","Score","Risk","Action","Country","City","ISP","Feodo","Spamhaus","ET","Scored At"];
    const rows    = auditEntries.map(e => [
      e.ip, e.score, e.riskLevel, e.action,
      e.geo?.country||"—", e.geo?.city||"—", e.network?.isp||"—",
      e.threatFeeds?.feodo?"Yes":"No",
      e.threatFeeds?.spamhaus?"Yes":"No",
      e.threatFeeds?.emergingThreats?"Yes":"No",
      e.meta?.scoredAt ? new Date(e.meta.scoredAt).toISOString() : new Date().toISOString()
    ]);
    const csv  = [headers,...rows].map(r => r.map(v=>`"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv],{type:"text/csv"});
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"),{href:url,download:`ipshield-${Date.now()}.csv`});
    a.click();
    URL.revokeObjectURL(url);
    toast(`Exported ${auditEntries.length} audit ${auditEntries.length === 1 ? "entry" : "entries"}`, "success");
  }

  function addAuditEntry(d) {
    auditEntries.unshift(d);
    if (auditEntries.length > 100) auditEntries.pop();
    renderAudit();
  }

  function renderAudit() {
    auditCount.textContent = `${auditEntries.length} ${auditEntries.length===1?"entry":"entries"}`;
    if (!auditEntries.length) {
      auditList.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No queries yet</div>`;
      return;
    }
    auditList.innerHTML = auditEntries.map(e => {
      const f = [
        e.threatFeeds?.feodo&&"F",
        e.threatFeeds?.spamhaus&&"S",
        e.threatFeeds?.emergingThreats&&"E",
        e.threatFeeds?.otx?.pulseCount>0&&"O"
      ].filter(Boolean).join("");
      return `<div class="audit-item" data-ip="${escHtml(e.ip)}">
        <span class="audit-ip">${escHtml(e.ip)}</span>
        ${f?`<span style="font-size:9px;color:#ff3355;font-weight:700;">[${f}]</span>`:""}
        <span class="audit-badge ${e.riskLevel}">${e.riskLevel}</span>
        <span class="audit-score ${e.riskLevel}">${e.score}</span>
        <span class="audit-ts">${fmtTime(new Date(e.meta?.scoredAt||Date.now()))}</span>
      </div>`;
    }).join("");
    auditList.querySelectorAll(".audit-item").forEach(item => {
      item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
    });
  }

  function updateStats(riskLevel) {
    if (riskLevel in sessionStats) {
      sessionStats[riskLevel]++;
      const map = { CRITICAL:"stat-critical", HIGH:"stat-high", MEDIUM:"stat-medium", LOW:"stat-low" };
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
        const map = { CRITICAL:"stat-critical", HIGH:"stat-high", MEDIUM:"stat-medium", LOW:"stat-low" };
        Object.entries(map).forEach(([risk, id]) => {
          const el = document.getElementById(id);
          if (el && data.riskDistribution[risk] != null) {
            el.textContent = data.riskDistribution[risk];
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
    const list = [
      { label:"FEODO",    data:feeds.feodo },
      { label:"SPAMHAUS", data:feeds.spamhaus },
      { label:"ET INTEL", data:feeds.emergingThreats },
      { label:"OTX",      data:feeds.otx }
    ];
    bar.innerHTML = `<span style="color:var(--text3);text-transform:uppercase;letter-spacing:2px;">Threat Feeds:</span>
      ${list.map(f => {
        const loaded = f.label==="OTX" ? f.data?.enabled : f.data?.loaded;
        const count  = f.data?.count ? ` (${Number(f.data.count).toLocaleString()})` : "";
        return `<span style="color:${loaded?"var(--low)":"var(--text3)"};">${loaded?"●":"○"} ${f.label}${count}</span>`;
      }).join("")}`;
  }

  function setLoading(on) {
    scoreBtn.disabled = on;
    if (on) {
      resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><span>Analyzing ${escHtml(ipInput.value.trim())}…</span></div>`;
      procTime.textContent = "";
    }
  }

  function clearPanel() {
    currentIP = null; lastResult = null; ipInput.value = "";
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

  function setBulkStatus(msg) {
    const el = document.getElementById("bulkStatus");
    if (el) el.textContent = msg;
  }

  function kv(key, val) {
    return `<div class="kv"><span class="kv-key">${key}</span><span class="kv-val" title="${escHtml(String(val))}">${escHtml(String(val))}</span></div>`;
  }

  function riskIcon(l) { return { CRITICAL:"■", HIGH:"▲", MEDIUM:"◆", LOW:"●" }[l] || "●"; }

  function fmtTime(d) {
    return d instanceof Date && !isNaN(d)
      ? d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}) : "—";
  }

  function escHtml(str) {
    return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function isValidIP(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip);
  }

  setInterval(loadWatchlist, 1000 * 60 * 2);
})();