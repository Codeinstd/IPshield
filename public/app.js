// (() => {
//   const API     = "/api";
//   const API_KEY = "b2bc8fe074823d37e59d57a80bbb67f6558bc145e8d6f6ef5111133a0159f020";

//   const ipInput    = document.getElementById("ipInput");
//   const scoreBtn   = document.getElementById("scoreBtn");
//   const clearBtn   = document.getElementById("clearBtn");
//   const resultBody = document.getElementById("resultBody");
//   const procTime   = document.getElementById("processingTime");
//   const auditList  = document.getElementById("auditList");
//   const auditCount = document.getElementById("auditCount");

//   const sessionStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
//   let auditEntries   = [];
//   let map            = null;
//   let mapMarker      = null;
//   let isDark         = true;
//   let currentIP      = null;
//   let lastResult     = null;

//   let auditFilters  = { q:"", risk:"", minScore:0, maxScore:100, proxy:null, tor:null, datacenter:null, sort:"date_desc" };
//   let auditPage     = 0;
//   let auditTotal    = 0;
//   let usingDB       = false; 
//   const AUDIT_PAGE_SIZE = 25;
 

//   injectExtraUI();
//   injectAuditControls(); 
//   initMap();
//   loadStats();
//   loadWatchlist();
//   setupEventListeners();
//   detectAndFillIP();

//   // 

//   // ── Auto-detect visitor IP ─────────────────────────────────────────────────
//   async function detectAndFillIP() {
//     try {
//       const res  = await fetch("https://api.ipify.org?format=json");
//       const data = await res.json();
//       if (data.ip && isValidIP(data.ip)) {
//         ipInput.value = data.ip;
//         ipInput.style.color = "var(--accent)";
//         setTimeout(() => { ipInput.style.color = ""; }, 2000);
//       }
//     } catch (_) {}
//   }

//   // ── Extra UI ───────────────────────────────────────────────────────────────
//   function injectExtraUI() {
//     const headerRight = document.querySelector(".header-right");
//     if (headerRight) {
//       const toggle = document.createElement("button");
//       toggle.className = "btn btn-ghost";
//       toggle.id = "themeToggle";
//       toggle.textContent = "☀ LIGHT";
//       toggle.style.cssText = "padding:6px 12px;font-size:11px;";
//       toggle.addEventListener("click", toggleTheme);
//       headerRight.prepend(toggle);
//     }

//     const searchSection = document.querySelector(".search-section");
//     if (searchSection) {
//       const bulk = document.createElement("div");
//       bulk.id = "bulkSection";
//       bulk.style.cssText = "margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;";
//       bulk.innerHTML = `
//         <label style="font-size:10px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;">Bulk:</label>
//         <input type="file" id="csvUpload" accept=".csv,.txt" style="display:none">
//         <button class="btn btn-ghost" id="csvBtn"    style="padding:8px 14px;font-size:11px;">↑ UPLOAD CSV</button>
//         <button class="btn btn-ghost" id="exportBtn" style="padding:8px 14px;font-size:11px;">↓ EXPORT LOG</button>
//         <span id="bulkStatus" style="font-size:11px;color:var(--text2);"></span>`;
//       searchSection.appendChild(bulk);
//     }

//     const mainGrid = document.querySelector(".main-grid");
//     if (mainGrid) {
//       const row = document.createElement("div");
//       row.id = "mapWatchRow";
//       row.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:24px;";

//       const mapWrap = document.createElement("div");
//       mapWrap.id = "mapSection";
//       mapWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;";
//       mapWrap.innerHTML = `
//         <div class="panel-header">
//           <div class="panel-title">// Geo Map</div>
//           <div id="mapLabel" style="font-size:11px;color:var(--text3);">Score an IP to see location</div>
//         </div>
//         <div id="mapContainer" style="height:320px;background:var(--bg2);display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;">Loading map…</div>`;

//       const watchWrap = document.createElement("div");
//       watchWrap.id = "watchlistSection";
//       watchWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;";
//       watchWrap.innerHTML = `
//         <div class="panel-header" style="justify-content:space-between;">
//           <div class="panel-title">// Watchlist</div>
//           <div style="display:flex;gap:8px;align-items:center;">
//             <span id="watchlistCount" style="font-size:11px;color:var(--text3);">0 IPs</span>
//             <button id="addWatchBtn" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">+ WATCH</button>
//             <button id="pollBtn"     class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">↻ POLL</button>
//           </div>
//         </div>
//         <div id="watchlistBody" style="flex:1;overflow-y:auto;max-height:260px;">
//           <div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No IPs being watched</div>
//         </div>
//         <div id="monitorStatus" style="padding:8px 16px;font-size:10px;color:var(--text3);border-top:1px solid var(--border);"></div>`;

//       row.appendChild(mapWrap);
//       row.appendChild(watchWrap);
//       mainGrid.after(row);

//       const style = document.createElement("style");
//       style.textContent = "@media(max-width:768px){#mapWatchRow{grid-template-columns:1fr!important}}";
//       document.head.appendChild(style);
//     }
//   }

//   // - Inject audit controls
//   function injectAuditControls() {
//   const auditPanel = document.querySelector(".audit-panel");
//   if (!auditPanel) return;
 
//   const controls = document.createElement("div");
//   controls.id = "auditControls";
//   controls.style.cssText = "padding:12px 16px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:10px;";
//   controls.innerHTML = `
//     <!-- Search bar -->
//     <div style="position:relative;">
//       <input id="auditSearch" type="text" placeholder="Search IP, country, ISP…"
//         maxlength="100"
//         style="width:100%;padding:8px 36px 8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;
//                color:var(--text);font-family:inherit;font-size:12px;outline:none;">
//       <button id="auditSearchClear" title="Clear search"
//         style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;display:none;">✕</button>
//     </div>
 
//     <!-- Risk filter chips -->
//     <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
//       <span style="font-size:10px;color:var(--text3);letter-spacing:1px;">RISK:</span>
//       ${["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(r => `
//         <button class="audit-risk-chip" data-risk="${r === "ALL" ? "" : r}"
//           style="padding:3px 10px;border-radius:12px;border:1px solid ${r==="ALL"?"var(--accent)":"var(--border)"};
//                  background:${r==="ALL"?"rgba(0,217,255,0.1)":"transparent"};
//                  color:${r==="ALL"?"var(--accent)":"var(--text3)"};
//                  font-size:10px;font-weight:600;cursor:pointer;letter-spacing:0.5px;font-family:inherit;">
//           ${r}
//         </button>`).join("")}
//     </div>
 
//     <!-- Score range + toggles row -->
//     <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
//       <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text3);">
//         <span>Score:</span>
//         <input id="auditMinScore" type="number" min="0" max="100" value="0" placeholder="0"
//           style="width:44px;padding:3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
//         <span>–</span>
//         <input id="auditMaxScore" type="number" min="0" max="100" value="100" placeholder="100"
//           style="width:44px;padding:3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
//       </div>
 
//       <div style="display:flex;gap:6px;">
//         <button class="audit-toggle" data-key="proxy" data-val="null"
//           style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
//           PROXY
//         </button>
//         <button class="audit-toggle" data-key="tor" data-val="null"
//           style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
//           TOR
//         </button>
//         <button class="audit-toggle" data-key="datacenter" data-val="null"
//           style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit;">
//           DC
//         </button>
//       </div>
 
//       <div style="margin-left:auto;display:flex;gap:6px;align-items:center;">
//         <select id="auditSort"
//           style="padding:3px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;cursor:pointer;">
//           <option value="date_desc">Newest first</option>
//           <option value="date_asc">Oldest first</option>
//           <option value="score_desc">Highest score</option>
//           <option value="score_asc">Lowest score</option>
//         </select>
//         <button id="auditLoadDB" class="btn btn-ghost"
//           style="padding:3px 10px;font-size:10px;letter-spacing:1px;" title="Load full history from database">
//           ↓ DB
//         </button>
//         <button id="auditReset" class="btn btn-ghost"
//           style="padding:3px 10px;font-size:10px;letter-spacing:1px;">
//           RESET
//         </button>
//       </div>
//     </div>
 
//     <!-- Result count -->
//     <div id="auditFilterStatus" style="font-size:10px;color:var(--text3);"></div>`;
 
//   // Insert before audit list
//   const auditListEl = document.getElementById("auditList");
//   if (auditListEl) auditPanel.insertBefore(controls, auditListEl);
 
//   // Wire up events
//   let searchTimer;
//   document.getElementById("auditSearch")?.addEventListener("input", e => {
//     const clearBtn = document.getElementById("auditSearchClear");
//     if (clearBtn) clearBtn.style.display = e.target.value ? "block" : "none";
//     clearTimeout(searchTimer);
//     searchTimer = setTimeout(() => { auditFilters.q = e.target.value.trim(); auditPage = 0; renderAudit(); }, 300);
//   });
 
//   document.getElementById("auditSearchClear")?.addEventListener("click", () => {
//     const input = document.getElementById("auditSearch");
//     if (input) { input.value = ""; document.getElementById("auditSearchClear").style.display = "none"; }
//     auditFilters.q = ""; auditPage = 0; renderAudit();
//   });
 
//   document.querySelectorAll(".audit-risk-chip").forEach(chip => {
//     chip.addEventListener("click", () => {
//       document.querySelectorAll(".audit-risk-chip").forEach(c => {
//         c.style.borderColor = "var(--border)"; c.style.background = "transparent"; c.style.color = "var(--text3)";
//       });
//       chip.style.borderColor = "var(--accent)"; chip.style.background = "rgba(0,217,255,0.1)"; chip.style.color = "var(--accent)";
//       auditFilters.risk = chip.dataset.risk; auditPage = 0; renderAudit();
//     });
//   });
 
//   document.getElementById("auditMinScore")?.addEventListener("change", e => {
//     auditFilters.minScore = parseInt(e.target.value) || 0; auditPage = 0; renderAudit();
//   });
//   document.getElementById("auditMaxScore")?.addEventListener("change", e => {
//     auditFilters.maxScore = parseInt(e.target.value) ?? 100; auditPage = 0; renderAudit();
//   });
 
//   document.querySelectorAll(".audit-toggle").forEach(btn => {
//     btn.addEventListener("click", () => {
//       const key = btn.dataset.key;
//       const cur = auditFilters[key];
//       // Cycle: null → true → false → null
//       auditFilters[key] = cur === null ? true : cur === true ? false : null;
//       btn.style.background   = auditFilters[key] === true  ? "rgba(0,232,124,0.15)" :
//                                auditFilters[key] === false ? "rgba(255,51,85,0.15)" : "transparent";
//       btn.style.borderColor  = auditFilters[key] === true  ? "var(--low)" :
//                                auditFilters[key] === false ? "var(--critical)" : "var(--border)";
//       btn.style.color        = auditFilters[key] === true  ? "var(--low)" :
//                                auditFilters[key] === false ? "var(--critical)" : "var(--text3)";
//       auditPage = 0; renderAudit();
//     });
//   });
 
//   document.getElementById("auditSort")?.addEventListener("change", e => {
//     auditFilters.sort = e.target.value; auditPage = 0; renderAudit();
//   });
 
//   document.getElementById("auditLoadDB")?.addEventListener("click", async () => {
//     usingDB = true; auditPage = 0;
//     await fetchAndRenderFromDB();
//   });
 
//   document.getElementById("auditReset")?.addEventListener("click", () => {
//     auditFilters = { q:"", risk:"", minScore:0, maxScore:100, proxy:null, tor:null, datacenter:null, sort:"date_desc" };
//     usingDB      = false;
//     auditPage    = 0;
//     // Reset UI
//     const input = document.getElementById("auditSearch");
//     if (input) input.value = "";
//     document.querySelectorAll(".audit-risk-chip").forEach((c, i) => {
//       c.style.borderColor = i===0?"var(--accent)":"var(--border)";
//       c.style.background  = i===0?"rgba(0,217,255,0.1)":"transparent";
//       c.style.color       = i===0?"var(--accent)":"var(--text3)";
//     });
//     document.querySelectorAll(".audit-toggle").forEach(b => {
//       b.style.background = "transparent"; b.style.borderColor = "var(--border)"; b.style.color = "var(--text3)";
//     });
//     const minEl = document.getElementById("auditMinScore"); if (minEl) minEl.value = "0";
//     const maxEl = document.getElementById("auditMaxScore"); if (maxEl) maxEl.value = "100";
//     const sort  = document.getElementById("auditSort");     if (sort)  sort.value  = "date_desc";
//     renderAudit();
//   });
// }
 
// // ── Filter in-memory entries ───────────────────────────────────────────────────
// function applyFilters(entries) {
//   return entries.filter(e => {
//     const f = auditFilters;
//     if (f.q) {
//       const q = f.q.toLowerCase();
//       if (!e.ip?.toLowerCase().includes(q) &&
//           !e.geo?.country?.toLowerCase().includes(q) &&
//           !e.network?.isp?.toLowerCase().includes(q)) return false;
//     }
//     if (f.risk       && e.riskLevel !== f.risk)                         return false;
//     if (f.minScore != null && (e.score??0) < f.minScore)                return false;
//     if (f.maxScore != null && (e.score??0) > f.maxScore)                return false;
//     if (f.proxy    != null && !!e.intelligence?.isProxy !== f.proxy)     return false;
//     if (f.tor      != null && !!e.intelligence?.isTor   !== f.tor)       return false;
//     if (f.datacenter != null && !!e.intelligence?.isDatacenter !== f.datacenter) return false;
//     return true;
//   });
// }
 
// function sortEntries(entries) {
//   return [...entries].sort((a, b) => {
//     switch (auditFilters.sort) {
//       case "score_desc": return (b.score??0) - (a.score??0);
//       case "score_asc":  return (a.score??0) - (b.score??0);
//       case "date_asc":   return new Date(a.meta?.scoredAt||0) - new Date(b.meta?.scoredAt||0);
//       default:           return new Date(b.meta?.scoredAt||0) - new Date(a.meta?.scoredAt||0);
//     }
//   });
// }
 
// // ── Fetch from DB via API ─────────────────────────────────────────────────────
// async function fetchAndRenderFromDB() {
//   const params = new URLSearchParams({
//     limit:  AUDIT_PAGE_SIZE,
//     offset: auditPage * AUDIT_PAGE_SIZE,
//     sort:   auditFilters.sort
//   });
//   if (auditFilters.q)              params.set("q",          auditFilters.q);
//   if (auditFilters.risk)           params.set("risk",       auditFilters.risk);
//   if (auditFilters.minScore > 0)   params.set("minScore",   auditFilters.minScore);
//   if (auditFilters.maxScore < 100) params.set("maxScore",   auditFilters.maxScore);
//   if (auditFilters.proxy    != null) params.set("proxy",    auditFilters.proxy);
//   if (auditFilters.tor      != null) params.set("tor",      auditFilters.tor);
//   if (auditFilters.datacenter != null) params.set("datacenter", auditFilters.datacenter);
 
//   try {
//     const res  = await fetch(`${API}/audit/search?${params}`, { headers: { "x-api-key": API_KEY } });
//     const data = await res.json();
//     if (!res.ok) throw new Error(data.error);
//     auditTotal = data.total;
//     renderAuditEntries(data.entries, data.total);
//   } catch (err) {
//     setBulkStatus(`Audit DB error: ${err.message}`);
//   }
// }
 
// // ── Main renderAudit ──────────────────────────────────────────────────────────
// function addAuditEntry(d) {
//   auditEntries.unshift(d);
//   if (auditEntries.length > 200) auditEntries.pop();
//   if (!usingDB) renderAudit();
// }
 
// function renderAudit() {
//   if (usingDB) { fetchAndRenderFromDB(); return; }
 
//   const filtered = sortEntries(applyFilters(auditEntries));
//   auditTotal     = filtered.length;
//   const page     = filtered.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);
//   renderAuditEntries(page, filtered.length);
// }
 
// function renderAuditEntries(entries, total) {
//   auditCount.textContent = `${total} ${total===1?"entry":"entries"}`;
 
//   const status = document.getElementById("auditFilterStatus");
//   const hasFilter = auditFilters.q || auditFilters.risk || auditFilters.minScore > 0 ||
//                     auditFilters.maxScore < 100 || auditFilters.proxy != null ||
//                     auditFilters.tor != null || auditFilters.datacenter != null;
 
//   if (status) {
//     status.textContent = hasFilter
//       ? `Showing ${Math.min(entries.length, total)} of ${total} matching entries${usingDB ? " (DB)" : " (session)"}`
//       : usingDB ? `Full database history — ${total} total entries` : "";
//   }
 
//   if (!entries.length) {
//     auditList.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
//       ${hasFilter ? "No entries match your filters" : "No queries yet"}
//     </div>`;
//     return;
//   }
 
//   auditList.innerHTML = entries.map(e => {
//     // Handle both in-memory format and DB row format
//     const ip        = e.ip;
//     const score     = e.score       ?? 0;
//     const riskLevel = e.riskLevel   || e.risk_level || "LOW";
//     const scoredAt  = e.meta?.scoredAt || (e.scored_at ? new Date(e.scored_at) : new Date());
//     const f = [
//       (e.threatFeeds?.feodo || e.is_feodo)           && "F",
//       (e.threatFeeds?.spamhaus || e.is_spamhaus)     && "S",
//       (e.threatFeeds?.emergingThreats || e.is_et)    && "E",
//       (e.threatFeeds?.otx?.pulseCount > 0)           && "O"
//     ].filter(Boolean).join("");
 
//     return `<div class="audit-item" data-ip="${escHtml(ip)}">
//       <span class="audit-ip">${escHtml(ip)}</span>
//       ${f ? `<span style="font-size:9px;color:#ff3355;font-weight:700;">[${f}]</span>` : ""}
//       <span class="audit-badge ${riskLevel}">${riskLevel}</span>
//       <span class="audit-score ${riskLevel}">${score}</span>
//       <span class="audit-ts">${fmtTime(new Date(scoredAt))}</span>
//     </div>`;
//   }).join("");
 
//   // Pagination controls
//   const totalPages = Math.ceil(total / AUDIT_PAGE_SIZE);
//   if (totalPages > 1) {
//     const nav = document.createElement("div");
//     nav.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:8px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text3);";
//     nav.innerHTML = `
//       <button id="auditPrev" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage===0?"disabled":""}>← Prev</button>
//       <span>Page ${auditPage+1} of ${totalPages}</span>
//       <button id="auditNext" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage>=totalPages-1?"disabled":""}>Next →</button>`;
//     auditList.appendChild(nav);
 
//     document.getElementById("auditPrev")?.addEventListener("click", () => { auditPage--; renderAudit(); });
//     document.getElementById("auditNext")?.addEventListener("click", () => { auditPage++; renderAudit(); });
//   }
 
//   auditList.querySelectorAll(".audit-item").forEach(item => {
//     item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
//   });
// }

//   // ── Map ────────────────────────────────────────────────────────────────────
//   function initMap() {
//     const container = document.getElementById("mapContainer");
//     if (!container || typeof L === "undefined") return;
//     container.innerHTML = "";
//     container.style.cssText = "height:320px;";
//     map = L.map("mapContainer", { zoomControl: true, attributionControl: false });
//     L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
//     map.setView([20, 0], 2);
//   }

//   function updateMap(geo, ip, riskLevel) {
//     if (!map || geo.lat == null || geo.lon == null) return;
//     const color = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c" }[riskLevel] || "#00d9ff";
//     const icon  = L.divIcon({
//       className: "", iconSize: [14,14], iconAnchor: [7,7],
//       html: `<div style="width:14px;height:14px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 0 8px ${color};"></div>`
//     });
//     if (mapMarker) map.removeLayer(mapMarker);
//     mapMarker = L.marker([geo.lat, geo.lon], { icon })
//       .addTo(map)
//       .bindPopup(`<b style="font-family:monospace">${ip}</b><br>${geo.city||""}, ${geo.country||""}<br>Risk: ${riskLevel}`)
//       .openPopup();
//     map.flyTo([geo.lat, geo.lon], 6, { duration: 1.2 });
//     const label = document.getElementById("mapLabel");
//     if (label) label.textContent = `${geo.city||"—"}, ${geo.country||"—"}`;
//   }

//   // ── Events ─────────────────────────────────────────────────────────────────
//   function setupEventListeners() {
//     scoreBtn.addEventListener("click", scoreIP);
//     clearBtn.addEventListener("click", clearPanel);
//     ipInput.addEventListener("keydown", e => { if (e.key === "Enter") scoreIP(); });

//     document.querySelectorAll(".quick-chip").forEach(chip => {
//       chip.addEventListener("click", () => { ipInput.value = chip.dataset.ip; scoreIP(); });
//     });

//     document.addEventListener("click", e => {
//       if (e.target.id === "csvBtn")      document.getElementById("csvUpload").click();
//       if (e.target.id === "exportBtn")   exportLog();
//       if (e.target.id === "addWatchBtn") addCurrentToWatchlist();
//       if (e.target.id === "pollBtn")     triggerPoll();
//     });

//     document.addEventListener("change", e => {
//       if (e.target.id === "csvUpload") handleCSVUpload(e.target.files[0]);
//     });

//     // Single unified click handler on resultBody — no inline onclick needed
//     resultBody.addEventListener("click", e => {
//       if (e.target.id === "watchCurrentBtn") {
//         addCurrentToWatchlist();
//         return;
//       }
//       const tabBtn = e.target.closest(".tab-btn");
//       if (tabBtn) {
//         const tab = tabBtn.dataset.tab;
//         const ip  = tabBtn.dataset.ip;
//         ["Signals","Network","WHOIS"].forEach(t => {
//           const content = document.getElementById(`tabContent-${t}`);
//           const btn     = resultBody.querySelector(`.tab-btn[data-tab="${t}"]`);
//           if (content) content.style.display = t === tab ? "block" : "none";
//           if (btn) {
//             btn.style.borderBottomColor = t === tab ? "var(--accent)" : "transparent";
//             btn.style.color             = t === tab ? "var(--accent)" : "var(--text3)";
//           }
//         });
//         if (tab === "WHOIS" && ip) {
//           const panel = document.getElementById("whoisPanel");
//           if (panel && panel.dataset.loaded === "false") {
//             panel.dataset.loaded = "true";
//             loadWhois(ip);
//           }
//         }
//       }
//     });
//   }

//   // ── Theme ──────────────────────────────────────────────────────────────────
//   function toggleTheme() {
//     isDark = !isDark;
//     const root = document.documentElement;
//     const btn  = document.getElementById("themeToggle");
//     if (isDark) {
//       ["--bg","--bg1","--bg2","--bg3","--text","--text2","--text3","--border","--border2"].forEach(v => root.style.removeProperty(v));
//       if (btn) btn.textContent = "☀ LIGHT";
//     } else {
//       root.style.setProperty("--bg","#f0f4f8"); root.style.setProperty("--bg1","#ffffff");
//       root.style.setProperty("--bg2","#e8edf2"); root.style.setProperty("--bg3","#dce3ea");
//       root.style.setProperty("--text","#1a2332"); root.style.setProperty("--text2","#4a6278");
//       root.style.setProperty("--text3","#7a95a8"); root.style.setProperty("--border","#c8d8e4");
//       root.style.setProperty("--border2","#b0c4d4");
//       if (btn) btn.textContent = "☾ DARK";
//     }
//     if (map) {
//       map.eachLayer(l => { if (l._url) map.removeLayer(l); });
//       L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
//     }
//   }

//   // ── Score ──────────────────────────────────────────────────────────────────
//   async function scoreIP() {
//     const ip = ipInput.value.trim();
//     if (!ip) return;
//     if (!isValidIP(ip)) { showError("Invalid IP address format."); return; }
//     setLoading(true);
//     try {
//       const res  = await fetch(`${API}/score/${encodeURIComponent(ip)}`, { headers: { "x-api-key": API_KEY } });
//       const data = await res.json();
//       if (!res.ok) throw new Error(data.error || "Scoring failed");
//       currentIP  = ip;
//       lastResult = data;
//       renderResult(data);
//       addAuditEntry(data);
//       updateStats(data.riskLevel);
//       updateMap(data.geo || {}, data.ip, data.riskLevel);
//     } catch (err) {
//       showError(err.message || "Service temporarily unavailable.");
//     } finally {
//       setLoading(false);
//     }
//   }

//   // ── Watchlist ──────────────────────────────────────────────────────────────
//   async function loadWatchlist() {
//     try {
//       const res  = await fetch(`${API}/watchlist`, { headers: { "x-api-key": API_KEY } });
//       if (!res.ok) return;
//       const data = await res.json();
//       renderWatchlist(data.watchlist || [], data.monitor);
//     } catch (_) {}
//   }

//   async function addCurrentToWatchlist() {
//     const ip = currentIP || ipInput.value.trim();
//     if (!ip || !isValidIP(ip)) { setBulkStatus("Score an IP first, then click + WATCH"); return; }
//     const label     = prompt(`Label for ${ip}:`, ip) ?? ip;
//     const threshold = parseInt(prompt("Alert threshold (0-100):", "30") || "30");
//     try {
//       const res  = await fetch(`${API}/watchlist`, {
//         method: "POST",
//         headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
//         body: JSON.stringify({ ip, label, threshold, alertOnChange: true })
//       });
//       const data = await res.json();
//       if (!res.ok) throw new Error(data.error);
//       setBulkStatus(`✓ ${ip} added to watchlist`);
//       loadWatchlist();
//     } catch (err) { setBulkStatus(`Error: ${err.message}`); }
//   }

//   async function removeFromWatchlist(ip) {
//     try {
//       await fetch(`${API}/watchlist/${encodeURIComponent(ip)}`, {
//         method: "DELETE", headers: { "x-api-key": API_KEY }
//       });
//       loadWatchlist();
//     } catch (err) { setBulkStatus(`Error: ${err.message}`); }
//   }

//   async function triggerPoll() {
//     const btn = document.getElementById("pollBtn");
//     if (btn) { btn.disabled = true; btn.textContent = "↻ POLLING…"; }
//     try {
//       await fetch(`${API}/watchlist/poll`, { method: "POST", headers: { "x-api-key": API_KEY } });
//       setBulkStatus("Poll triggered — watchlist updating…");
//       setTimeout(loadWatchlist, 5000);
//     } finally {
//       if (btn) { btn.disabled = false; btn.textContent = "↻ POLL"; }
//     }
//   }

//   function renderWatchlist(items, monitor) {
//     const count = document.getElementById("watchlistCount");
//     const body  = document.getElementById("watchlistBody");
//     const mStat = document.getElementById("monitorStatus");

//     if (count) count.textContent = `${items.length} IP${items.length !== 1 ? "s" : ""}`;
//     if (monitor && mStat) mStat.textContent = `Monitor: ${monitor.active ? "● ACTIVE" : "○ INACTIVE"} · every ${monitor.intervalMins}min`;

//     if (!items.length) {
//       if (body) body.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">No IPs being watched.<br>Score an IP then click <strong>+ WATCH</strong>.</div>`;
//       return;
//     }

//     if (!body) return;

//     body.innerHTML = items.map(item => {
//       const clr = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c", UNKNOWN:"#6a8fa8" }[item.last_risk] || "#6a8fa8";
//       const chk = item.last_checked ? new Date(item.last_checked).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}) : "never";
//       return `
//         <div class="watchlist-item" data-ip="${escHtml(item.ip)}"
//           style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;">
//           <div style="flex:1;min-width:0;">
//             <div style="font-size:12px;font-weight:600;color:var(--text);font-family:monospace;">${escHtml(item.ip)}</div>
//             <div style="font-size:10px;color:var(--text3);">${item.label !== item.ip ? escHtml(item.label) + " · " : ""}checked ${chk}</div>
//             <div style="height:2px;background:var(--bg3);border-radius:2px;margin-top:4px;">
//               <div style="height:2px;width:${item.last_score}%;background:${clr};border-radius:2px;"></div>
//             </div>
//           </div>
//           <div style="text-align:right;flex-shrink:0;">
//             <div style="font-size:16px;font-weight:700;color:${clr};">${item.last_score}</div>
//             <div style="font-size:9px;font-weight:700;color:${clr};letter-spacing:1px;">${item.last_risk}</div>
//           </div>
//           <div style="font-size:10px;color:var(--text3);">⚑${item.threshold}</div>
//           <button class="watchlist-remove" data-ip="${escHtml(item.ip)}"
//             style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:14px;padding:4px;" title="Remove">✕</button>
//         </div>`;
//     }).join("");

//     body.querySelectorAll(".watchlist-item").forEach(row => {
//       row.addEventListener("click", () => { ipInput.value = row.dataset.ip; scoreIP(); });
//     });
//     body.querySelectorAll(".watchlist-remove").forEach(btn => {
//       btn.addEventListener("click", e => { e.stopPropagation(); removeFromWatchlist(btn.dataset.ip); });
//     });
//   }

//   // ── WHOIS ──────────────────────────────────────────────────────────────────
//   async function loadWhois(ip) {
//     const panel = document.getElementById("whoisPanel");
//     if (!panel) return;
//     panel.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text2);font-size:12px;">Loading WHOIS data for ${escHtml(ip)}…</div>`;
//     try {
//       const res  = await fetch(`${API}/whois/${encodeURIComponent(ip)}`, { headers: { "x-api-key": API_KEY } });
//       const data = await res.json();
//       if (!res.ok) throw new Error(data.error || "WHOIS lookup failed");
//       renderWhois(data.whois, data.signals || [], panel);
//     } catch (err) {
//       panel.dataset.loaded = "false";
//       panel.innerHTML = `<div style="padding:16px;color:var(--critical);font-size:12px;">⚠ ${escHtml(err.message)}<br><small style="color:var(--text3);">Click WHOIS tab to retry</small></div>`;
//     }
//   }

//   function renderWhois(w, signals, panel) {
//     if (!w) {
//       panel.innerHTML = `<div style="padding:16px;color:var(--text3);font-size:12px;">No WHOIS data available for this IP</div>`;
//       return;
//     }
//     const ageBadge = w.agedays !== null
//       ? `<span style="font-size:10px;padding:2px 8px;border-radius:3px;margin-left:8px;
//            background:${w.agedays < 30 ? "rgba(255,51,85,0.15)" : w.agedays < 90 ? "rgba(255,119,0,0.15)" : "rgba(0,232,124,0.1)"};
//            color:${w.agedays < 30 ? "#ff3355" : w.agedays < 90 ? "#ff7700" : "#00e87c"};">
//            ${w.agedays < 1 ? "< 1 day old" : w.agedays + " days old"}
//          </span>` : "";

//     panel.innerHTML = `
//       ${signals.length ? `
//         <div style="padding:12px 16px;border-bottom:1px solid var(--border);">
//           ${signals.map(s => `
//             <div class="signal-item ${s.severity}" style="margin-bottom:6px;">
//               <span class="sig-cat">${escHtml(s.category)}</span>
//               <span class="sig-detail">${escHtml(s.detail)}</span>
//               <span class="sig-sev">${s.severity.toUpperCase()}</span>
//             </div>`).join("")}
//         </div>` : ""}
//       <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px;">
//         <div class="detail-card">
//           <div class="detail-card-title">// Registration</div>
//           ${kv("Network",  w.network  || "—")}
//           ${kv("Handle",   w.handle   || "—")}
//           ${kv("CIDR",     w.cidr     || "—")}
//           ${kv("Type",     w.type     || "—")}
//           <div class="kv">
//             <span class="kv-key">Registered</span>
//             <span class="kv-val">${w.registered && w.registered !== "—" ? new Date(w.registered).toLocaleDateString() : "—"}${ageBadge}</span>
//           </div>
//           ${kv("Last Changed", w.lastChanged && w.lastChanged !== "—" ? new Date(w.lastChanged).toLocaleDateString() : "—")}
//         </div>
//         <div class="detail-card">
//           <div class="detail-card-title">// Organization</div>
//           ${kv("Org Name",    w.orgName    || "—")}
//           ${kv("Org ID",      w.orgId      || "—")}
//           ${kv("Country",     w.country    || "—")}
//           ${kv("Abuse Email", w.abuseEmail || "—")}
//           ${kv("Registrar",   w.registrar  || "—")}
//         </div>
//       </div>
//       ${w.remarks?.length ? `
//         <div style="padding:0 16px 16px;">
//           <div class="detail-card">
//             <div class="detail-card-title">// Remarks</div>
//             ${w.remarks.map(r => `<div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${escHtml(r)}</div>`).join("")}
//           </div>
//         </div>` : ""}`;
//   }

//   // ── Render result ──────────────────────────────────────────────────────────
//   function renderResult(d) {
//     const score     = d.score        ?? 0;
//     const riskLevel = d.riskLevel    ?? "LOW";
//     const action    = d.action       ?? "ALLOW";
//     const geo       = d.geo          ?? {};
//     const network   = d.network      ?? {};
//     const intel     = d.intelligence ?? {};
//     const meta      = d.meta         ?? {};
//     const signals   = d.signals      || buildFallbackSignals(d);

//     const circ   = 2 * Math.PI * 52;
//     const offset = circ - (score / 100) * circ;
//     const stroke = { CRITICAL:"#ff3355", HIGH:"#ff7700", MEDIUM:"#ffcc00", LOW:"#00e87c" }[riskLevel] || "#00e87c";

//     procTime.textContent = meta.processingMs ? `${meta.processingMs}ms${meta.cached ? " · cached" : ""}` : "";

//     resultBody.innerHTML = `
//       <div class="score-header">
//         <div class="score-ring-wrap">
//           <svg width="120" height="120" viewBox="0 0 120 120">
//             <circle class="score-bg" cx="60" cy="60" r="52"/>
//             <circle class="score-fill" cx="60" cy="60" r="52"
//               stroke="${stroke}" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/>
//           </svg>
//           <div class="score-center">
//             <div class="score-num" style="color:${stroke}">${score}</div>
//             <div class="score-max">/100</div>
//           </div>
//         </div>
//         <div class="score-meta">
//           <div class="score-ip">${escHtml(d.ip)}</div>
//           <div class="risk-badge ${riskLevel}"><span>${riskIcon(riskLevel)}</span><span>${riskLevel}</span></div>
//           <div class="action-badge ${action}">RECOMMENDED ACTION: <span class="action-val">${action}</span></div>
//           ${d.scoreBoost > 0 ? `<div style="font-size:10px;color:var(--text3);margin-top:6px;">Base: ${d.baseScore} + Feed boost: +${d.scoreBoost}</div>` : ""}
//           ${intel.shodanTags?.length ? `<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
//             ${intel.shodanTags.map(t => `<span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,217,255,0.1);color:var(--accent);border:1px solid rgba(0,217,255,0.3);">${escHtml(t)}</span>`).join("")}
//           </div>` : ""}
//           <div style="margin-top:10px;">
//             <button id="watchCurrentBtn" class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">+ Watch</button>
//           </div>
//         </div>
//       </div>

//       ${threatFeedBadges(d.threatFeeds)}

//       <div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px;">
//         ${["Signals","Network","WHOIS"].map((tab, i) => `
//           <button class="tab-btn" data-tab="${tab}" data-ip="${escHtml(d.ip)}"
//             style="padding:8px 16px;background:none;border:none;border-bottom:2px solid ${i===0?"var(--accent)":"transparent"};
//                    color:${i===0?"var(--accent)":"var(--text3)"};cursor:pointer;font-family:inherit;font-size:11px;letter-spacing:1px;text-transform:uppercase;">
//             ${tab}
//           </button>`).join("")}
//       </div>

//       <div id="tabContent-Signals">
//         <div class="signal-list">
//           ${signals.map(s => `
//             <div class="signal-item ${s.severity}">
//               <span class="sig-cat">${escHtml(s.category)}</span>
//               <span class="sig-detail">${escHtml(s.detail)}</span>
//               <span class="sig-sev">${s.severity.toUpperCase()}</span>
//             </div>`).join("")}
//         </div>
//       </div>

//       <div id="tabContent-Network" style="display:none;">
//         <div class="detail-grid">
//           <div class="detail-card">
//             <div class="detail-card-title">// Geolocation</div>
//             ${kv("Country",  geo.country  || "—")}
//             ${kv("Region",   geo.region   || "—")}
//             ${kv("City",     geo.city     || "—")}
//             ${kv("Timezone", geo.timezone || "—")}
//             ${kv("Lat / Lon", geo.lat != null ? `${geo.lat}, ${geo.lon}` : "N/A (private)")}
//           </div>
//           <div class="detail-card">
//             <div class="detail-card-title">// Network</div>
//             ${kv("ISP",        network.isp  || "—")}
//             ${kv("ASN",        network.asn  || "—")}
//             ${kv("Type",       network.type || "—")}
//             ${kv("Datacenter", intel.isDatacenter ? "Yes" : "No")}
//             ${kv("Proxy",      intel.isProxy ? "⚠ Detected" : "No")}
//             ${kv("Tor",        intel.isTor   ? "⚠ Exit Node" : "No")}
//             ${intel.openPorts?.length ? kv("Open Ports", intel.openPorts.slice(0,6).join(", ")) : ""}
//             ${intel.vulns?.length     ? kv("CVEs", `${intel.vulns.length} found`) : ""}
//           </div>
//         </div>
//         ${intel.virusTotal ? `
//           <div class="detail-card" style="margin-top:16px;">
//             <div class="detail-card-title">// VirusTotal</div>
//             <div style="display:flex;gap:16px;margin-top:4px;">
//               ${vtBar("Malicious",  intel.virusTotal.malicious,  intel.virusTotal.total, "#ff3355")}
//               ${vtBar("Suspicious", intel.virusTotal.suspicious, intel.virusTotal.total, "#ff7700")}
//               ${vtBar("Harmless",   intel.virusTotal.harmless,   intel.virusTotal.total, "#00e87c")}
//             </div>
//           </div>` : ""}
//         ${d.threatFeeds?.otx?.pulseNames?.length ? `
//           <div class="detail-card" style="margin-top:16px;">
//             <div class="detail-card-title">// OTX Pulses</div>
//             ${d.threatFeeds.otx.pulseNames.map(n => `<div class="kv"><span class="kv-key">Pulse</span><span class="kv-val">${escHtml(n)}</span></div>`).join("")}
//           </div>` : ""}
//       </div>

//       <div id="tabContent-WHOIS" style="display:none;">
//         <div id="whoisPanel" data-loaded="false">
//           <div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
//             Click the WHOIS tab above to load deep registration data
//           </div>
//         </div>
//       </div>`;
//   }

//   // ── Helpers ────────────────────────────────────────────────────────────────
//   function threatFeedBadges(tf) {
//     if (!tf) return "";
//     const badges = [];
//     if (tf.feodo)           badges.push({ label:"FEODO C2",      color:"#ff3355", bg:"rgba(255,51,85,0.15)",  tip:"Active C2 botnet — Feodo Tracker" });
//     if (tf.spamhaus)        badges.push({ label:"SPAMHAUS DROP", color:"#ff3355", bg:"rgba(255,51,85,0.15)",  tip:"Do not route or peer — Spamhaus" });
//     if (tf.emergingThreats) badges.push({ label:"ET INTEL",      color:"#ff7700", bg:"rgba(255,119,0,0.15)", tip:"Emerging Threats compromised list" });
//     if (tf.otx?.pulseCount > 0) badges.push({ label:`OTX ×${tf.otx.pulseCount}`, color:"#ffcc00", bg:"rgba(255,204,0,0.15)", tip:`${tf.otx.pulseCount} OTX pulse(s)` });
//     if (!badges.length) return `<div style="font-size:11px;color:var(--low);margin-bottom:12px;">✓ Not listed on any threat feed</div>`;
//     return `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center;">
//       <span style="font-size:10px;color:var(--text3);letter-spacing:2px;">THREAT FEEDS:</span>
//       ${badges.map(b => `<span title="${escHtml(b.tip)}" style="font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:4px;background:${b.bg};color:${b.color};border:1px solid ${b.color};cursor:help;">${b.label}</span>`).join("")}
//     </div>`;
//   }

//   function vtBar(label, count, total, color) {
//     const pct = total > 0 ? Math.round((count/total)*100) : 0;
//     return `<div style="flex:1;text-align:center;">
//       <div style="font-size:10px;color:var(--text3);margin-bottom:4px;">${label}</div>
//       <div style="font-size:18px;font-weight:700;color:${color};">${count}</div>
//       <div style="height:3px;background:var(--bg3);border-radius:2px;margin-top:4px;">
//         <div style="height:3px;width:${pct}%;background:${color};border-radius:2px;transition:width 0.5s;"></div>
//       </div>
//     </div>`;
//   }

//   function buildFallbackSignals(d) {
//     const score = d.score ?? 0;
//     const intel = d.intelligence ?? {};
//     const sigs  = [];
//     sigs.push({ category:"ABUSE",    detail:`Confidence score: ${score}/100`, severity: score>80?"critical":score>60?"high":score>30?"medium":"low" });
//     if (intel.isProxy)      sigs.push({ category:"PROXY",   detail:"Proxy detected",        severity:"high" });
//     if (intel.isTor)        sigs.push({ category:"TOR",     detail:"Tor exit node",          severity:"critical" });
//     if (intel.isDatacenter) sigs.push({ category:"HOSTING", detail:"Datacenter / cloud IP", severity:"medium" });
//     sigs.push({ category:"VELOCITY", detail:`Velocity: ${intel.velocity||"LOW"}`,            severity:"info" });
//     return sigs;
//   }

//   async function handleCSVUpload(file) {
//     if (!file) return;
//     const text = await file.text();
//     const ips  = text.split(/[\n,]+/).map(s => s.trim()).filter(isValidIP);
//     if (!ips.length)     { setBulkStatus("No valid IPs found."); return; }
//     if (ips.length > 50) { setBulkStatus("Trimming to 50 IPs."); ips.length = 50; }
//     setBulkStatus(`Scoring ${ips.length} IPs…`);
//     try {
//       const res  = await fetch(`${API}/score/batch`, {
//         method: "POST",
//         headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
//         body: JSON.stringify({ ips })
//       });
//       const data = await res.json();
//       if (!res.ok) throw new Error(data.error);
//       data.results.forEach(r => { if (r.score != null) { addAuditEntry(r); updateStats(r.riskLevel); } });
//       const failed = data.results.filter(r => r.error).length;
//       setBulkStatus(`✓ ${data.results.length - failed} scored${failed ? `, ${failed} failed` : ""}.`);
//       const last = data.results.find(r => r.score != null);
//       if (last) { renderResult(last); updateMap(last.geo||{}, last.ip, last.riskLevel); }
//     } catch (err) { setBulkStatus(`Error: ${err.message}`); }
//   }

//   function exportLog() {
//     if (!auditEntries.length) { setBulkStatus("No entries to export."); return; }
//     const headers = ["IP","Score","Risk","Action","Country","City","ISP","Feodo","Spamhaus","ET","Scored At"];
//     const rows    = auditEntries.map(e => [
//       e.ip, e.score, e.riskLevel, e.action,
//       e.geo?.country||"—", e.geo?.city||"—", e.network?.isp||"—",
//       e.threatFeeds?.feodo?"Yes":"No",
//       e.threatFeeds?.spamhaus?"Yes":"No",
//       e.threatFeeds?.emergingThreats?"Yes":"No",
//       e.meta?.scoredAt ? new Date(e.meta.scoredAt).toISOString() : new Date().toISOString()
//     ]);
//     const csv  = [headers,...rows].map(r => r.map(v=>`"${v}"`).join(",")).join("\n");
//     const blob = new Blob([csv],{type:"text/csv"});
//     const url  = URL.createObjectURL(blob);
//     const a    = Object.assign(document.createElement("a"),{href:url,download:`ipshield-${Date.now()}.csv`});
//     a.click();
//     URL.revokeObjectURL(url);
//     setBulkStatus(`✓ Exported ${auditEntries.length} entries.`);
//   }

//   // Filter in-memory entries 
// function applyFilters(entries) {
//   return entries.filter(e => {
//     const f = auditFilters;
//     if (f.q) {
//       const q = f.q.toLowerCase();
//       if (!e.ip?.toLowerCase().includes(q) &&
//           !e.geo?.country?.toLowerCase().includes(q) &&
//           !e.network?.isp?.toLowerCase().includes(q)) return false;
//     }
//     if (f.risk       && e.riskLevel !== f.risk)                         return false;
//     if (f.minScore != null && (e.score??0) < f.minScore)                return false;
//     if (f.maxScore != null && (e.score??0) > f.maxScore)                return false;
//     if (f.proxy    != null && !!e.intelligence?.isProxy !== f.proxy)     return false;
//     if (f.tor      != null && !!e.intelligence?.isTor   !== f.tor)       return false;
//     if (f.datacenter != null && !!e.intelligence?.isDatacenter !== f.datacenter) return false;
//     return true;
//   });
// }
 
// function sortEntries(entries) {
//   return [...entries].sort((a, b) => {
//     switch (auditFilters.sort) {
//       case "score_desc": return (b.score??0) - (a.score??0);
//       case "score_asc":  return (a.score??0) - (b.score??0);
//       case "date_asc":   return new Date(a.meta?.scoredAt||0) - new Date(b.meta?.scoredAt||0);
//       default:           return new Date(b.meta?.scoredAt||0) - new Date(a.meta?.scoredAt||0);
//     }
//   });
// }

//   //Fetch from DB via API 
// async function fetchAndRenderFromDB() {
//   const params = new URLSearchParams({
//     limit:  AUDIT_PAGE_SIZE,
//     offset: auditPage * AUDIT_PAGE_SIZE,
//     sort:   auditFilters.sort
//   });
//   if (auditFilters.q)              params.set("q",          auditFilters.q);
//   if (auditFilters.risk)           params.set("risk",       auditFilters.risk);
//   if (auditFilters.minScore > 0)   params.set("minScore",   auditFilters.minScore);
//   if (auditFilters.maxScore < 100) params.set("maxScore",   auditFilters.maxScore);
//   if (auditFilters.proxy    != null) params.set("proxy",    auditFilters.proxy);
//   if (auditFilters.tor      != null) params.set("tor",      auditFilters.tor);
//   if (auditFilters.datacenter != null) params.set("datacenter", auditFilters.datacenter);
 
//   try {
//     const res  = await fetch(`${API}/audit/search?${params}`, { headers: { "x-api-key": API_KEY } });
//     const data = await res.json();
//     if (!res.ok) throw new Error(data.error);
//     auditTotal = data.total;
//     renderAuditEntries(data.entries, data.total);
//   } catch (err) {
//     setBulkStatus(`Audit DB error: ${err.message}`);
//   }
// }
  
//   // renderAudit

//   function addAuditEntry(d) {
//   auditEntries.unshift(d);
//   if (auditEntries.length > 200) auditEntries.pop();
//   if (!usingDB) renderAudit();
// }

//   function renderAudit() {
//   if (usingDB) { fetchAndRenderFromDB(); return; }
 
//   const filtered = sortEntries(applyFilters(auditEntries));
//   auditTotal     = filtered.length;
//   const page     = filtered.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);
//   renderAuditEntries(page, filtered.length);
// }
 
// function renderAuditEntries(entries, total) {
//   auditCount.textContent = `${total} ${total===1?"entry":"entries"}`;
 
//   const status = document.getElementById("auditFilterStatus");
//   const hasFilter = auditFilters.q || auditFilters.risk || auditFilters.minScore > 0 ||
//                     auditFilters.maxScore < 100 || auditFilters.proxy != null ||
//                     auditFilters.tor != null || auditFilters.datacenter != null;
 
//   if (status) {
//     status.textContent = hasFilter
//       ? `Showing ${Math.min(entries.length, total)} of ${total} matching entries${usingDB ? " (DB)" : " (session)"}`
//       : usingDB ? `Full database history — ${total} total entries` : "";
//   }
 
//   if (!entries.length) {
//     auditList.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
//       ${hasFilter ? "No entries match your filters" : "No queries yet"}
//     </div>`;
//     return;
//   }
 
//   auditList.innerHTML = entries.map(e => {
//     // Handle both in-memory format and DB row format
//     const ip        = e.ip;
//     const score     = e.score       ?? 0;
//     const riskLevel = e.riskLevel   || e.risk_level || "LOW";
//     const scoredAt  = e.meta?.scoredAt || (e.scored_at ? new Date(e.scored_at) : new Date());
//     const f = [
//       (e.threatFeeds?.feodo || e.is_feodo)           && "F",
//       (e.threatFeeds?.spamhaus || e.is_spamhaus)     && "S",
//       (e.threatFeeds?.emergingThreats || e.is_et)    && "E",
//       (e.threatFeeds?.otx?.pulseCount > 0)           && "O"
//     ].filter(Boolean).join("");
 
//     return `<div class="audit-item" data-ip="${escHtml(ip)}">
//       <span class="audit-ip">${escHtml(ip)}</span>
//       ${f ? `<span style="font-size:9px;color:#ff3355;font-weight:700;">[${f}]</span>` : ""}
//       <span class="audit-badge ${riskLevel}">${riskLevel}</span>
//       <span class="audit-score ${riskLevel}">${score}</span>
//       <span class="audit-ts">${fmtTime(new Date(scoredAt))}</span>
//     </div>`;
//   }).join("");
  
//   // Pagination controls
//   const totalPages = Math.ceil(total / AUDIT_PAGE_SIZE);
//   if (totalPages > 1) {
//     const nav = document.createElement("div");
//     nav.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:8px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text3);";
//     nav.innerHTML = `
//       <button id="auditPrev" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage===0?"disabled":""}>← Prev</button>
//       <span>Page ${auditPage+1} of ${totalPages}</span>
//       <button id="auditNext" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;" ${auditPage>=totalPages-1?"disabled":""}>Next →</button>`;
//     auditList.appendChild(nav);
 
//     document.getElementById("auditPrev")?.addEventListener("click", () => { auditPage--; renderAudit(); });
//     document.getElementById("auditNext")?.addEventListener("click", () => { auditPage++; renderAudit(); });
//   }
 
//   auditList.querySelectorAll(".audit-item").forEach(item => {
//     item.addEventListener("click", () => { ipInput.value = item.dataset.ip; scoreIP(); });
//   });
// }

//   function updateStats(riskLevel) {
//     if (riskLevel in sessionStats) {
//       sessionStats[riskLevel]++;
//       const map = { CRITICAL:"stat-critical", HIGH:"stat-high", MEDIUM:"stat-medium", LOW:"stat-low" };
//       const el  = document.getElementById(map[riskLevel]);
//       if (el) el.textContent = sessionStats[riskLevel];
//     }
//   }

//   async function loadStats() {
//     try {
//       const res  = await fetch(`${API}/stats`, { headers: { "x-api-key": API_KEY } });
//       if (!res.ok) return;
//       const data = await res.json();
//       if (data.riskDistribution) {
//         const map = { CRITICAL:"stat-critical", HIGH:"stat-high", MEDIUM:"stat-medium", LOW:"stat-low" };
//         Object.entries(map).forEach(([risk, id]) => {
//           const el = document.getElementById(id);
//           if (el && data.riskDistribution[risk] != null) {
//             el.textContent = data.riskDistribution[risk];
//             sessionStats[risk] = data.riskDistribution[risk];
//           }
//         });
//       }
//       if (data.threatFeeds) showFeedStatus(data.threatFeeds);
//     } catch (_) {}
//   }

//   function showFeedStatus(feeds) {
//     let bar = document.getElementById("feedStatusBar");
//     if (!bar) {
//       bar = document.createElement("div");
//       bar.id = "feedStatusBar";
//       bar.style.cssText = "display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:6px 32px;background:var(--bg1);border-bottom:1px solid var(--border);font-size:10px;letter-spacing:1px;";
//       const header = document.querySelector("header");
//       if (header?.nextSibling) header.parentNode.insertBefore(bar, header.nextSibling);
//     }
//     const list = [
//       { label:"FEODO",    data:feeds.feodo },
//       { label:"SPAMHAUS", data:feeds.spamhaus },
//       { label:"ET INTEL", data:feeds.emergingThreats },
//       { label:"OTX",      data:feeds.otx }
//     ];
//     bar.innerHTML = `<span style="color:var(--text3);text-transform:uppercase;letter-spacing:2px;">Threat Feeds:</span>
//       ${list.map(f => {
//         const loaded = f.label==="OTX" ? f.data?.enabled : f.data?.loaded;
//         const count  = f.data?.count ? ` (${Number(f.data.count).toLocaleString()})` : "";
//         return `<span style="color:${loaded?"var(--low)":"var(--text3)"};">${loaded?"●":"○"} ${f.label}${count}</span>`;
//       }).join("")}`;
//   }

//   function setLoading(on) {
//     scoreBtn.disabled = on;
//     if (on) {
//       resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><span>Analyzing ${escHtml(ipInput.value.trim())}…</span></div>`;
//       procTime.textContent = "";
//     }
//   }

//   function clearPanel() {
//     currentIP = null; lastResult = null; ipInput.value = "";
//     resultBody.innerHTML = `
//       <div class="placeholder">
//         <div class="placeholder-icon">⬡</div>
//         <div class="placeholder-text">
//           Enter an IP address above to begin analysis.<br>
//           Risk scoring includes geo, threat intel,<br>
//           network classification &amp; behavioral signals.
//         </div>
//       </div>`;
//     procTime.textContent = "";
//   }

//   function showError(msg) {
//     resultBody.innerHTML = `<div class="error-msg">⚠ ${escHtml(msg)}</div>`;
//     procTime.textContent = "";
//   }

//   function setBulkStatus(msg) {
//     const el = document.getElementById("bulkStatus");
//     if (el) el.textContent = msg;
//   }

//   function kv(key, val) {
//     return `<div class="kv"><span class="kv-key">${key}</span><span class="kv-val" title="${escHtml(String(val))}">${escHtml(String(val))}</span></div>`;
//   }

//   function riskIcon(l) { return { CRITICAL:"■", HIGH:"▲", MEDIUM:"◆", LOW:"●" }[l] || "●"; }

//   function fmtTime(d) {
//     return d instanceof Date && !isNaN(d)
//       ? d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}) : "—";
//   }

//   function escHtml(str) {
//     return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
//   }

//   function isValidIP(ip) {
//     return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip);
//   }

//   setInterval(loadWatchlist, 1000 * 60 * 2);
// })();


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
  let currentIP      = null;
  let lastResult     = null;

  let auditFilters  = { q:"", risk:"", minScore:0, maxScore:100, proxy:null, tor:null, datacenter:null, sort:"date_desc" };
  let auditPage     = 0;
  let auditTotal    = 0;
  let usingDB       = false; 
  const AUDIT_PAGE_SIZE = 25;

  injectExtraUI();
  injectAuditControls();
  initMap();
  loadStats();
  loadWatchlist();
  setupEventListeners();
  detectAndFillIP();

  // ── Auto-detect system IP ─────────────────────────────────────────────────
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

  // ── Extra UI ───────────────────────────────────────────────────────────────
  function injectExtraUI() {
    const headerRight = document.querySelector(".header-right");
    if (headerRight) {
      const toggle = document.createElement("button");
      toggle.className = "btn btn-ghost";
      toggle.id = "themeToggle";
      toggle.textContent = "☀ LIGHT";
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
      <button class="btn btn-ghost" id="csvBtn"      style="padding:8px 14px;font-size:11px;">↑ UPLOAD CSV</button>
      <button class="btn btn-ghost" id="firewallBtn" style="padding:8px 14px;font-size:11px;">🛡 FIREWALL RULES</button>
      <span id="bulkStatus" style="font-size:11px;color:var(--text2);"></span>`;
      searchSection.appendChild(bulk);
    }

    const mainGrid = document.querySelector(".main-grid");
    if (mainGrid) {
      const row = document.createElement("div");
      row.id = "mapWatchRow";
      row.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:24px;";

      const mapWrap = document.createElement("div");
      mapWrap.id = "mapSection";
      mapWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;";
      mapWrap.innerHTML = `
        <div class="panel-header">
          <div class="panel-title">// Geo Map</div>
          <div id="mapLabel" style="font-size:11px;color:var(--text3);">Score an IP to see location</div>
        </div>
        <div id="mapContainer" style="height:320px;background:var(--bg2);display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;">Loading map…</div>`;

      const watchWrap = document.createElement("div");
      watchWrap.id = "watchlistSection";
      watchWrap.style.cssText = "background:var(--bg1);border:1px solid var(--border);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;";
      watchWrap.innerHTML = `
        <div class="panel-header" style="justify-content:space-between;">
          <div class="panel-title">// Watchlist</div>
          <div style="display:flex;gap:8px;align-items:center;">
            <span id="watchlistCount" style="font-size:11px;color:var(--text3);">0 IPs</span>
            <button id="addWatchBtn" class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">+ WATCH</button>
            <button id="pollBtn"     class="btn btn-ghost" style="padding:4px 10px;font-size:11px;">↻ POLL</button>
          </div>
        </div>
        <div id="watchlistBody" style="flex:1;overflow-y:auto;max-height:260px;">
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
        maxlength="100"
        style="width:100%;padding:8px 36px 8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;
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
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text3);">
        <span>Score:</span>
        <input id="auditMinScore" type="number" min="0" max="100" value="0" placeholder="0"
          style="width:44px;padding:3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
        <span>–</span>
        <input id="auditMaxScore" type="number" min="0" max="100" value="100" placeholder="100"
          style="width:44px;padding:3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;">
      </div>
 
      <div style="display:flex;gap:6px;">
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
 
      <div style="margin-left:auto;display:flex;gap:6px;align-items:center;">
        <select id="auditSort"
          style="padding:3px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:inherit;cursor:pointer;">
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
  document.getElementById("auditSearch")?.addEventListener("input", e => {
    const clearBtn = document.getElementById("auditSearchClear");
    if (clearBtn) clearBtn.style.display = e.target.value ? "block" : "none";
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { auditFilters.q = e.target.value.trim(); auditPage = 0; renderAudit(); }, 300);
  });
 
  document.getElementById("auditSearchClear")?.addEventListener("click", () => {
    const input = document.getElementById("auditSearch");
    if (input) { input.value = ""; document.getElementById("auditSearchClear").style.display = "none"; }
    auditFilters.q = ""; auditPage = 0; renderAudit();
  });
 
  document.querySelectorAll(".audit-risk-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      document.querySelectorAll(".audit-risk-chip").forEach(c => {
        c.style.borderColor = "var(--border)"; c.style.background = "transparent"; c.style.color = "var(--text3)";
      });
      chip.style.borderColor = "var(--accent)"; chip.style.background = "rgba(0,217,255,0.1)"; chip.style.color = "var(--accent)";
      auditFilters.risk = chip.dataset.risk; auditPage = 0; renderAudit();
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

// firewall export 
function showFirewallExport() {
  // Collect CRITICAL and HIGH IPs from session
  const threats = auditEntries.filter(e => e.riskLevel === "CRITICAL" || e.riskLevel === "HIGH");
 
  if (!threats.length) {
    setBulkStatus("No CRITICAL or HIGH IPs in audit log to export.");
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
    if (f.risk       && e.riskLevel !== f.risk)                         return false;
    if (f.minScore != null && (e.score??0) < f.minScore)                return false;
    if (f.maxScore != null && (e.score??0) > f.maxScore)                return false;
    if (f.proxy    != null && !!e.intelligence?.isProxy !== f.proxy)     return false;
    if (f.tor      != null && !!e.intelligence?.isTor   !== f.tor)       return false;
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
  if (auditFilters.q)              params.set("q",          auditFilters.q);
  if (auditFilters.risk)           params.set("risk",       auditFilters.risk);
  if (auditFilters.minScore > 0)   params.set("minScore",   auditFilters.minScore);
  if (auditFilters.maxScore < 100) params.set("maxScore",   auditFilters.maxScore);
  if (auditFilters.proxy    != null) params.set("proxy",    auditFilters.proxy);
  if (auditFilters.tor      != null) params.set("tor",      auditFilters.tor);
  if (auditFilters.datacenter != null) params.set("datacenter", auditFilters.datacenter);
 
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
  const page     = filtered.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);
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
    container.style.cssText = "height:320px;";
    map = L.map("mapContainer", { zoomControl: true, attributionControl: false });
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
    map.setView([20, 0], 2);
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
    ipInput.addEventListener("keydown", e => { if (e.key === "Enter") scoreIP(); });

    document.querySelectorAll(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => { ipInput.value = chip.dataset.ip; scoreIP(); });
    });

    document.addEventListener("click", e => {
      if (e.target.id === "csvBtn")      document.getElementById("csvUpload").click();
      if (e.target.id === "exportBtn")   exportLog();
      if (e.target.id === "addWatchBtn") addCurrentToWatchlist();
      if (e.target.id === "pollBtn")     triggerPoll();
      if (e.target.id === "firewallBtn") showFirewallExport();
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

  // ── Theme ──────────────────────────────────────────────────────────────────
  function toggleTheme() {
    isDark = !isDark;
    const root = document.documentElement;
    const btn  = document.getElementById("themeToggle");
    if (isDark) {
      ["--bg","--bg1","--bg2","--bg3","--text","--text2","--text3","--border","--border2"].forEach(v => root.style.removeProperty(v));
      if (btn) btn.textContent = "☀ LIGHT";
    } else {
      root.style.setProperty("--bg","#f0f4f8"); root.style.setProperty("--bg1","#ffffff");
      root.style.setProperty("--bg2","#e8edf2"); root.style.setProperty("--bg3","#dce3ea");
      root.style.setProperty("--text","#1a2332"); root.style.setProperty("--text2","#4a6278");
      root.style.setProperty("--text3","#7a95a8"); root.style.setProperty("--border","#c8d8e4");
      root.style.setProperty("--border2","#b0c4d4");
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
      const res  = await fetch(`${API}/score/${encodeURIComponent(ip)}`, { headers: { "x-api-key": API_KEY } });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scoring failed");
      currentIP  = ip;
      lastResult = data;
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
    if (!ip || !isValidIP(ip)) { setBulkStatus("Score an IP first, then click + WATCH"); return; }
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
      setBulkStatus(`✓ ${ip} added to watchlist`);
      loadWatchlist();
    } catch (err) { setBulkStatus(`Error: ${err.message}`); }
  }

  async function removeFromWatchlist(ip) {
    try {
      await fetch(`${API}/watchlist/${encodeURIComponent(ip)}`, {
        method: "DELETE", headers: { "x-api-key": API_KEY }
      });
      loadWatchlist();
    } catch (err) { setBulkStatus(`Error: ${err.message}`); }
  }

  async function triggerPoll() {
    const btn = document.getElementById("pollBtn");
    if (btn) { btn.disabled = true; btn.textContent = "↻ POLLING…"; }
    try {
      await fetch(`${API}/watchlist/poll`, { method: "POST", headers: { "x-api-key": API_KEY } });
      setBulkStatus("Poll triggered — watchlist updating…");
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

  // ── WHOIS ──────────────────────────────────────────────────────────────────
  async function loadWhois(ip) {
    const panel = document.getElementById("whoisPanel");
    if (!panel) return;
    panel.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text2);font-size:12px;">Loading WHOIS data for ${escHtml(ip)}…</div>`;
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
        <div style="padding:12px 16px;border-bottom:1px solid var(--border);">
          ${signals.map(s => `
            <div class="signal-item ${s.severity}" style="margin-bottom:6px;">
              <span class="sig-cat">${escHtml(s.category)}</span>
              <span class="sig-detail">${escHtml(s.detail)}</span>
              <span class="sig-sev">${s.severity.toUpperCase()}</span>
            </div>`).join("")}
        </div>` : ""}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px;">
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
        <div style="padding:0 16px 16px;">
          <div class="detail-card">
            <div class="detail-card-title">// Remarks</div>
            ${w.remarks.map(r => `<div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${escHtml(r)}</div>`).join("")}
          </div>
        </div>` : ""}`;
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
          <div style="margin-top:10px;">
            <button id="watchCurrentBtn" class="btn btn-ghost" style="padding:5px 12px;font-size:11px;">+ Watch</button>
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
          </div>` : ""}
      </div>

      <div id="tabContent-WHOIS" style="display:none;">
        <div id="whoisPanel" data-loaded="false">
          <div style="padding:24px;text-align:center;color:var(--text3);font-size:11px;">
            Click the WHOIS tab above to load deep registration data
          </div>
        </div>
      </div>`;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
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
    if (intel.isProxy)      sigs.push({ category:"PROXY",   detail:"Proxy detected",        severity:"high" });
    if (intel.isTor)        sigs.push({ category:"TOR",     detail:"Tor exit node",          severity:"critical" });
    if (intel.isDatacenter) sigs.push({ category:"HOSTING", detail:"Datacenter / cloud IP", severity:"medium" });
    sigs.push({ category:"VELOCITY", detail:`Velocity: ${intel.velocity||"LOW"}`,            severity:"info" });
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
      setBulkStatus(`✓ ${data.results.length - failed} scored${failed ? `, ${failed} failed` : ""}.`);
      const last = data.results.find(r => r.score != null);
      if (last) { renderResult(last); updateMap(last.geo||{}, last.ip, last.riskLevel); }
    } catch (err) { setBulkStatus(`Error: ${err.message}`); }
  }

  function exportLog() {
    if (!auditEntries.length) { setBulkStatus("No entries to export."); return; }
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
    setBulkStatus(`✓ Exported ${auditEntries.length} entries.`);
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