/**
 * ipintel.service.js
 * Place in: backend/services/ipintel.service.js
 */

const axios  = require("axios");
const cache  = require("../store/cache");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────
async function getAbuseData(ip, retries = 2) {
  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params:  { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: process.env.ABUSE_IPDB_KEY, Accept: "application/json" },
      timeout: 5000
    });
    return res.data.data;
  } catch (err) {
    console.error("AbuseIPDB error:", err.response?.data || err.message);
    if (retries > 0) { await sleep(1000); return getAbuseData(ip, retries - 1); }
    return { abuseConfidenceScore: 0, totalReports: 0 };
  }
}

// ── Shodan InternetDB (free, no key) ──────────────────────────────────────────
async function getShodanData(ip) {
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 5000 });
    return res.data; // { ip, ports, cpes, hostnames, tags, vulns }
  } catch (err) {
    if (err.response?.status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], cpes: [] };
    console.error("Shodan error:", err.message);
    return { ports: [], tags: [], vulns: [], hostnames: [], cpes: [] };
  }
}

// ── VirusTotal ────────────────────────────────────────────────────────────────
async function getVirusTotalData(ip) {
  if (!process.env.VIRUSTOTAL_KEY) return null;
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": process.env.VIRUSTOTAL_KEY },
      timeout: 6000
    });
    const stats = res.data?.data?.attributes?.last_analysis_stats || {};
    return {
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      total:      Object.values(stats).reduce((a, b) => a + b, 0)
    };
  } catch (err) {
    console.error("VirusTotal error:", err.response?.status || err.message);
    return null;
  }
}

// ── Geo (ip-api.com) ──────────────────────────────────────────────────────────
const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc00:|fd)/;

async function getGeoData(ip) {
  if (PRIVATE_IP.test(ip)) {
    return {
      _private:     true,
      country_name: "Private Network",
      region:       "Local",
      city:         "Local",
      timezone:     Intl.DateTimeFormat().resolvedOptions().timeZone,
      latitude:     null,
      longitude:    null,
      org:          "Private / RFC1918",
      asn:          "—",
      proxy:        false,
      hosting:      false
    };
  }
  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}`, {
      params: { fields: "status,message,country,regionName,city,timezone,lat,lon,isp,org,as,proxy,hosting" },
      timeout: 5000
    });
    const d = res.data;
    if (d.status !== "success") throw new Error(d.message || "geo failed");
    return {
      country_name: d.country,
      region:       d.regionName,
      city:         d.city,
      timezone:     d.timezone,
      latitude:     d.lat,
      longitude:    d.lon,
      org:          d.isp,
      asn:          d.as,
      proxy:        d.proxy,
      hosting:      d.hosting
    };
  } catch (err) {
    console.error("Geo error:", err.message);
    return {};
  }
}

// ── Velocity ──────────────────────────────────────────────────────────────────
function computeVelocity(abuse) {
  if (abuse.totalReports > 50) return "HIGH";
  if (abuse.totalReports > 10) return "MEDIUM";
  return "LOW";
}

// ── Threat signals builder ────────────────────────────────────────────────────
function buildSignals({ abuse, geo, shodan, vt, score }) {
  const signals = [];

  // Abuse score signal
  signals.push({
    category: "ABUSE",
    detail:   `Confidence score: ${score}/100 · ${abuse.totalReports || 0} reports`,
    severity: score > 80 ? "critical" : score > 60 ? "high" : score > 30 ? "medium" : "low"
  });

  // Shodan tags (c2, botnet, scanner, honeypot, tor, etc.)
  if (shodan.tags?.length) {
    shodan.tags.forEach(tag => {
      const sev = ["c2", "botnet", "malware"].includes(tag) ? "critical"
                : ["scanner", "tor", "proxy"].includes(tag) ? "high" : "medium";
      signals.push({ category: "SHODAN", detail: `Tagged: ${tag}`, severity: sev });
    });
  }

  // Open ports
  if (shodan.ports?.length) {
    signals.push({
      category: "PORTS",
      detail:   `Open ports: ${shodan.ports.slice(0, 8).join(", ")}${shodan.ports.length > 8 ? "…" : ""}`,
      severity: shodan.ports.some(p => [22, 23, 3389, 5900].includes(p)) ? "high" : "medium"
    });
  }

  // Vulnerabilities
  if (shodan.vulns?.length) {
    signals.push({
      category: "VULNS",
      detail:   `${shodan.vulns.length} CVE(s): ${shodan.vulns.slice(0, 3).join(", ")}`,
      severity: "critical"
    });
  }

  // VirusTotal
  if (vt) {
    signals.push({
      category: "VIRUSTOTAL",
      detail:   `${vt.malicious} malicious, ${vt.suspicious} suspicious of ${vt.total} engines`,
      severity: vt.malicious > 5 ? "critical" : vt.malicious > 0 ? "high" : "low"
    });
  }

  // Proxy / Tor / Datacenter
  if (geo.proxy) signals.push({ category: "PROXY",      detail: "Proxy detected",          severity: "high" });
  if (shodan.tags?.includes("tor")) signals.push({ category: "TOR", detail: "Tor exit node", severity: "critical" });
  if (geo.hosting) signals.push({ category: "HOSTING",   detail: "Datacenter / cloud IP",   severity: "medium" });

  // Velocity
  const velocity = computeVelocity(abuse);
  signals.push({
    category: "VELOCITY",
    detail:   `Abuse report velocity: ${velocity} (${abuse.totalReports || 0} total reports)`,
    severity: velocity === "HIGH" ? "high" : velocity === "MEDIUM" ? "medium" : "info"
  });

  return signals;
}

// ── Main export ───────────────────────────────────────────────────────────────
async function getFullIntel(ip) {
  // Cache hit
  const cached = cache.get(ip);
  if (cached) return { ...cached, meta: { ...cached.meta, cached: true } };

  const start = Date.now();

  // All external calls in parallel
  const [abuse, geo, shodan, vt] = await Promise.all([
    getAbuseData(ip),
    getGeoData(ip),
    getShodanData(ip),
    getVirusTotalData(ip)
  ]);

  const score = abuse.abuseConfidenceScore || 0;

  const riskLevel =
    score > 80 ? "CRITICAL" :
    score > 60 ? "HIGH" :
    score > 30 ? "MEDIUM" : "LOW";

  const action =
    score > 80 ? "BLOCK" :
    score > 60 ? "CHALLENGE" :
    score > 30 ? "MONITOR" : "ALLOW";

  const signals  = buildSignals({ abuse, geo, shodan, vt, score });
  const velocity = computeVelocity(abuse);

  const result = {
    ip,
    score,
    riskLevel,
    action,

    geo: {
      country:  geo.country_name || "—",
      region:   geo.region       || "—",
      city:     geo.city         || "—",
      timezone: geo.timezone     || "—",
      lat:      geo._private ? null : (geo.latitude  ?? null),
      lon:      geo._private ? null : (geo.longitude ?? null)
    },

    network: {
      isp:       geo.org      || "—",
      asn:       geo.asn      || "—",
      type:      geo.hosting  ? "hosting" : "residential",
      hostnames: shodan.hostnames || []
    },

    intelligence: {
      isDatacenter: geo.hosting || false,
      isProxy:      geo.proxy   || false,
      isTor:        shodan.tags?.includes("tor") || (geo.org || "").toLowerCase().includes("tor"),
      velocity,
      openPorts:    shodan.ports  || [],
      vulns:        shodan.vulns  || [],
      shodanTags:   shodan.tags   || [],
      virusTotal:   vt            || null
    },

    signals,

    meta: {
      processingMs: Date.now() - start,
      cached:       false,
      scoredAt:     new Date()
    }
  };

  cache.set(ip, result);
  return result;
}

module.exports = { getFullIntel, getAbuseData };