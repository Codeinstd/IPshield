const axios                = require("axios");
const cache                = require("../store/cache");
const { checkThreatFeeds } = require("./threatfeeds.service");
const { getWhoisIntel }    = require("./whois.service");
const { getReverseDNS }    = require("./rdns.service");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

async function getShodanData(ip) {
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 5000 });
    return res.data;
  } catch (err) {
    if (err.response?.status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], cpes: [] };
    console.error("Shodan error:", err.message);
    return { ports: [], tags: [], vulns: [], hostnames: [], cpes: [] };
  }
}

async function getVirusTotalData(ip) {
  if (!process.env.VIRUSTOTAL_KEY) return null;
  try {
    const res = await axios.get(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      { headers: { "x-apikey": process.env.VIRUSTOTAL_KEY }, timeout: 6000 }
    );
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

const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc00:|fd)/;

async function getGeoData(ip) {
  if (PRIVATE_IP.test(ip)) {
    return {
      _private: true, country_name: "Private Network", region: "Local",
      city: "Local", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      latitude: null, longitude: null, org: "Private / RFC1918",
      asn: "—", proxy: false, hosting: false
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
      country_name: d.country, region: d.regionName, city: d.city,
      timezone: d.timezone, latitude: d.lat, longitude: d.lon,
      org: d.isp, asn: d.as, proxy: d.proxy, hosting: d.hosting
    };
  } catch (err) {
    console.error("Geo error:", err.message);
    return {};
  }
}

function computeVelocity(abuse) {
  if (abuse.totalReports > 50) return "HIGH";
  if (abuse.totalReports > 10) return "MEDIUM";
  return "LOW";
}

/**
 * computeConfidence
 *
 * This is deliberately separate from riskLevel. riskLevel says how dangerous
 * an IP looks; confidence says how much real data backed that judgment. An
 * IP with score 5 because every source came back empty is not the same as
 * an IP with score 5 because every source independently checked out — the
 * first is "we don't know," the second is "we checked, and it's clean."
 * Collapsing those into one number becomes a real problem once IPShield is
 * used outside well-covered regions (thinner feed/WHOIS coverage for some
 * registries and geographies).
 *
 * Each source caps an overall ceiling rather than contributing to a blended
 * average — averaging let strong sources dilute one genuinely weak one (a
 * sparse WHOIS result in a thin-coverage region barely moved an averaged
 * score when geo+feeds were otherwise intact). A ceiling model means
 * confidence is only as good as the weakest meaningfully-failed source,
 * which is the honest framing: one blind spot is one blind spot, no matter
 * how much other data surrounds it.
 */
function computeConfidence({ geo, whoisData, feeds, rdns }) {
  const reasons = [];
  let ceiling = "HIGH";

  function downgrade(to) {
    const order = { HIGH: 2, MEDIUM: 1, LOW: 0 };
    if (order[to] < order[ceiling]) ceiling = to;
  }

  // Geo — getGeoData returns {} on failure. Private IPs are handled before
  // getFullIntel reaches this point, so {} here means a genuine API failure.
  const geoResolved = !!(geo && Object.keys(geo).length > 0);
  if (!geoResolved) {
    downgrade("MEDIUM");
    reasons.push("Geolocation lookup failed — country/region/ISP unavailable");
  }

  // WHOIS — getRDAPData returns null only when ARIN, RIPE, and APNIC all
  // fail. A non-null result with no org name / no registration date is a
  // real registry response that happened to be sparse — the realistic
  // signature of under-resourced registries (some AFRINIC/APNIC-allocated
  // ranges), not a request failure. Both cases lower confidence, but total
  // failure is treated as worse than a sparse-but-real answer.
  const whois = whoisData?.whois ?? null;
  if (!whois) {
    downgrade("LOW");
    reasons.push("WHOIS lookup failed across all registries (ARIN, RIPE, APNIC)");
  } else if (whois.orgName === "—" && whois.registered === "—") {
    downgrade("MEDIUM");
    reasons.push("WHOIS registry responded but returned minimal/sparse data");
  }

  // Threat feeds — feedsLoaded (not the hit/miss booleans) distinguishes a
  // feed that loaded and found nothing from a feed that never loaded at
  // all; both produce `false` for feodo/spamhaus/emergingThreats otherwise.
  const loaded = feeds?.feedsLoaded ?? {};
  const loadedCount = [loaded.feodo, loaded.spamhaus, loaded.emergingThreats].filter(Boolean).length;
  if (loadedCount === 0) {
    downgrade("LOW");
    reasons.push("No threat feeds were loaded — feed coverage unavailable for this check");
  } else if (loadedCount < 3) {
    downgrade("MEDIUM");
    reasons.push(`Only ${loadedCount} of 3 threat feeds were loaded for this check`);
  }
  if (loaded.otxChecked === false) {
    reasons.push("OTX lookup unavailable (missing API key or request failed)");
  }

  // Reverse DNS — a genuine "no PTR record" is informative on its own (the
  // absence of a PTR is itself a data point); a timeout means we genuinely
  // don't know, so only the timeout case affects confidence.
  if (rdns?.timedOut) {
    downgrade("MEDIUM");
    reasons.push("Reverse DNS lookup timed out — PTR-based signals may be incomplete");
  }

  return { level: ceiling, reasons };
}

function buildSignals({ abuse, geo, shodan, vt, feeds, whoisData, rdns, score }) {
  const signals = [];

  signals.push({
    category: "ABUSE",
    detail:   `Confidence score: ${score}/100 · ${abuse.totalReports || 0} reports`,
    severity: score > 80 ? "critical" : score > 60 ? "high" : score > 30 ? "medium" : "low"
  });

  if (feeds?.signals?.length)     signals.push(...feeds.signals);
  if (whoisData?.signals?.length) signals.push(...whoisData.signals);
  if (rdns?.signals?.length)      signals.push(...rdns.signals);

  if (shodan.tags?.length) {
    shodan.tags.forEach(tag => {
      const sev = ["c2","botnet","malware"].includes(tag) ? "critical"
                : ["scanner","tor","proxy"].includes(tag)  ? "high" : "medium";
      signals.push({ category: "SHODAN", detail: `Tagged: ${tag}`, severity: sev });
    });
  }

  if (shodan.ports?.length) {
    signals.push({
      category: "PORTS",
      detail:   `Open ports: ${shodan.ports.slice(0,8).join(", ")}${shodan.ports.length > 8 ? "…" : ""}`,
      severity: shodan.ports.some(p => [22,23,3389,5900].includes(p)) ? "high" : "medium"
    });
  }

  if (shodan.vulns?.length) {
    signals.push({
      category: "VULNS",
      detail:   `${shodan.vulns.length} CVE(s): ${shodan.vulns.slice(0,3).join(", ")}`,
      severity: "critical"
    });
  }

  if (vt) {
    signals.push({
      category: "VIRUSTOTAL",
      detail:   `${vt.malicious} malicious, ${vt.suspicious} suspicious of ${vt.total} engines`,
      severity: vt.malicious > 5 ? "critical" : vt.malicious > 0 ? "high" : "low"
    });
  }

  if (geo.proxy)                    signals.push({ category: "PROXY",   detail: "Proxy detected",        severity: "high" });
  if (shodan.tags?.includes("tor")) signals.push({ category: "TOR",     detail: "Tor exit node",          severity: "critical" });
  if (geo.hosting)                  signals.push({ category: "HOSTING", detail: "Datacenter / cloud IP", severity: "medium" });

  // FCrDNS mismatch — PTR hostname doesn't resolve back to original IP
  if (rdns?.fcrdns === false && rdns?.primary) {
    signals.push({
      category: "RDNS",
      detail:   `FCrDNS mismatch — ${rdns.primary} does not resolve back to ${rdns.ip}`,
      severity: "medium"
    });
  }

  const velocity = computeVelocity(abuse);
  signals.push({
    category: "VELOCITY",
    detail:   `Abuse report velocity: ${velocity} (${abuse.totalReports || 0} total reports)`,
    severity: velocity === "HIGH" ? "high" : velocity === "MEDIUM" ? "medium" : "info"
  });

  return signals;
}

async function getFullIntel(ip, options = {}) {
  if (!options.bypassCache) {
    const cached = cache.get(ip);
    if (cached) return { ...cached, meta: { ...cached.meta, cached: true } };
  }

  const start = Date.now();

  const [abuse, geo, shodan, vt, feeds, whoisData, rdns] = await Promise.all([
    getAbuseData(ip),
    getGeoData(ip),
    getShodanData(ip),
    getVirusTotalData(ip),
    checkThreatFeeds(ip),
    getWhoisIntel(ip),
    getReverseDNS(ip)
  ]);

  const baseScore = abuse.abuseConfidenceScore || 0;
  const score     = Math.min(baseScore + (feeds?.scoreBoost || 0), 100);

  const riskLevel =
    score > 80 ? "CRITICAL" :
    score > 60 ? "HIGH"     :
    score > 30 ? "MEDIUM"   : "LOW";

  const action =
    score > 80 ? "BLOCK"     :
    score > 60 ? "CHALLENGE" :
    score > 30 ? "MONITOR"   : "ALLOW";

  const velocity = computeVelocity(abuse);
  const signals  = buildSignals({ abuse, geo, shodan, vt, feeds, whoisData, rdns, score });
  const confidence = computeConfidence({ geo, whoisData, feeds, rdns });

  const result = {
    ip, score, baseScore,
    scoreBoost: feeds?.scoreBoost || 0,
    riskLevel, action,
    confidence: confidence.level,
    confidenceReasons: confidence.reasons,

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

    threatFeeds: {
      feodo:           feeds?.feodo           || false,
      spamhaus:        feeds?.spamhaus        || false,
      emergingThreats: feeds?.emergingThreats || false,
      otx:             feeds?.otx             || null
    },

    rdns: {
      hostnames: rdns.hostnames || [],
      primary:   rdns.primary   || null,
      fcrdns:    rdns.fcrdns    ?? null,
      private:   rdns.private   || false
    },

    whois:   whoisData?.whois || null,
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