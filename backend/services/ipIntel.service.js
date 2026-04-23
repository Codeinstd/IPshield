const axios = require("axios");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getAbuseData(ip, retries = 2) {
  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: {
        Key: process.env.ABUSE_IPDB_KEY,
        Accept: "application/json"
      },
      timeout: 5000
    });
    return res.data.data;
  } catch (err) {
    console.error("AbuseIPDB error:", err.response?.data || err.message);
    if (retries > 0) {
      await sleep(1000);
      return getAbuseData(ip, retries - 1);
    }
    return { abuseConfidenceScore: 0, totalReports: 0 };
  }
}

const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc00:|fd)/;

async function getGeoData(ip) {
  if (PRIVATE_IP.test(ip)) {
    return {
      _private:   true,
      country_name: "Private Network",
      region:     "Local",
      city:       "Local",
      timezone:   Intl.DateTimeFormat().resolvedOptions().timeZone,
      latitude:   "N/A",
      longitude:  "N/A",
      org:        "Private / RFC1918",
      asn:        "—",
      proxy:      false,
      hosting:    false
    };
  }

  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}`, {
      params: {
        fields: "status,message,country,regionName,city,timezone,lat,lon,isp,org,as,proxy,hosting"
      },
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

function computeVelocity(abuse) {
  if (abuse.totalReports > 50) return "HIGH";
  if (abuse.totalReports > 10) return "MEDIUM";
  return "LOW";
}

async function getFullIntel(ip) {
  const start = Date.now();

  const [abuse, geo] = await Promise.all([
    getAbuseData(ip),
    getGeoData(ip)
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

  const velocity = computeVelocity(abuse);

  return {
    ip,
    score,
    riskLevel,
    action,

    geo: {
      country:  geo.country_name || geo.country || "—",
      region:   geo.region       || geo.regionName || "—",
      city:     geo.city         || "—",
      timezone: geo.timezone     || "—",
      lat:      geo.latitude     ?? geo.lat ?? "—",
      lon:      geo.longitude    ?? geo.lon ?? "—"
    },

    network: {
      isp:  geo.org  || "—",
      asn:  geo.asn  || "—",
      type: geo.hosting ? "hosting" : "residential"
    },

    intelligence: {
      isDatacenter: geo.hosting || false,
      isProxy:      geo.proxy   || false,
      isTor:        (geo.org || "").toLowerCase().includes("tor"),
      velocity
    },

    meta: {
      processingMs: Date.now() - start
    }
  };
}

module.exports = { getFullIntel, getAbuseData };