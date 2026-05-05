const axios = require("axios");

// ── In-memory feed cache 
const feedCache = {
  feodo:          { ips: new Set(), ts: 0 },
  spamhaus:       { ips: new Set(), ts: 0 },
  emergingThreats:{ ips: new Set(), ts: 0 },
};

const FEED_TTL = 1000 * 60 * 60 * 6; // refresh feeds every 6 hours

// ── Feed loaders

async function loadFeodoFeed() {
  if (Date.now() - feedCache.feodo.ts < FEED_TTL) return;
  try {
    const res  = await axios.get(
      "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
      { timeout: 8000, responseType: "text" }
    );
    const ips  = res.data
      .split("\n")
      .map(l => l.trim())
      .filter(l => l && !l.startsWith("#") && isValidIPv4(l));

    feedCache.feodo.ips = new Set(ips);
    feedCache.feodo.ts  = Date.now();
    console.log(`✓ Feodo feed loaded: ${ips.length} C2 IPs`);
  } catch (err) {
    console.error("Feodo feed error:", err.message);
  }
}

async function loadSpamhausFeed() {
  if (Date.now() - feedCache.spamhaus.ts < FEED_TTL) return;
  try {
    const res  = await axios.get(
      "https://www.spamhaus.org/drop/drop.txt",
      { timeout: 8000, responseType: "text" }
    );
    // DROP list uses CIDR ranges — extract and store them for range matching
    const ranges = res.data
      .split("\n")
      .map(l => l.split(";")[0].trim())
      .filter(l => l && !l.startsWith(";") && l.includes("/"));

    feedCache.spamhaus.ips = new Set(ranges);
    feedCache.spamhaus.ts  = Date.now();
    console.log(`✓ Spamhaus DROP feed loaded: ${ranges.length} ranges`);
  } catch (err) {
    console.error("Spamhaus feed error:", err.message);
  }
}

async function loadEmergingThreatsFeed() {
  if (Date.now() - feedCache.emergingThreats.ts < FEED_TTL) return;
  try {
    const res  = await axios.get(
      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
      { timeout: 8000, responseType: "text" }
    );
    const ips  = res.data
      .split("\n")
      .map(l => l.trim())
      .filter(l => l && !l.startsWith("#") && isValidIPv4(l));

    feedCache.emergingThreats.ips = new Set(ips);
    feedCache.emergingThreats.ts  = Date.now();
    console.log(`✓ Emerging Threats feed loaded: ${ips.length} IPs`);
  } catch (err) {
    console.error("Emerging Threats feed error:", err.message);
  }
}

// ── OTX lookup (per-IP, not a bulk feed) 
async function getOTXData(ip) {
  if (!process.env.OTX_API_KEY) return null;
  try {
    const res = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`,
      {
        headers: { "X-OTX-API-KEY": process.env.OTX_API_KEY },
        timeout: 6000
      }
    );
    const d = res.data;
    return {
      pulseCount:  d.pulse_info?.count        || 0,
      pulseNames:  (d.pulse_info?.pulses || []).slice(0, 3).map(p => p.name),
      reputation:  d.reputation               || 0,
      malwareCount:d.malware_count             || 0,
      tags:        (d.pulse_info?.pulses || [])
                    .flatMap(p => p.tags || [])
                    .filter((t, i, a) => a.indexOf(t) === i) // unique
                    .slice(0, 8)
    };
  } catch (err) {
    if (err.response?.status !== 404) {
      console.error("OTX error:", err.response?.status || err.message);
    }
    return null;
  }
}

// ── CIDR range checker for Spamhaus 
function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
}

function isInCIDR(ip, cidr) {
  try {
    const [range, bits] = cidr.split("/");
    const mask    = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
    return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
  } catch { return false; }
}

function isInSpamhaus(ip) {
  for (const range of feedCache.spamhaus.ips) {
    if (isInCIDR(ip, range)) return true;
  }
  return false;
}

// ── Main export 

/**
 * checkThreatFeeds(ip)
 * Returns a threat feed result object with signals and score boost.
 */
async function checkThreatFeeds(ip) {
  // Load/refresh all feeds in parallel
  await Promise.allSettled([
    loadFeodoFeed(),
    loadSpamhausFeed(),
    loadEmergingThreatsFeed()
  ]);

  // Per-IP OTX lookup
  const otx = await getOTXData(ip);

  const results = {
    feodo:          feedCache.feodo.ips.has(ip),
    spamhaus:       isInSpamhaus(ip),
    emergingThreats:feedCache.emergingThreats.ips.has(ip),
    otx,
    signals:        [],
    scoreBoost:     0  // additional score to add to abuse score
  };

  // Build signals from feed hits
  if (results.feodo) {
    results.signals.push({
      category: "FEODO",
      detail:   "Listed on Feodo Tracker — active C2 botnet infrastructure",
      severity: "critical"
    });
    results.scoreBoost += 40;
  }

  if (results.spamhaus) {
    results.signals.push({
      category: "SPAMHAUS",
      detail:   "Listed on Spamhaus DROP — do not route or peer",
      severity: "critical"
    });
    results.scoreBoost += 35;
  }

  if (results.emergingThreats) {
    results.signals.push({
      category: "ET INTEL",
      detail:   "Listed on Emerging Threats compromised IP list",
      severity: "high"
    });
    results.scoreBoost += 25;
  }

  if (otx) {
    if (otx.pulseCount > 0) {
      results.signals.push({
        category: "OTX",
        detail:   `Found in ${otx.pulseCount} OTX pulse(s): ${otx.pulseNames.slice(0,2).join(", ")}`,
        severity: otx.pulseCount > 5 ? "critical" : otx.pulseCount > 2 ? "high" : "medium"
      });
      results.scoreBoost += Math.min(otx.pulseCount * 5, 30);
    }

    if (otx.malwareCount > 0) {
      results.signals.push({
        category: "OTX MALWARE",
        detail:   `Associated with ${otx.malwareCount} malware sample(s)`,
        severity: "critical"
      });
      results.scoreBoost += 20;
    }
  }

  // Cap score boost at 60 — don't exceed 100 total
  results.scoreBoost = Math.min(results.scoreBoost, 60);

  return results;
}

/**
 * getFeedStats()
 * Returns current feed status for the /api/stats endpoint.
 */
function getFeedStats() {
  return {
    feodo: {
      loaded: feedCache.feodo.ts > 0,
      count:  feedCache.feodo.ips.size,
      age:    feedCache.feodo.ts ? Math.round((Date.now() - feedCache.feodo.ts) / 1000 / 60) + "m ago" : "never"
    },
    spamhaus: {
      loaded: feedCache.spamhaus.ts > 0,
      count:  feedCache.spamhaus.ips.size,
      age:    feedCache.spamhaus.ts ? Math.round((Date.now() - feedCache.spamhaus.ts) / 1000 / 60) + "m ago" : "never"
    },
    emergingThreats: {
      loaded: feedCache.emergingThreats.ts > 0,
      count:  feedCache.emergingThreats.ips.size,
      age:    feedCache.emergingThreats.ts ? Math.round((Date.now() - feedCache.emergingThreats.ts) / 1000 / 60) + "m ago" : "never"
    },
    otx: { enabled: !!process.env.OTX_API_KEY }
  };
}

function isValidIPv4(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

// Pre-load feeds on startup
setTimeout(() => {
  Promise.allSettled([
    loadFeodoFeed(),
    loadSpamhausFeed(),
    loadEmergingThreatsFeed()
  ]).then(() => console.log("✓ Threat feeds initialized"));
}, 2000);

module.exports = { checkThreatFeeds, getFeedStats };