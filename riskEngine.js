const geoip = require('geoip-lite');

// Known high-risk ASNs (Tor exits, VPN providers, botnets, bulletproof hosting)
const HIGH_RISK_ASNS = new Set([
  'AS60068', 'AS51167', 'AS209103', 'AS44477', 'AS396356',
  'AS47583', 'AS9009', 'AS13213', 'AS20860', 'AS35017'
]);

// High-risk country codes (OFAC sanctioned or high fraud regions)
const HIGH_RISK_COUNTRIES = new Set([
  'KP', 'IR', 'CU', 'SY', 'RU', 'BY', 'MM', 'VE', 'ZW', 'SD'
]);

const MEDIUM_RISK_COUNTRIES = new Set([
  'NG', 'PK', 'BD', 'ID', 'UA', 'CN', 'VN', 'EG', 'GH', 'KE'
]);

// Datacenter/hosting IP ranges (simplified CIDR representation as prefixes)
const DATACENTER_PREFIXES = [
  '104.16.', '104.17.', '104.18.', '104.19.', // Cloudflare
  '192.168.', '10.', '172.16.', '172.17.',       // Private
  '45.33.', '45.56.', '45.79.',                  // Linode
  '198.41.', '198.51.',                           // ARIN
  '35.192.', '35.184.', '34.102.',               // GCP
  '52.', '54.', '3.208.',                         // AWS (simplified)
  '40.112.', '40.114.',                           // Azure (simplified)
];

// Threat intelligence feed (mock — in prod, integrate AbuseIPDB, MaxMind, etc.)
const THREAT_INTEL_DB = new Map([
  ['185.220.101.1', { type: 'tor_exit', severity: 'critical', reports: 847 }],
  ['45.33.32.156',  { type: 'scanner',  severity: 'high',     reports: 234 }],
  ['198.20.69.98',  { type: 'proxy',    severity: 'medium',   reports: 112 }],
  ['192.241.235.82',{ type: 'botnet',   severity: 'high',     reports: 521 }],
]);

// Behavioral anomaly patterns (tracked in-memory for MVP)
const behaviorTracker = new Map(); // ip -> { requests: [], firstSeen, flags }

/**
 * Parse IP and classify basic type
 */
function classifyIPType(ip) {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  if (privateRanges.some(r => r.test(ip))) return 'private';
  if (ip.includes(':')) return 'ipv6';
  return 'ipv4';
}

/**
 * Check if IP appears to be in a datacenter range
 */
function isDatacenterIP(ip) {
  return DATACENTER_PREFIXES.some(prefix => ip.startsWith(prefix));
}

/**
 * Track behavioral signals
 */
function trackBehavior(ip) {
  const now = Date.now();
  if (!behaviorTracker.has(ip)) {
    behaviorTracker.set(ip, { requests: [now], firstSeen: now, flags: [] });
  } else {
    const data = behaviorTracker.get(ip);
    data.requests.push(now);
    // Keep only last 5 mins of requests
    data.requests = data.requests.filter(t => now - t < 300000);
  }
  return behaviorTracker.get(ip);
}

/**
 * Calculate velocity risk score (0-100)
 */
function calcVelocityRisk(behaviorData) {
  const rps5min = behaviorData.requests.length;
  if (rps5min > 500) return { score: 90, label: 'extreme velocity' };
  if (rps5min > 200) return { score: 70, label: 'high velocity' };
  if (rps5min > 50)  return { score: 40, label: 'elevated velocity' };
  if (rps5min > 20)  return { score: 20, label: 'moderate velocity' };
  return { score: 0, label: 'normal velocity' };
}

/**
 * Main risk scoring function
 * Returns a structured risk report
 */
function scoreIP(ip, metadata = {}) {
  const startTime = Date.now();
  const signals = [];
  let totalScore = 0;
  const weights = {
    threatIntel: 40,
    geo: 20,
    network: 20,
    behavior: 15,
    datacenter: 5
  };

  // ── 1. Geo lookup ────────────────────────────────────────────
  const geo = geoip.lookup(ip) || {};
  const country = geo.country || 'UNKNOWN';
  const region = geo.region || '';
  const city = geo.city || '';
  const timezone = geo.timezone || '';
  const ll = geo.ll || [0, 0];

  let geoScore = 0;
  let geoLabel = 'low risk location';
  if (HIGH_RISK_COUNTRIES.has(country)) {
    geoScore = 100;
    geoLabel = `sanctioned/high-risk country (${country})`;
    signals.push({ category: 'geo', severity: 'critical', detail: geoLabel });
  } else if (MEDIUM_RISK_COUNTRIES.has(country)) {
    geoScore = 50;
    geoLabel = `elevated-risk country (${country})`;
    signals.push({ category: 'geo', severity: 'medium', detail: geoLabel });
  } else if (country !== 'UNKNOWN') {
    signals.push({ category: 'geo', severity: 'low', detail: `origin: ${country}` });
  } else {
    geoScore = 30;
    signals.push({ category: 'geo', severity: 'medium', detail: 'geo lookup failed — unroutable or private IP' });
  }

  // ── 2. Threat Intelligence ───────────────────────────────────
  let threatScore = 0;
  const threatEntry = THREAT_INTEL_DB.get(ip);
  if (threatEntry) {
    const severityMap = { critical: 100, high: 80, medium: 50, low: 20 };
    threatScore = severityMap[threatEntry.severity] || 50;
    signals.push({
      category: 'threat_intel',
      severity: threatEntry.severity,
      detail: `known ${threatEntry.type} — ${threatEntry.reports} abuse reports`
    });
  }

  // ── 3. Network / ASN analysis ────────────────────────────────
  let networkScore = 0;
  const ipType = classifyIPType(ip);
  const datacenter = isDatacenterIP(ip);

  if (ipType === 'private') {
    networkScore = 10;
    signals.push({ category: 'network', severity: 'info', detail: 'private/internal IP address' });
  }

  const dcScore = datacenter ? 30 : 0;
  if (datacenter) {
    signals.push({ category: 'network', severity: 'medium', detail: 'datacenter/hosting IP detected' });
  }

  // IPv6 — slightly elevated (harder to trace)
  if (ipType === 'ipv6') {
    networkScore += 10;
    signals.push({ category: 'network', severity: 'low', detail: 'IPv6 address — reduced traceability' });
  }

  // ── 4. Behavioral signals ────────────────────────────────────
  const behavior = trackBehavior(ip);
  const velocity = calcVelocityRisk(behavior);
  if (velocity.score > 0) {
    signals.push({ category: 'behavior', severity: velocity.score > 60 ? 'high' : 'medium', detail: velocity.label });
  }

  // ── 5. Composite score ───────────────────────────────────────
  totalScore = Math.min(100, Math.round(
    (geoScore      * weights.geo      / 100) +
    (threatScore   * weights.threatIntel / 100) +
    (networkScore  * weights.network   / 100) +
    (velocity.score * weights.behavior / 100) +
    (dcScore       * weights.datacenter / 100)
  ));

  // Risk level classification
  let riskLevel, action;
  if (totalScore >= 75) {
    riskLevel = 'CRITICAL';
    action = 'BLOCK';
  } else if (totalScore >= 50) {
    riskLevel = 'HIGH';
    action = 'CHALLENGE';
  } else if (totalScore >= 25) {
    riskLevel = 'MEDIUM';
    action = 'MONITOR';
  } else {
    riskLevel = 'LOW';
    action = 'ALLOW';
  }

  const processingMs = Date.now() - startTime;

  return {
    ip,
    score: totalScore,
    riskLevel,
    action,
    signals,
    geo: {
      country,
      region,
      city,
      timezone,
      coordinates: ll
    },
    network: {
      type: ipType,
      isDatacenter: datacenter,
    },
    behavior: {
      requestsLast5Min: behavior.requests.length,
      firstSeen: new Date(behavior.firstSeen).toISOString(),
      velocityLabel: velocity.label
    },
    threatIntel: threatEntry || null,
    meta: {
      scoredAt: new Date().toISOString(),
      processingMs,
      version: '1.0.0'
    }
  };
}

module.exports = { scoreIP, behaviorTracker };
