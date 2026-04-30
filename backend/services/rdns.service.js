
const dns = require("dns").promises;

// Patterns that suggest dynamic/residential IPs
const DYNAMIC_PATTERNS = [
  /\d+[.-]\d+[.-]\d+[.-]\d+/,         // raw IP in hostname
  /dynamic/i, /dhcp/i, /cable/i,
  /dsl/i, /broadband/i, /residential/i,
  /pool/i, /client/i, /cpe/i,
  /ppp/i, /dial/i, /adsl/i
];

// Patterns that suggest hosting/datacenter
const HOSTING_PATTERNS = [
  /server/i, /host/i, /node/i,
  /vps/i, /cloud/i, /dedicated/i,
  /static/i, /edge/i, /cdn/i
];

// Suspicious TLDs/patterns in PTR records
const SUSPICIOUS_PATTERNS = [
  /\.ru$/i, /\.cn$/i, /\.tk$/i,
  /tor/i, /exit/i, /relay/i,
  /proxy/i, /vpn/i, /anon/i,
  /botnet/i, /malware/i, /spam/i
];

async function getReverseDNS(ip) {
  const result = {
    ptr:        [],
    hasPTR:     false,
    isDynamic:  false,
    isHosting:  false,
    isSuspicious: false,
    suspiciousReasons: [],
    signals:    []
  };

  try {
    const hostnames = await dns.reverse(ip);
    result.ptr    = hostnames;
    result.hasPTR = hostnames.length > 0;

    for (const hostname of hostnames) {
      // Check dynamic patterns
      if (DYNAMIC_PATTERNS.some(p => p.test(hostname))) {
        result.isDynamic = true;
      }

      // Check hosting patterns
      if (HOSTING_PATTERNS.some(p => p.test(hostname))) {
        result.isHosting = true;
      }

      // Check suspicious patterns
      const matched = SUSPICIOUS_PATTERNS.filter(p => p.test(hostname));
      if (matched.length) {
        result.isSuspicious = true;
        result.suspiciousReasons.push(hostname);
      }
    }

    // Build signals
    if (result.isSuspicious) {
      result.signals.push({
        category: "RDNS",
        detail:   `Suspicious PTR record: ${result.suspiciousReasons.slice(0,2).join(", ")}`,
        severity: "high"
      });
    }

    if (result.isDynamic) {
      result.signals.push({
        category: "RDNS",
        detail:   `Dynamic/residential PTR: ${hostnames[0]}`,
        severity: "medium"
      });
    }

    if (!result.hasPTR) {
      result.signals.push({
        category: "RDNS",
        detail:   "No PTR record — reverse DNS not configured",
        severity: "low"
      });
    }

  } catch (err) {
    // ENOTFOUND / ENODATA = no PTR record (common and not alarming)
    if (err.code !== "ENOTFOUND" && err.code !== "ENODATA" && err.code !== "ESERVFAIL") {
      console.error("rDNS error:", err.code, err.message);
    }
    result.signals.push({
      category: "RDNS",
      detail:   "No PTR record — reverse DNS not configured",
      severity: "low"
    });
  }

  return result;
}

module.exports = { getReverseDNS };