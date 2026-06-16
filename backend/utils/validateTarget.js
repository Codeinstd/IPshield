const dns = require("dns").promises;
const net = require("net");


// Blocked IP ranges (RFC1918 + special ranges)
const PRIVATE_RANGES = [
  /^10\./,
  /^127\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./,
  /^169\.254\./,        // AWS metadata / link-local
  /^::1$/,
  /^fc00:/,             // IPv6 private
  /^fe80:/              // IPv6 link-local
];

// Cloud metadata (critical SSRF protection)
const CLOUD_METADATA_IPS = [
  "169.254.169.254"
];


// Check if IP is private
function isPrivateIP(ip) {
  if (!ip) return true;

  if (net.isIP(ip) === 0) return true;

  return (
    PRIVATE_RANGES.some((r) => r.test(ip)) ||
    CLOUD_METADATA_IPS.includes(ip)
  );
}

// Validate domain format
function isValidDomain(domain) {
  return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain);
}


// Extract hostname safely
function extractHost(target) {
  try {
    if (target.startsWith("http")) {
      return new URL(target).hostname;
    }
    return target;
  } catch {
    return null;
  }
}


// Resolve DNS and check IP safety
async function resolveAndCheck(host) {
  try {
    const ips = await dns.lookup(host, { all: true });

    for (const ipObj of ips) {
      if (isPrivateIP(ipObj.address)) {
        return {
          ok: false,
          error: `Blocked unsafe IP resolved: ${ipObj.address}`
        };
      }
    }

    return { ok: true };
  } catch (err) {
    return { ok: false, error: "DNS resolution failed" };
  }
}


// MAIN VALIDATOR
async function validateTarget(target) {
  if (!target || typeof target !== "string") {
    return { ok: false, error: "Target required" };
  }

  const host = extractHost(target);
  if (!host) {
    return { ok: false, error: "Invalid target format" };
  }

  // Case 1: IP address
  if (net.isIP(host)) {
    if (isPrivateIP(host)) {
      return { ok: false, error: "Private IPs are not allowed" };
    }
    return { ok: true, type: "ip" };
  }

  // Case 2: Domain
  if (!isValidDomain(host)) {
    return { ok: false, error: "Invalid domain format" };
  }

  // DNS resolution check (IMPORTANT SSRF protection)
  const dnsCheck = await resolveAndCheck(host);
  if (!dnsCheck.ok) return dnsCheck;

  return { ok: true, type: "domain" };
}

module.exports = { validateTarget };