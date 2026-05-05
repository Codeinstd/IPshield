const dns = require("dns").promises;

// ── Suspicious PTR patterns 
const PATTERNS = [
  // Tor / anonymization
  { regex: /tor[-_.]?exit|\.torproject\./i,          label: "Tor exit node hostname",   severity: "critical" },
  { regex: /vpn|proxy|socks|anonymi[sz]/i,           label: "VPN/proxy hostname",       severity: "high"     },

  // C2 / malicious
  { regex: /botnet|c2\.|cnc\.|command[-_.]control/i, label: "C2/botnet hostname",       severity: "critical" },
  { regex: /bulletproof|offshore[-_.]host/i,         label: "Bulletproof hosting",      severity: "critical" },
  { regex: /scanner|masscan|shodan|censys|zgrab/i,   label: "Scanner hostname",         severity: "high"     },
  { regex: /spam|mailer[-_.]?out|bulk[-_.]?mail/i,   label: "Spam/bulk mail hostname",  severity: "high"     },

  // Dynamic / residential
  { regex: /dynamic|dhcp|dsl|cable|broadband/i,      label: "Dynamic/residential host", severity: "low"      },
  { regex: /dial[-_.]?up/i,                          label: "Dial-up connection",       severity: "low"      },
  { regex: /\d{1,3}[._-]\d{1,3}[._-]\d{1,3}[._-]\d{1,3}/, label: "Reverse IP in hostname (dynamic)", severity: "low" },

  // Cloud / VPS hosting
  { regex: /\.compute\.amazonaws\.com$/i,            label: "AWS EC2 instance",         severity: "medium"   },
  { regex: /\.googleusercontent\.com$/i,             label: "Google Cloud instance",    severity: "medium"   },
  { regex: /\.vultr\.com$/i,                         label: "Vultr VPS",                severity: "medium"   },
  { regex: /\.linode\.com$/i,                        label: "Linode/Akamai VPS",        severity: "medium"   },
  { regex: /\.digitalocean\.com$/i,                  label: "DigitalOcean VPS",         severity: "medium"   },
  { regex: /\.hetzner\.|\.hetzner-cloud\./i,         label: "Hetzner VPS",              severity: "medium"   },

  // Research / known tools
  { regex: /security[-_.]?research|pen[-_.]?test/i,  label: "Security research host",   severity: "info"     },
  { regex: /honeypot|tarpit/i,                       label: "Honeypot hostname",        severity: "info"     },
];

const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$)/;

// ── Main reverse DNS lookup 
async function getReverseDNS(ip) {
  if (PRIVATE_IP.test(ip)) {
    return { ip, hostnames: [], primary: null, signals: [], private: true, fcrdns: null };
  }

  let hostnames = [];
  try {
    hostnames = await Promise.race([
      dns.reverse(ip),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))
    ]);
  } catch (err) {
    if (err.code !== "ENOTFOUND" && err.code !== "ENODATA" && err.message !== "timeout") {
      console.error(`rDNS error for ${ip}:`, err.code || err.message);
    }
  }

  const primary = hostnames[0] || null;
  const signals = buildRDNSSignals(hostnames);

  // FCrDNS check on primary hostname
  let fcrdns = null;
  if (primary) {
    fcrdns = await verifyFCrDNS(ip, primary).catch(() => false);
  }

  return { ip, hostnames, primary, signals, private: false, fcrdns };
}

// ── Pattern analysis 
function buildRDNSSignals(hostnames) {
  if (!hostnames.length) return [];
  const signals = [];
  const seen    = new Set();

  for (const hostname of hostnames) {
    for (const { regex, label, severity } of PATTERNS) {
      if (regex.test(hostname) && !seen.has(label)) {
        seen.add(label);
        signals.push({ category: "RDNS", detail: `${label}: ${hostname}`, severity });
      }
    }
  }

  return signals;
}

// ── Forward-confirmed reverse DNS (FCrDNS)
// Checks that the PTR hostname resolves back to the original IP
async function verifyFCrDNS(ip, hostname) {
  try {
    const [v4, v6] = await Promise.all([
      dns.resolve4(hostname).catch(() => []),
      dns.resolve6(hostname).catch(() => [])
    ]);
    return [...v4, ...v6].includes(ip);
  } catch {
    return false;
  }
}

module.exports = { getReverseDNS, buildRDNSSignals, verifyFCrDNS };