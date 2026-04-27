/**
 * whois.service.js
 * Place in: backend/services/whois.service.js
 *
 * Install dep: npm install whois-json
 *
 * Provides deep WHOIS intelligence:
 * - IP WHOIS (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
 * - Registration dates, org, abuse contacts
 * - Risk signals: young registration, anonymous registrar, etc.
 */

const axios = require("axios");

// ── RDAP lookup (modern replacement for WHOIS) ────────────────────────────────
// RDAP is the standardized REST API for WHOIS data — no parsing needed
async function getRDAPData(ip) {
  try {
    // Step 1: Find the correct RDAP server for this IP
    const bootstrap = await axios.get(
      `https://rdap.arin.net/registry/ip/${ip}`,
      { timeout: 8000, headers: { Accept: "application/rdap+json" } }
    );
    return parseRDAP(bootstrap.data, ip);
  } catch (err) {
    // Fallback: try RIPE for European IPs
    try {
      const ripe = await axios.get(
        `https://rdap.db.ripe.net/ip/${ip}`,
        { timeout: 8000, headers: { Accept: "application/rdap+json" } }
      );
      return parseRDAP(ripe.data, ip);
    } catch (_) {
      // Fallback: try APNIC for Asia-Pacific
      try {
        const apnic = await axios.get(
          `https://rdap.apnic.net/ip/${ip}`,
          { timeout: 8000, headers: { Accept: "application/rdap+json" } }
        );
        return parseRDAP(apnic.data, ip);
      } catch (__) {
        console.error("RDAP all registries failed for:", ip);
        return null;
      }
    }
  }
}

function parseRDAP(data, ip) {
  // Extract entities (org, abuse contact, registrant)
  const entities   = data.entities || [];
  const org        = findEntity(entities, "registrant") || findEntity(entities, "administrative") || findEntity(entities, "technical");
  const abuseEnt   = findAbuseContact(entities);

  // Extract dates
  const events     = data.events || [];
  const registered = findEvent(events, "registration");
  const lastChanged= findEvent(events, "last changed");
  const expiry     = findEvent(events, "expiration");

  // Extract CIDR / network range
  const cidr       = data.cidr0_cidrs?.map(c => `${c.v4prefix || c.v6prefix}/${c.length}`).join(", ")
                  || data.handle
                  || "—";

  // Extract org name
  const orgName    = extractOrgName(org) || data.name || "—";

  // Extract abuse email
  const abuseEmail = extractEmail(abuseEnt) || "—";

  // Extract country
  const country    = data.country
                  || org?.vcardArray?.[1]?.find(v => v[0] === "adr")?.[3]?.["country-name"]
                  || "—";

  const registeredDate = registered ? new Date(registered) : null;
  const agedays        = registeredDate ? Math.floor((Date.now() - registeredDate.getTime()) / 86400000) : null;

  return {
    ip,
    network:      data.name        || "—",
    handle:       data.handle      || "—",
    cidr,
    orgName,
    orgId:        org?.handle       || "—",
    country,
    abuseEmail,
    registered:   registered        || "—",
    lastChanged:  lastChanged       || "—",
    expiry:       expiry            || "—",
    agedays,
    registrar:    data.port43       || "—",
    type:         data.type         || "—",
    remarks:      (data.remarks || []).map(r => r.description?.join(" ") || "").filter(Boolean).slice(0,3),
    raw:          data
  };
}

function findEntity(entities, role) {
  for (const e of entities) {
    if (e.roles?.includes(role)) return e;
    if (e.entities) {
      const found = findEntity(e.entities, role);
      if (found) return found;
    }
  }
  return null;
}

function findAbuseContact(entities) {
  for (const e of entities) {
    if (e.roles?.includes("abuse")) return e;
    if (e.entities) {
      const found = findAbuseContact(e.entities);
      if (found) return found;
    }
  }
  return null;
}

function findEvent(events, action) {
  const e = events.find(ev => ev.eventAction === action);
  return e?.eventDate || null;
}

function extractOrgName(entity) {
  if (!entity) return null;
  // Try vcardArray first
  const vcard = entity.vcardArray?.[1];
  if (vcard) {
    const fn = vcard.find(v => v[0] === "fn");
    if (fn) return fn[3];
  }
  return entity.handle || null;
}

function extractEmail(entity) {
  if (!entity) return null;
  const vcard = entity.vcardArray?.[1];
  if (vcard) {
    const email = vcard.find(v => v[0] === "email");
    if (email) return email[3];
  }
  return null;
}

// ── Risk signals from WHOIS data ──────────────────────────────────────────────
function buildWhoisSignals(whois) {
  if (!whois) return [];
  const signals = [];

  // Young network registration
  if (whois.agedays !== null && whois.agedays < 30) {
    signals.push({
      category: "WHOIS",
      detail:   `Network registered only ${whois.agedays} day(s) ago — very new`,
      severity: "critical"
    });
  } else if (whois.agedays !== null && whois.agedays < 90) {
    signals.push({
      category: "WHOIS",
      detail:   `Network registered ${whois.agedays} days ago — relatively new`,
      severity: "high"
    });
  }

  // No abuse contact
  if (whois.abuseEmail === "—") {
    signals.push({
      category: "WHOIS",
      detail:   "No abuse contact registered — unresponsive network",
      severity: "medium"
    });
  }

  // Unknown/anonymous org
  if (!whois.orgName || whois.orgName === "—" || whois.orgName.toLowerCase().includes("privacy")) {
    signals.push({
      category: "WHOIS",
      detail:   "Organization name hidden or anonymous",
      severity: "medium"
    });
  }

  return signals;
}

// ── Main export ───────────────────────────────────────────────────────────────
async function getWhoisIntel(ip) {
  const whois   = await getRDAPData(ip);
  const signals = buildWhoisSignals(whois);
  return { whois, signals };
}

module.exports = { getWhoisIntel, buildWhoisSignals };