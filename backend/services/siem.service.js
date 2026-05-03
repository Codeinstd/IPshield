const axios  = require("axios");
const logger = require("../utils/logger");

// ── Config 
function getConfig() {
  return {
    enabled:    process.env.SIEM_ENABLED === "true",
    type:       (process.env.SIEM_TYPE || "generic").toLowerCase(),
    url:        process.env.SIEM_WEBHOOK_URL || "",
    token:      process.env.SIEM_TOKEN || "",
    minScore:   parseInt(process.env.SIEM_MIN_SCORE || "0"),
    minRisk:    process.env.SIEM_MIN_RISK || "LOW",
    verifySsl:  process.env.SIEM_VERIFY_SSL !== "false"
  };
}

// ── Risk level ordering 
const RISK_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function meetsThreshold(result) {
  const cfg = getConfig();
  if (result.score < cfg.minScore) return false;
  if (RISK_ORDER[result.riskLevel] < (RISK_ORDER[cfg.minRisk] || 0)) return false;
  return true;
}

// ── Payload builders 

function buildSplunkPayload(result) {
  return {
    time:       Math.floor(Date.now() / 1000),
    host:       "ipshield",
    source:     "ipshield:threat_intel",
    sourcetype: "ipshield:ip_score",
    index:      "threat_intel",
    event: {
      ip:              result.ip,
      score:           result.score,
      risk_level:      result.riskLevel,
      action:          result.action,
      country:         result.geo?.country         || null,
      city:            result.geo?.city            || null,
      isp:             result.network?.isp         || null,
      asn:             result.network?.asn         || null,
      is_proxy:        result.intelligence?.isProxy        || false,
      is_tor:          result.intelligence?.isTor          || false,
      is_datacenter:   result.intelligence?.isDatacenter   || false,
      velocity:        result.intelligence?.velocity       || "LOW",
      open_ports:      result.intelligence?.openPorts      || [],
      vulns:           result.intelligence?.vulns          || [],
      shodan_tags:     result.intelligence?.shodanTags     || [],
      feodo:           result.threatFeeds?.feodo           || false,
      spamhaus:        result.threatFeeds?.spamhaus        || false,
      emerging_threats:result.threatFeeds?.emergingThreats || false,
      otx_pulses:      result.threatFeeds?.otx?.pulseCount || 0,
      whois_org:       result.whois?.orgName               || null,
      whois_age_days:  result.whois?.agedays               || null,
      scored_at:       new Date().toISOString(),
      processing_ms:   result.meta?.processingMs           || 0
    }
  };
}

function buildElasticPayload(result) {
  return {
    "@timestamp":      new Date().toISOString(),
    "event.kind":      "event",
    "event.category":  ["threat"],
    "event.type":      ["indicator"],
    "event.outcome":   result.riskLevel === "CRITICAL" || result.riskLevel === "HIGH" ? "failure" : "unknown",
    "threat.indicator.type": "ipv4-addr",
    "threat.indicator.ip":   result.ip,
    "threat.indicator.confidence": result.score >= 80 ? "High" : result.score >= 50 ? "Medium" : "Low",
    "source.ip":               result.ip,
    "source.geo.country_name": result.geo?.country || null,
    "source.geo.city_name":    result.geo?.city    || null,
    "source.as.organization.name": result.network?.isp || null,
    "source.as.number":            result.network?.asn || null,
    "ipshield.score":              result.score,
    "ipshield.risk_level":         result.riskLevel,
    "ipshield.action":             result.action,
    "ipshield.is_proxy":           result.intelligence?.isProxy      || false,
    "ipshield.is_tor":             result.intelligence?.isTor        || false,
    "ipshield.is_datacenter":      result.intelligence?.isDatacenter || false,
    "ipshield.feodo":              result.threatFeeds?.feodo         || false,
    "ipshield.spamhaus":           result.threatFeeds?.spamhaus      || false,
    "ipshield.emerging_threats":   result.threatFeeds?.emergingThreats || false,
    "ipshield.otx_pulses":         result.threatFeeds?.otx?.pulseCount || 0,
    "ipshield.open_ports":         result.intelligence?.openPorts    || [],
    "ipshield.vulns":              result.intelligence?.vulns        || [],
    "ipshield.shodan_tags":        result.intelligence?.shodanTags   || [],
    "tags": ["ipshield", result.riskLevel.toLowerCase()]
  };
}

function buildSentinelPayload(result) {
  return {
    TimeGenerated:     new Date().toISOString(),
    SourceSystem:      "IPShield",
    Type:              "IPShield_CL",
    IPAddress_s:       result.ip,
    Score_d:           result.score,
    RiskLevel_s:       result.riskLevel,
    Action_s:          result.action,
    Country_s:         result.geo?.country         || "",
    City_s:            result.geo?.city            || "",
    ISP_s:             result.network?.isp         || "",
    ASN_s:             result.network?.asn         || "",
    IsProxy_b:         result.intelligence?.isProxy        || false,
    IsTor_b:           result.intelligence?.isTor          || false,
    IsDatacenter_b:    result.intelligence?.isDatacenter   || false,
    Velocity_s:        result.intelligence?.velocity       || "LOW",
    OpenPorts_s:       (result.intelligence?.openPorts || []).join(","),
    Vulns_s:           (result.intelligence?.vulns    || []).join(","),
    ShodanTags_s:      (result.intelligence?.shodanTags || []).join(","),
    Feodo_b:           result.threatFeeds?.feodo           || false,
    Spamhaus_b:        result.threatFeeds?.spamhaus        || false,
    EmergingThreats_b: result.threatFeeds?.emergingThreats || false,
    OTXPulses_d:       result.threatFeeds?.otx?.pulseCount || 0,
    WhoisOrg_s:        result.whois?.orgName               || "",
    WhoisAgeDays_d:    result.whois?.agedays               || -1,
    ProcessingMs_d:    result.meta?.processingMs           || 0
  };
}

function buildQRadarPayload(result) {
  // QRadar CEF (Common Event Format)
  const sev = result.score >= 80 ? 10 : result.score >= 60 ? 7 : result.score >= 30 ? 4 : 1;
  return `CEF:0|IPShield|ThreatIntel|2.2|IP_SCORE|IP Risk Score Event|${sev}|` +
    `src=${result.ip} ` +
    `cs1=${result.riskLevel} cs1Label=RiskLevel ` +
    `cs2=${result.action} cs2Label=Action ` +
    `cs3=${result.geo?.country||""} cs3Label=Country ` +
    `cs4=${result.network?.isp||""} cs4Label=ISP ` +
    `cn1=${result.score} cn1Label=Score ` +
    `cn2=${result.threatFeeds?.otx?.pulseCount||0} cn2Label=OTXPulses ` +
    `flexString1=${(result.intelligence?.shodanTags||[]).join(";")} flexString1Label=ShodanTags ` +
    `rt=${Date.now()} ` +
    `deviceCustomDate1=${new Date().toISOString()} deviceCustomDate1Label=ScoredAt`;
}

function buildGenericPayload(result) {
  return {
    source:      "ipshield",
    version:     "2.2",
    timestamp:   new Date().toISOString(),
    event_type:  "ip_score",
    ip:          result.ip,
    score:       result.score,
    base_score:  result.baseScore,
    score_boost: result.scoreBoost,
    risk_level:  result.riskLevel,
    action:      result.action,
    geo: {
      country:   result.geo?.country  || null,
      city:      result.geo?.city     || null,
      region:    result.geo?.region   || null,
      timezone:  result.geo?.timezone || null,
      lat:       result.geo?.lat      || null,
      lon:       result.geo?.lon      || null
    },
    network: {
      isp:       result.network?.isp  || null,
      asn:       result.network?.asn  || null,
      type:      result.network?.type || null
    },
    intelligence: {
      is_proxy:       result.intelligence?.isProxy        || false,
      is_tor:         result.intelligence?.isTor          || false,
      is_datacenter:  result.intelligence?.isDatacenter   || false,
      velocity:       result.intelligence?.velocity       || "LOW",
      open_ports:     result.intelligence?.openPorts      || [],
      vulns:          result.intelligence?.vulns          || [],
      shodan_tags:    result.intelligence?.shodanTags     || []
    },
    threat_feeds: {
      feodo:            result.threatFeeds?.feodo           || false,
      spamhaus:         result.threatFeeds?.spamhaus        || false,
      emerging_threats: result.threatFeeds?.emergingThreats || false,
      otx_pulses:       result.threatFeeds?.otx?.pulseCount || 0,
      otx_tags:         result.threatFeeds?.otx?.tags       || []
    },
    whois: result.whois ? {
      org_name:    result.whois.orgName    || null,
      org_id:      result.whois.orgId      || null,
      country:     result.whois.country    || null,
      abuse_email: result.whois.abuseEmail || null,
      age_days:    result.whois.agedays    || null,
      registered:  result.whois.registered || null
    } : null,
    signals:      (result.signals || []).map(s => ({ category: s.category, detail: s.detail, severity: s.severity })),
    meta: {
      processing_ms: result.meta?.processingMs || 0,
      cached:        result.meta?.cached       || false
    }
  };
}

// ── Send to SIEM 
async function sendToSIEM(result) {
  const cfg = getConfig();
  if (!cfg.enabled || !cfg.url) return { sent: false, reason: "SIEM not configured" };
  if (!meetsThreshold(result))  return { sent: false, reason: "Below threshold" };

  let payload, headers, url = cfg.url;

  switch (cfg.type) {
    case "splunk":
      payload = buildSplunkPayload(result);
      headers = {
        "Content-Type":  "application/json",
        "Authorization": `Splunk ${cfg.token}`
      };
      break;

    case "elastic":
      payload = buildElasticPayload(result);
      headers = {
        "Content-Type":  "application/json",
        "Authorization": `ApiKey ${cfg.token}`
      };
      break;

    case "sentinel":
      payload = [buildSentinelPayload(result)]; // Sentinel expects array
      headers = {
        "Content-Type":  "application/json",
        "Log-Type":      "IPShield",
        "Authorization": `SharedKey ${cfg.token}`
      };
      break;

    case "qradar":
      payload = buildQRadarPayload(result);
      headers = { "Content-Type": "text/plain", "SEC": cfg.token };
      break;

    default: // generic
      payload = buildGenericPayload(result);
      headers = {
        "Content-Type":  "application/json",
        ...(cfg.token ? { "Authorization": `Bearer ${cfg.token}` } : {})
      };
  }

  try {
    const res = await axios.post(url, payload, {
      headers,
      timeout:         5000,
      httpsAgent:      cfg.verifySsl ? undefined : new (require("https").Agent)({ rejectUnauthorized: false }),
      validateStatus:  status => status < 500
    });

    if (res.status >= 400) {
      logger.warn(`SIEM webhook returned ${res.status} for ${result.ip}`);
      return { sent: false, status: res.status, reason: `HTTP ${res.status}` };
    }

    logger.info(`SIEM: forwarded ${result.ip} (score:${result.score}) → ${cfg.type}`);
    return { sent: true, status: res.status };
  } catch (err) {
    logger.error(`SIEM webhook failed for ${result.ip}:`, err.message);
    return { sent: false, reason: err.message };
  }
}

// ── Test webhook
async function testSIEM(overrides = {}) {
  const cfg = { ...getConfig(), ...overrides };
  if (!cfg.url) return { success: false, reason: "No webhook URL configured" };

  const mockResult = {
    ip: "185.220.101.1", score: 95, baseScore: 85, scoreBoost: 10,
    riskLevel: "CRITICAL", action: "BLOCK",
    geo:          { country:"Germany", city:"Frankfurt", region:"Hesse", timezone:"Europe/Berlin", lat:50.1109, lon:8.6821 },
    network:      { isp:"Franken-Rechenzentrum GmbH", asn:"AS60729", type:"hosting" },
    intelligence: { isProxy:false, isTor:true, isDatacenter:true, velocity:"HIGH", openPorts:[80,443,9001], vulns:[], shodanTags:["tor","scanner"] },
    threatFeeds:  { feodo:true, spamhaus:false, emergingThreats:true, otx:{ pulseCount:3, pulseNames:["Tor Exit Nodes"], tags:["tor","anonymizer"] } },
    whois:        { orgName:"Franken-Rechenzentrum", orgId:"FRZ-1", country:"DE", abuseEmail:"abuse@frz.de", agedays:2847, registered:"2016-04-12T00:00:00Z" },
    signals:      [{ category:"ABUSE", detail:"Score 95/100", severity:"critical" }, { category:"TOR", detail:"Tor exit node", severity:"critical" }],
    meta:         { processingMs:842, cached:false, scoredAt:new Date() }
  };

  // Temporarily override config for test
  const origEnabled = process.env.SIEM_ENABLED;
  const origUrl     = process.env.SIEM_WEBHOOK_URL;
  const origType    = process.env.SIEM_TYPE;
  const origToken   = process.env.SIEM_TOKEN;
  if (overrides.url)   process.env.SIEM_WEBHOOK_URL = overrides.url;
  if (overrides.type)  process.env.SIEM_TYPE        = overrides.type;
  if (overrides.token) process.env.SIEM_TOKEN       = overrides.token;
  process.env.SIEM_ENABLED   = "true";
  process.env.SIEM_MIN_SCORE = "0";
  process.env.SIEM_MIN_RISK  = "LOW";

  const result = await sendToSIEM(mockResult);

  // Restore
  process.env.SIEM_ENABLED       = origEnabled || "";
  process.env.SIEM_WEBHOOK_URL   = origUrl     || "";
  process.env.SIEM_TYPE          = origType    || "";
  process.env.SIEM_TOKEN         = origToken   || "";

  return result;
}

function getSIEMStatus() {
  const cfg = getConfig();
  return {
    enabled:   cfg.enabled,
    type:      cfg.type,
    url:       cfg.url ? cfg.url.replace(/\/\/[^@]*@/, "//***@").replace(/(token|key|password)=[^&]*/gi, "$1=***") : null,
    minScore:  cfg.minScore,
    minRisk:   cfg.minRisk,
    hasToken:  !!cfg.token
  };
}

module.exports = { sendToSIEM, testSIEM, getSIEMStatus, buildGenericPayload };