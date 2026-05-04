const express = require("express");
const router  = express.Router();
const { param, validationResult } = require("express-validator");
const { getFullIntel } = require("../services/ipIntel.service");
const logger = require("../utils/logger");

router.get("/:ip",
  [
    param("ip").trim().notEmpty().custom(ip => {
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
        throw new Error("Invalid IP address");
      return true;
    })
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid IP address" });

    try {
      const ip     = req.params.ip;
      const cached = req.query.cached !== "false";
      logger.info(`PDF report requested for ${ip}`);

      const data = await getFullIntel(ip, { bypassCache: !cached });

      const PDFDocument = require("pdfkit");
      const doc = new PDFDocument({ margin: 50, size: "A4", autoFirstPage: true, bufferPages: true });

      const filename = `ipshield-report-${ip.replace(/[:.]/g, "_")}-${Date.now()}.pdf`;
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      doc.pipe(res);

      buildPDF(doc, data);
      doc.end();
    } catch (err) {
      next(err);
    }
  }
);

// ── Color palette 
const C = {
  bg:       "#080c0f",
  dark:     "#0d1117",
  card:     "#111820",
  accent:   "#00d9ff",
  critical: "#ff3355",
  high:     "#ff7700",
  medium:   "#ffcc00",
  low:      "#00e87c",
  white:    "#ffffff",
  text:     "#c9d8e8",
  text2:    "#6a8fa8",
  border:   "#1e2d3d"
};

const RISK_COLOR = { CRITICAL: C.critical, HIGH: C.high, MEDIUM: C.medium, LOW: C.low };
const SEV_COLOR  = { critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.accent };

// safe() — strips non-printable ASCII and uses "N/A" as fallback (not em-dash)
function safe(val) {
  if (val === null || val === undefined) return "N/A";
  const str = String(val).replace(/[^\x20-\x7E]/g, "").trim();
  return str || "N/A";
}

// has() — check if a value is meaningful (not null, undefined, "—", "N/A", empty)
function has(val) {
  if (val === null || val === undefined) return false;
  const str = String(val).trim();
  return str !== "" && str !== "N/A" && str !== "-" && str !== "N/A";
}

function buildPDF(doc, d) {
  const score     = d.score        ?? 0;
  const riskLevel = d.riskLevel    ?? "LOW";
  const geo       = d.geo          ?? {};
  const network   = d.network      ?? {};
  const intel     = d.intelligence ?? {};
  const signals   = d.signals      ?? [];
  const feeds     = d.threatFeeds  ?? {};
  const rdns      = d.rdns         ?? {};
  const whois     = d.whois        ?? null;

  const riskColor = RISK_COLOR[riskLevel] || C.low;
  const pageW     = doc.page.width;
  const pageH     = doc.page.height;
  const M         = 48;
  const W         = pageW - M * 2;
  const FOOTER_H  = 36;
  const MAX_Y     = pageH - FOOTER_H - 16; // content must stay above footer

  // ── Layout helpers 
  function newPage() {
    doc.addPage();
    return M;
  }

  function checkY(y, needed) {
    if (y + needed > MAX_Y) return newPage();
    return y;
  }

  function sectionHeader(title, x, y, w) {
    doc.rect(x, y, w, 18).fill(C.dark);
    doc.fontSize(8).font("Helvetica-Bold").fillColor(C.accent)
       .text(`// ${title.toUpperCase()}`, x + 8, y + 5, { width: w - 16, lineBreak: false });
    return y + 22;
  }

  // kvRow — label on left, value on right, no em-dash issues
  function kvRow(label, value, x, y, w, valColor) {
    const lw = 115;
    const vw = w - lw - 20;
    const display = has(value) ? safe(value) : "N/A";
    const color   = has(value) ? (valColor || C.white) : C.text2;
    doc.fontSize(8).font("Helvetica").fillColor(C.text2)
       .text(safe(label), x + 8, y, { width: lw, lineBreak: false });
    doc.fontSize(8).font("Helvetica").fillColor(color)
       .text(display, x + 8 + lw, y, { width: vw, lineBreak: false, ellipsis: true });
    return y + 14;
  }

  
  // HEADER
  doc.rect(0, 0, pageW, 68).fill(C.dark);
  doc.fontSize(22).font("Helvetica-Bold")
     .fillColor(C.white).text("IP", M, 20, { continued: true })
     .fillColor(C.accent).text("Shield");
  doc.fontSize(9).font("Helvetica").fillColor(C.text2)
     .text("Risk Intelligence Report", M, 46);
  doc.fontSize(8).fillColor(C.text2)
     .text(new Date().toUTCString(), M, 46, { align: "right", width: W });

  // ── Risk banner 
  doc.rect(0, 68, pageW, 44).fill(riskColor);
  doc.fontSize(11).font("Helvetica-Bold").fillColor("#000000")
     .text(`${riskLevel} RISK  |  Action: ${safe(d.action)}`, M, 78, { width: W * 0.6 });
  doc.fontSize(19).font("Helvetica-Bold").fillColor("#000000")
     .text(safe(d.ip), M, 78, { align: "right", width: W });

  // ── Score Strip 
  let y = 124;
  doc.rect(M, y, W, 52).fill(C.dark);
  doc.circle(M + 36, y + 26, 22).stroke(riskColor).lineWidth(2);
  doc.fontSize(16).font("Helvetica-Bold").fillColor(riskColor)
     .text(String(score), M + 14, y + 15, { width: 44, align: "center" });
  doc.fontSize(7).font("Helvetica").fillColor(C.text2)
     .text("/100", M + 14, y + 33, { width: 44, align: "center" });

  const boostNote = d.scoreBoost > 0
    ? `Base score: ${d.baseScore}  +  Feed boost: +${d.scoreBoost}`
    : "Source: AbuseIPDB";
  doc.fontSize(10).font("Helvetica-Bold").fillColor(C.white)
     .text("ABUSE CONFIDENCE SCORE", M + 70, y + 8);
  doc.fontSize(8).font("Helvetica").fillColor(C.text2)
     .text(boostNote, M + 70, y + 24);

  const scoredAt = d.meta?.scoredAt ? new Date(d.meta.scoredAt).toUTCString() : new Date().toUTCString();
  const procMs   = d.meta?.processingMs ? `${d.meta.processingMs}ms${d.meta.cached ? " (cached)" : ""}` : "";
  doc.fontSize(8).font("Helvetica").fillColor(C.text2)
     .text(`Generated: ${scoredAt}   ${procMs}`, M + 70, y + 38);

  y += 64;

  
  // TWO COLUMNS: Geolocation | Network
  const colW = (W - 12) / 2;
  const lx   = M;
  const rx   = M + colW + 12;

  y = checkY(y, 130);
  let ly = sectionHeader("Geolocation", lx, y, colW);
  let ry = sectionHeader("Network", rx, y, colW);

  // Geo rows — use direct property access, not fallback em-dash
  ly = kvRow("Country",   geo.country,  lx, ly, colW);
  ly = kvRow("Region",    geo.region,   lx, ly, colW);
  ly = kvRow("City",      geo.city,     lx, ly, colW);
  ly = kvRow("Timezone",  geo.timezone, lx, ly, colW);
  ly = kvRow("Latitude",  geo.lat,      lx, ly, colW);
  ly = kvRow("Longitude", geo.lon,      lx, ly, colW);

  // Show note if geo data unavailable
  if (!has(geo.country) && !has(geo.city)) {
    doc.fontSize(7).font("Helvetica").fillColor(C.text2)
       .text("Geo data unavailable for this IP", lx + 8, ly);
    ly += 14;
  }

  // Network rows
  ry = kvRow("ISP",        network.isp,  rx, ry, colW);
  ry = kvRow("ASN",        network.asn,  rx, ry, colW);
  ry = kvRow("Type",       network.type, rx, ry, colW);
  ry = kvRow("Datacenter", intel.isDatacenter ? "Yes" : "No", rx, ry, colW,
             intel.isDatacenter ? C.medium : C.white);
  ry = kvRow("Proxy",      intel.isProxy ? "Detected" : "No", rx, ry, colW,
             intel.isProxy ? C.high : C.white);
  ry = kvRow("Tor",        intel.isTor   ? "Exit Node" : "No", rx, ry, colW,
             intel.isTor ? C.critical : C.white);
  ry = kvRow("Velocity",   intel.velocity || "LOW", rx, ry, colW,
             intel.velocity === "HIGH" ? C.critical : intel.velocity === "MEDIUM" ? C.medium : C.low);

  y = Math.max(ly, ry) + 14;


  // TWO COLUMNS: Reverse DNS | WHOIS
  y = checkY(y, 120);

  ly = sectionHeader("Reverse DNS (PTR)", lx, y, colW);
  ry = sectionHeader("WHOIS / RDAP", rx, y, colW);

  // rDNS
  if (rdns.private) {
    doc.fontSize(8).font("Helvetica").fillColor(C.text2)
       .text("Private IP - no PTR record", lx + 8, ly); ly += 14;
  } else if (has(rdns.primary)) {
    doc.fontSize(8).font("Helvetica").fillColor(C.text2)
       .text("PTR Record", lx + 8, ly, { width: 80, lineBreak: false });
    doc.fontSize(8).font("Helvetica").fillColor(C.accent)
       .text(safe(rdns.primary), lx + 90, ly, { width: colW - 98, lineBreak: false, ellipsis: true });
    ly += 14;

    const fcLabel = rdns.fcrdns === true  ? "Verified"
                  : rdns.fcrdns === false ? "Mismatch"
                  : "N/A";
    const fcColor = rdns.fcrdns === true  ? C.low
                  : rdns.fcrdns === false ? C.medium : C.text2;
    ly = kvRow("FCrDNS Check", fcLabel, lx, ly, colW, fcColor);

    if ((rdns.hostnames?.length || 0) > 1) {
      ly = kvRow("Additional PTRs", `${rdns.hostnames.length - 1} more record(s)`, lx, ly, colW);
    }
  } else {
    doc.fontSize(8).font("Helvetica").fillColor(C.text2)
       .text("No PTR record found", lx + 8, ly); ly += 14;
  }

  // WHOIS
  if (whois) {
    ry = kvRow("Organisation", whois.orgName,    rx, ry, colW);
    ry = kvRow("Org ID",       whois.orgId,      rx, ry, colW);
    ry = kvRow("Country",      whois.country,    rx, ry, colW);
    ry = kvRow("Abuse Email",  whois.abuseEmail, rx, ry, colW,
               has(whois.abuseEmail) ? C.accent : C.text2);
    ry = kvRow("CIDR Range",   whois.cidr,       rx, ry, colW);
    const regDate = has(whois.registered)
      ? new Date(whois.registered).toLocaleDateString("en-GB")
      : null;
    ry = kvRow("Registered", regDate, rx, ry, colW);
    const ageColor = whois.agedays != null
      ? (whois.agedays < 30 ? C.critical : whois.agedays < 90 ? C.medium : C.white)
      : C.text2;
    ry = kvRow("Network Age",
               whois.agedays != null ? `${whois.agedays} days` : null,
               rx, ry, colW, ageColor);
  } else {
    doc.fontSize(8).font("Helvetica").fillColor(C.text2)
       .text("WHOIS data unavailable", rx + 8, ry); ry += 14;
  }

  y = Math.max(ly, ry) + 14;


  // Threat Feed Analysis
  y = checkY(y, 64);
  y = sectionHeader("Threat Feed Analysis", M, y, W);

  const feedItems = [
    { label: "Feodo Tracker (C2)",    hit: !!feeds.feodo           },
    { label: "Spamhaus DROP",         hit: !!feeds.spamhaus        },
    { label: "Emerging Threats",      hit: !!feeds.emergingThreats },
    { label: `OTX (${feeds.otx?.pulseCount || 0} pulses)`, hit: (feeds.otx?.pulseCount || 0) > 0 }
  ];

  const feedW = (W - 9) / 4;
  feedItems.forEach((f, i) => {
    const fx    = M + i * (feedW + 3);
    const color = f.hit ? C.critical : C.low;
    doc.rect(fx, y, feedW, 30).fill(C.card);
    doc.rect(fx, y, feedW, 3).fill(color);
    doc.fontSize(9).font("Helvetica-Bold").fillColor(color)
       .text(f.hit ? "LISTED" : "CLEAN", fx, y + 8, { width: feedW, align: "center" });
    doc.fontSize(6).font("Helvetica").fillColor(C.text2)
       .text(f.label, fx, y + 20, { width: feedW, align: "center" });
  });

  y += 42;


  // Threat Signals

  y = checkY(y, 60);
  y = sectionHeader("Threat Signals", M, y, W);

  // Header row
  doc.fontSize(7).font("Helvetica-Bold").fillColor(C.text2)
     .text("CATEGORY", M + 8,       y, { width: 72, lineBreak: false })
     .text("DETAIL",   M + 84,      y, { width: W - 164, lineBreak: false })
     .text("SEVERITY", M + W - 72,  y, { width: 64, align: "right" });
  y += 11;
  doc.rect(M, y, W, 1).fill(C.border);
  y += 5;

  signals.forEach(sig => {
    y = checkY(y, 17);
    const color = SEV_COLOR[sig.severity] || C.text2;
    doc.rect(M, y + 1, 3, 11).fill(color);
    doc.fontSize(7.5).font("Helvetica-Bold").fillColor(color)
       .text(safe(sig.category), M + 8, y + 2, { width: 70, lineBreak: false });
    doc.fontSize(7.5).font("Helvetica").fillColor(C.white)
       .text(safe(sig.detail), M + 84, y + 2, { width: W - 164, lineBreak: false, ellipsis: true });
    doc.fontSize(7.5).font("Helvetica-Bold").fillColor(color)
       .text(sig.severity.toUpperCase(), M, y + 2, { width: W - 4, align: "right" });
    y += 15;
  });

  y += 8;

  // Shodan Intelligence
  if (intel.openPorts?.length || intel.vulns?.length || intel.shodanTags?.length) {
    y = checkY(y, 70);
    y = sectionHeader("Shodan Intelligence", M, y, W);

    if (intel.shodanTags?.length) {
      y = kvRow("Tags",       intel.shodanTags.join(", "), M, y, W, C.accent);
    }
    if (intel.openPorts?.length) {
      y = kvRow("Open Ports", intel.openPorts.join(", "),  M, y, W, C.white);
    }
    if (intel.vulns?.length) {
      y = kvRow("CVEs",
                `${intel.vulns.length} found: ${intel.vulns.slice(0,4).join(", ")}${intel.vulns.length > 4 ? "..." : ""}`,
                M, y, W, C.critical);
    }
    y += 8;
  }


  // VirusTotal

  if (intel.virusTotal) {
    y = checkY(y, 72);
    y = sectionHeader("VirusTotal Multi-Engine Analysis", M, y, W);

    const vt      = intel.virusTotal;
    const vtItems = [
      { label: "Malicious",     val: vt.malicious,  color: C.critical },
      { label: "Suspicious",    val: vt.suspicious, color: C.high     },
      { label: "Harmless",      val: vt.harmless,   color: C.low      },
      { label: "Total Engines", val: vt.total,      color: C.text2    }
    ];
    const vtW = (W - 9) / 4;
    vtItems.forEach((item, i) => {
      const vx = M + i * (vtW + 3);
      doc.rect(vx, y, vtW, 36).fill(C.card);
      doc.fontSize(20).font("Helvetica-Bold").fillColor(item.color)
         .text(String(item.val), vx, y + 4, { width: vtW, align: "center" });
      doc.fontSize(7).font("Helvetica").fillColor(C.text2)
         .text(item.label, vx, y + 26, { width: vtW, align: "center" });
    });
    y += 44;

    // Malicious % bar
    const pct = vt.total > 0 ? vt.malicious / vt.total : 0;
    doc.rect(M, y, W, 5).fill(C.card);
    if (pct > 0) doc.rect(M, y, Math.round(W * pct), 5).fill(C.critical);
    doc.fontSize(7).font("Helvetica").fillColor(C.text2)
       .text(`${Math.round(pct * 100)}% of engines flagged malicious`, M, y + 8);
    y += 22;
  }


  // OTX Pulses
  if (feeds.otx?.pulseNames?.length) {
    y = checkY(y, 60);
    y = sectionHeader("AlienVault OTX Threat Pulses", M, y, W);
    feeds.otx.pulseNames.slice(0, 6).forEach(name => {
      y = checkY(y, 16);
      doc.rect(M, y + 1, 3, 10).fill(C.medium);
      doc.fontSize(7.5).font("Helvetica").fillColor(C.white)
         .text(safe(name), M + 10, y + 2, { width: W - 18, lineBreak: false, ellipsis: true });
      y += 14;
    });
    y += 6;
  }


  // FOOTER — rendered on every page using bufferedPageRange

  // const range = doc.bufferedPageRange();
  // for (let i = 0; i < range.count; i++) {
  //   doc.switchToPage(range.start + i);
  //   doc.rect(0, pageH - FOOTER_H, pageW, FOOTER_H).fill(C.dark);
  //   // doc.fontSize(7).font("Helvetica").fillColor(C.text2)
  //   //    .text("Generated by IPShield — IP Risk Intelligence Platform",
  //   //          M, pageH - FOOTER_H + 6, { width: W * 0.55, lineBreak: false });
  //   // doc.fontSize(7).fillColor(C.text2)
  //   //    .text(`${safe(d.ip)}  |  Page ${i + 1} of ${range.count}  |  ipshield-nk0w.onrender.com`,
  //   //          M, pageH - FOOTER_H + 6, { align: "right", width: W });
  //   doc.fontSize(6).fillColor(C.text2)
  //      .text("This report is auto-generated. Verify findings with a qualified security analyst before taking action.",
  //            M, pageH - FOOTER_H + 18, { width: W });
  // }
}

module.exports = router;