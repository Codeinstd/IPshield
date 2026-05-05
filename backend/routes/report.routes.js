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
      const doc = new PDFDocument({
        margin:        50,
        size:          "A4",
        autoFirstPage: true,
        bufferPages:   true
      });

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

// ── High contrast color palette 
// Dark areas use dark bg + white text
// Content areas use white bg + dark text for maximum readability
const C = {
  // Dark UI elements (header, banner, section titles)
  headerBg:   "#0d1117",
  sectionBg:  "#1a2332",
  // Content areas — WHITE background for readability
  rowBg:      "#ffffff",
  rowBgAlt:   "#f5f7fa",
  // Text
  textDark:   "#1a2332",   // main content text (on white bg)
  textMid:    "#4a6278",   // labels (on white bg)
  textLight:  "#ffffff",   // text on dark backgrounds
  textMuted:  "#8fa8bc",   // secondary on white
  // Accents
  accent:     "#0099bb",   // darker cyan — readable on white
  accentBg:   "#e8f7fb",
  // Risk colors
  critical:   "#cc1133",
  criticalBg: "#fde8ec",
  high:       "#cc5500",
  highBg:     "#fdf0e8",
  medium:     "#996600",
  mediumBg:   "#fdf8e8",
  low:        "#006633",
  lowBg:      "#e8f8ee",
  // Borders
  border:     "#dde3ea",
  borderDark: "#2a3a4a"
};

const RISK_BG    = { CRITICAL: C.criticalBg, HIGH: C.highBg,  MEDIUM: C.mediumBg,  LOW: C.lowBg  };
const RISK_COLOR = { CRITICAL: C.critical,   HIGH: C.high,    MEDIUM: C.medium,    LOW: C.low    };
const SEV_COLOR  = { critical: C.critical,   high: C.high,    medium: C.medium,    low: C.low,   info: C.accent };
const SEV_BG     = { critical: C.criticalBg, high: C.highBg,  medium: C.mediumBg,  low: C.lowBg, info: C.accentBg };

function safe(val) {
  if (val === null || val === undefined) return "N/A";
  const s = String(val).replace(/[^\x20-\x7E]/g, "").trim();
  return s || "N/A";
}

function has(val) {
  if (val === null || val === undefined) return false;
  const s = String(val).trim();
  return s !== "" && s !== "N/A" && s !== "-";
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
  const riskBg    = RISK_BG[riskLevel]    || C.lowBg;
  const pageW     = doc.page.width;
  const pageH     = doc.page.height;
  const M         = 48;
  const W         = pageW - M * 2;
  const FOOTER_H  = 40;
  const MAX_Y     = pageH - FOOTER_H - 10;

  // ── Helpers 
  function checkY(y, needed) {
    if (y + needed > MAX_Y) { doc.addPage(); return M; }
    return y;
  }

  // Section header — dark background, white text
  function sectionHeader(title, x, y, w) {
    doc.rect(x, y, w, 20).fill(C.sectionBg);
    doc.fontSize(8.5).font("Helvetica-Bold").fillColor(C.textLight)
       .text(title.toUpperCase(), x + 10, y + 6, { width: w - 20, lineBreak: false });
    return y + 24;
  }

  // KV row — alternating white/light grey, dark text — maximum readability
  function kvRow(label, value, x, y, w, valColor, isAlt) {
  const bg = isAlt ? C.rowBgAlt : C.rowBg;

  const lw = 130;
  const vw = w - lw - 20;

  const display = has(value) ? safe(value) : "N/A";
  const vColor  = has(value) ? (valColor || C.textDark) : C.textMuted;

  const labelOptions = { width: lw, lineGap: 0 };
  const valueOptions = { width: vw, lineGap: 0 };

  // Calculate dynamic height
  const labelHeight = doc.heightOfString(safe(label), labelOptions);
  const valueHeight = doc.heightOfString(display, valueOptions);

  const rowHeight = Math.max(labelHeight, valueHeight) + 6;

  // Background
  doc.rect(x, y, w, rowHeight).fill(bg);

  // Accent bar
  doc.rect(x, y, 2, rowHeight).fill(C.sectionBg);

  // Label
  doc.fontSize(8).font("Helvetica").fillColor(C.textMid)
     .text(safe(label), x + 10, y + 3, labelOptions);

  // Value (NOW WRAPS ✨)
  doc.fontSize(8).font("Helvetica-Bold").fillColor(vColor)
     .text(display, x + 10 + lw, y + 3, valueOptions);

  return y + rowHeight + 2;
}

 
  // HEADER — dark bar
  doc.rect(0, 0, pageW, 64).fill(C.headerBg);

  // Logo
  doc.fontSize(24).font("Helvetica-Bold")
     .fillColor("#ffffff").text("IP", M, 18, { continued: true })
     .fillColor("#00d9ff").text("Shield");
  doc.fontSize(9).font("Helvetica").fillColor("#8fa8bc")
     .text("Threat Intelligence Report", M, 44);
  doc.fontSize(8).fillColor("#8fa8bc")
     .text(new Date().toUTCString(), M, 44, { align: "right", width: W });

  // ── Risk banner 
  // Coloured banner with IP and risk
  doc.rect(0, 64, pageW, 50).fill(riskColor);

  doc.fontSize(10).font("Helvetica-Bold").fillColor("#ffffff")
     .text(`${riskLevel} RISK`, M, 73, { continued: true, width: 120 });
  doc.fontSize(10).font("Helvetica").fillColor("rgba(255,255,255,0.8)")
     .text(`  |  Recommended Action: ${safe(d.action)}`, { continued: false });

  doc.fontSize(22).font("Helvetica-Bold").fillColor("#ffffff")
     .text(safe(d.ip), M, 70, { align: "right", width: W });

  // doc.fontSize(8).font("Helvetica").fillColor("rgba(255,255,255,0.7)")
  //    .text(
  //      `Generated: ${d.meta?.scoredAt ? new Date(d.meta.scoredAt).toUTCString() : new Date().toUTCString()}` +
  //      (d.meta?.processingMs ? `   |   ${d.meta.processingMs}ms${d.meta.cached ? " (cached)" : ""}` : ""),
  //      M, 95, { width: W }
  //    );

  // ── Score strip — white background 
  let y = 126;
  doc.rect(M, y, W, 56).fill(C.rowBg).stroke(C.border).lineWidth(0.5);

  // Score ring (solid circle outline)
  doc.circle(M + 38, y + 28, 24).stroke(riskColor).lineWidth(3);
  doc.fontSize(18).font("Helvetica-Bold").fillColor(riskColor)
     .text(String(score), M + 14, y + 17, { width: 48, align: "center" });
  doc.fontSize(8).font("Helvetica").fillColor(C.textMid)
     .text("/100", M + 14, y + 37, { width: 48, align: "center" });

  // Score meta text — dark on white
  doc.fontSize(11).font("Helvetica-Bold").fillColor(C.textDark)
     .text("ABUSE CONFIDENCE SCORE", M + 76, y + 10);

  const boost = d.scoreBoost > 0
    ? `Base: ${d.baseScore}  +  Threat feed boost: +${d.scoreBoost}`
    : "Source: AbuseIPDB";
  doc.fontSize(8.5).font("Helvetica").fillColor(C.textMid)
     .text(boost, M + 76, y + 26);

  doc.fontSize(8).font("Helvetica").fillColor(C.textMuted)
     .text(`Risk Level: ${riskLevel}   |   Action: ${safe(d.action)}`, M + 76, y + 40);

  y += 70;


  // TWO COLUMNS: Geolocation | Network
  y = checkY(y, 140);
  const colW = (W - 12) / 2;
  const lx   = M;
  const rx   = M + colW + 12;

  let ly = sectionHeader("GEOLOCATION", lx, y, colW);
  let ry = sectionHeader("NETWORK", rx, y, colW);

  ly = kvRow("Country",   geo.country,  lx, ly, colW, C.textDark, false);
  ly = kvRow("Region",    geo.region,   lx, ly, colW, C.textDark, true);
  ly = kvRow("City",      geo.city,     lx, ly, colW, C.textDark, false);
  ly = kvRow("Timezone",  geo.timezone, lx, ly, colW, C.textDark, true);
  ly = kvRow("Latitude",  geo.lat,      lx, ly, colW, C.textDark, false);
  ly = kvRow("Longitude", geo.lon,      lx, ly, colW, C.textDark, true);

  if (!has(geo.country) && !has(geo.city)) {
    doc.rect(lx, ly, colW, 20).fill(C.rowBgAlt);
    doc.fontSize(8).font("Helvetica").fillColor(C.textMuted)
       .text("Geo data unavailable for this IP", lx + 10, ly + 6, { width: colW - 20 });
    ly += 22;
  }

  ry = kvRow("ISP",        network.isp,  rx, ry, colW, C.textDark,  false);
  ry = kvRow("ASN",        network.asn,  rx, ry, colW, C.textDark,  true);
  ry = kvRow("Type",       network.type, rx, ry, colW, C.textDark,  false);
  ry = kvRow("Datacenter", intel.isDatacenter ? "Yes" : "No", rx, ry, colW,
             intel.isDatacenter ? C.medium : C.textDark, true);
  ry = kvRow("Proxy",      intel.isProxy ? "Detected" : "No", rx, ry, colW,
             intel.isProxy ? C.high : C.textDark, false);
  ry = kvRow("Tor",        intel.isTor   ? "Exit Node" : "No", rx, ry, colW,
             intel.isTor ? C.critical : C.textDark, true);
  ry = kvRow("Velocity",   intel.velocity || "LOW", rx, ry, colW,
             intel.velocity === "HIGH" ? C.critical
           : intel.velocity === "MEDIUM" ? C.medium : C.low, false);

  y = Math.max(ly, ry) + 16;


  // TWO COLUMNS: Reverse DNS | WHOIS
  y = checkY(y, 130);

  ly = sectionHeader("REVERSE DNS (PTR)", lx, y, colW);
  ry = sectionHeader("WHOIS / RDAP", rx, y, colW);

  // rDNS
  if (rdns.private) {
    doc.rect(lx, ly, colW, 14).fill(C.rowBg);
    doc.fontSize(8).font("Helvetica").fillColor(C.textMuted)
       .text("Private IP - no PTR record", lx + 10, ly + 3); ly += 15;
  } else if (has(rdns.primary)) {
    // PTR value — may be long
    doc.rect(lx, ly, colW, 14).fill(C.rowBg);
    doc.rect(lx, ly, 2, 14).fill(C.sectionBg);
    doc.fontSize(8).font("Helvetica").fillColor(C.textMid)
       .text("PTR Record", lx + 10, ly + 3, { width: 90, lineBreak: false });
    doc.fontSize(8).font("Helvetica-Bold").fillColor(C.accent)
       .text(safe(rdns.primary), lx + 104, ly + 3, {
        width: colW - 114
      });
    ly += 15;

    const fcLabel = rdns.fcrdns === true  ? "Verified"
                  : rdns.fcrdns === false ? "Mismatch"
                  : "N/A";
    const fcColor = rdns.fcrdns === true  ? C.low
                  : rdns.fcrdns === false ? C.medium : C.textMuted;
    ly = kvRow("FCrDNS Check", fcLabel, lx, ly, colW, fcColor, true);

    if ((rdns.hostnames?.length || 0) > 1) {
      ly = kvRow("Additional PTRs", `${rdns.hostnames.length - 1} more`, lx, ly, colW, C.textDark, false);
    }
  } else {
    doc.rect(lx, ly, colW, 14).fill(C.rowBgAlt);
    doc.fontSize(8).font("Helvetica").fillColor(C.textMuted)
       .text("No PTR record found", lx + 10, ly + 3); ly += 15;
  }

  // WHOIS
  if (whois) {
    ry = kvRow("Organisation", whois.orgName,    rx, ry, colW, C.textDark,  false);
    ry = kvRow("Org ID",       whois.orgId,      rx, ry, colW, C.textDark,  true);
    ry = kvRow("Country",      whois.country,    rx, ry, colW, C.textDark,  false);
    ry = kvRow("Abuse Email",  whois.abuseEmail, rx, ry, colW,
               has(whois.abuseEmail) ? C.accent : C.textMuted, true);
    ry = kvRow("CIDR Range",   whois.cidr,       rx, ry, colW, C.textDark,  false);
    const regDate = has(whois.registered)
      ? new Date(whois.registered).toLocaleDateString("en-GB") : null;
    ry = kvRow("Registered",   regDate,          rx, ry, colW, C.textDark,  true);
    const ageColor = whois.agedays != null
      ? (whois.agedays < 30 ? C.critical : whois.agedays < 90 ? C.medium : C.textDark)
      : C.textMuted;
    ry = kvRow("Network Age",
               whois.agedays != null ? `${whois.agedays} days` : null,
               rx, ry, colW, ageColor, false);
  } else {
    doc.rect(rx, ry, colW, 14).fill(C.rowBgAlt);
    doc.fontSize(8).font("Helvetica").fillColor(C.textMuted)
       .text("WHOIS data unavailable", rx + 10, ry + 3); ry += 15;
  }

  y = Math.max(ly, ry) + 16;


  // Threat Feed Analysis
  y = checkY(y, 70);
  y = sectionHeader("THREAT FEED ANALYSIS", M, y, W);

  const feedItems = [
    { label: "Feodo Tracker (C2)",    hit: !!feeds.feodo           },
    { label: "Spamhaus DROP",         hit: !!feeds.spamhaus        },
    { label: "Emerging Threats",      hit: !!feeds.emergingThreats },
    { label: `OTX (${feeds.otx?.pulseCount || 0} pulses)`, hit: (feeds.otx?.pulseCount || 0) > 0 }
  ];

  const feedW = (W - 9) / 4;
  feedItems.forEach((f, i) => {
    const fx    = M + i * (feedW + 3);
    const bg    = f.hit ? C.criticalBg : C.lowBg;
    const color = f.hit ? C.critical   : C.low;
    doc.rect(fx, y, feedW, 32).fill(bg).stroke(color).lineWidth(0.5);
    doc.fontSize(10).font("Helvetica-Bold").fillColor(color)
       .text(f.hit ? "LISTED" : "CLEAN", fx, y + 6, { width: feedW, align: "center" });
    doc.fontSize(6.5).font("Helvetica").fillColor(C.textMid)
       .text(f.label, fx, y + 20, { width: feedW, align: "center" });
  });

  y += 44;


  // Threat Signals
  y = checkY(y, 60);
  y = sectionHeader("THREAT SIGNALS", M, y, W);

  // Column headers row
  doc.rect(M, y, W, 14).fill(C.rowBgAlt);
  doc.fontSize(7.5).font("Helvetica-Bold").fillColor(C.textMid)
     .text("CATEGORY", M + 10,      y + 3, { width: 75,       lineBreak: false })
     .text("DETAIL",   M + 90,      y + 3, { width: W - 170,  lineBreak: false })
     .text("SEVERITY", M + W - 75,  y + 3, { width: 70, align: "right" });
  y += 15;

  signals.forEach((sig, idx) => {
    y = checkY(y, 18);
    const color = SEV_COLOR[sig.severity] || C.textMid;
    const bg    = idx % 2 === 0 ? C.rowBg : C.rowBgAlt;

    doc.rect(M, y, W, 16).fill(bg);
    doc.rect(M, y, 3, 16).fill(color);

    doc.fontSize(7.5).font("Helvetica-Bold").fillColor(color)
       .text(safe(sig.category), M + 8, y + 4, { width: 78, lineBreak: false });
    doc.fontSize(7.5).font("Helvetica").fillColor(C.textDark)
       const detailHeight = doc.heightOfString(safe(sig.detail), {
  width: W - 168
});

const rowHeight = Math.max(16, detailHeight + 6);

doc.rect(M, y, W, rowHeight).fill(bg);
doc.rect(M, y, 3, rowHeight).fill(color);

doc.text(safe(sig.detail), M + 90, y + 4, {
  width: W - 168
});

y += rowHeight + 1;

    // Severity badge
    const sevBg = SEV_BG[sig.severity] || C.accentBg;
    doc.rect(M + W - 72, y + 3, 68, 11).fill(sevBg);
    doc.fontSize(7).font("Helvetica-Bold").fillColor(color)
       .text(sig.severity.toUpperCase(), M + W - 72, y + 5, { width: 68, align: "center" });

    y += 17;
  });

  y += 16;


  // Shodan Intelligence
  if (intel.openPorts?.length || intel.vulns?.length || intel.shodanTags?.length) {
    y = checkY(y, 80);
    y = sectionHeader("SHODAN INTELLIGENCE", M, y, W);

    if (intel.shodanTags?.length) {
      y = kvRow("Tags",       intel.shodanTags.join(", "), M, y, W, C.accent,   false);
    }
    if (intel.openPorts?.length) {
      y = kvRow("Open Ports", intel.openPorts.join(", "),  M, y, W, C.textDark, true);
    }
    if (intel.vulns?.length) {
      y = kvRow("CVEs Found",
                `${intel.vulns.length}: ${intel.vulns.slice(0,4).join(", ")}${intel.vulns.length > 4 ? "..." : ""}`,
                M, y, W, C.critical, false);
    }
    y += 16;
  }


  // VirusTotal
  if (intel.virusTotal) {
    y = checkY(y, 80);
    y = sectionHeader("VIRUSTOTAL MULTI-ENGINE ANALYSIS", M, y, W);

    const vt = intel.virusTotal;
    const vtItems = [
      { label: "Malicious",     val: vt.malicious,  color: C.critical, bg: C.criticalBg },
      { label: "Suspicious",    val: vt.suspicious, color: C.high,     bg: C.highBg     },
      { label: "Harmless",      val: vt.harmless,   color: C.low,      bg: C.lowBg      },
      { label: "Total Engines", val: vt.total,      color: C.textMid,  bg: C.rowBgAlt   }
    ];

    const vtW = (W - 9) / 4;
    vtItems.forEach((item, i) => {
      const vx = M + i * (vtW + 3);
      doc.rect(vx, y, vtW, 40).fill(item.bg).stroke(C.border).lineWidth(0.5);
      doc.fontSize(22).font("Helvetica-Bold").fillColor(item.color)
         .text(String(item.val), vx, y + 6, { width: vtW, align: "center" });
      doc.fontSize(7).font("Helvetica").fillColor(C.textMid)
         .text(item.label, vx, y + 29, { width: vtW, align: "center" });
    });

    y += 48;

    // Malicious percentage bar
    const pct = vt.total > 0 ? vt.malicious / vt.total : 0;
    doc.rect(M, y, W, 8).fill(C.lowBg).stroke(C.border).lineWidth(0.5);
    if (pct > 0) doc.rect(M, y, Math.round(W * pct), 8).fill(C.critical);
    doc.fontSize(7.5).font("Helvetica").fillColor(C.textMid)
       .text(`${Math.round(pct * 100)}% of engines flagged as malicious`, M, y + 11);
    y += 24;
  }


  // OTX Pulses
  if (feeds.otx?.pulseNames?.length) {
    y = checkY(y, 60);
    y = sectionHeader("ALIENVAULT OTX THREAT PULSES", M, y, W);
    feeds.otx.pulseNames.slice(0, 6).forEach((name, i) => {
      y = checkY(y, 16);
      doc.rect(M, y, W, 15).fill(i % 2 === 0 ? C.rowBg : C.rowBgAlt);
      doc.rect(M, y, 3, 15).fill(C.medium);
      doc.fontSize(7.5).font("Helvetica").fillColor(C.textDark)
         .text(safe(name), M + 10, y + 4, { width: W - 20, lineBreak: false, ellipsis: true });
      y += 16;
    });
    y += 8;
  }


  // FOOTER — rendered on every page
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.rect(0, pageH - FOOTER_H, pageW, FOOTER_H).fill(C.headerBg);
    doc.fontSize(6).font("Helvetica").fillColor("#8fa8bc")
       .text("Generated by IPShield - This report is auto-generated. Verify all findings with a qualified security analyst before taking action.",
             M, pageH - FOOTER_H + 8, { width: W, });
  }
}

module.exports = router;