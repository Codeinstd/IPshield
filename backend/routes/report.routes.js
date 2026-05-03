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
      const cached = req.query.cached !== "false"; // use cache by default
      logger.info(`PDF report requested for ${ip}`);

      const data = await getFullIntel(ip, { bypassCache: !cached });

      // Generate PDF
      const PDFDocument = require("pdfkit");
      const doc = new PDFDocument({ margin: 50, size: "A4" });

      // Stream directly to response
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

// ── PDF builder 
function buildPDF(doc, d) {
  const score     = d.score     ?? 0;
  const riskLevel = d.riskLevel ?? "LOW";
  const geo       = d.geo       ?? {};
  const network   = d.network   ?? {};
  const intel     = d.intelligence ?? {};
  const signals   = d.signals   ?? [];
  const feeds     = d.threatFeeds ?? {};
  const rdns      = d.rdns      ?? {};
  const whois     = d.whois     ?? null;

  // Color palette
  const COLORS = {
    bg:       "#080c0f",
    accent:   "#00d9ff",
    critical: "#ff3355",
    high:     "#ff7700",
    medium:   "#ffcc00",
    low:      "#00e87c",
    text:     "#c9d8e8",
    text2:    "#6a8fa8",
    border:   "#1e2d3d",
    white:    "#ffffff",
    dark:     "#0d1117"
  };

  const riskColor = {
    CRITICAL: COLORS.critical,
    HIGH:     COLORS.high,
    MEDIUM:   COLORS.medium,
    LOW:      COLORS.low
  }[riskLevel] || COLORS.low;

  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const margin = 50;
  const contentW = pageW - margin * 2;

  // ── Header bar 
  doc.rect(0, 0, pageW, 70).fill(COLORS.dark);
  doc.fontSize(20).font("Helvetica-Bold").fillColor(COLORS.white)
     .text("IP", margin, 24, { continued: true })
     .fillColor(COLORS.accent).text("Shield");
  doc.fontSize(10).font("Helvetica").fillColor(COLORS.text2)
     .text("Risk Intelligence Report", margin, 48);
  doc.fontSize(9).fillColor(COLORS.text2)
     .text(new Date().toUTCString(), 0, 48, { align: "right", width: pageW - margin });

  // ── Risk banner 
  doc.rect(0, 70, pageW, 48).fill(riskColor);
  doc.fontSize(14).font("Helvetica-Bold").fillColor("#000000")
     .text(`${riskLevel} RISK — ${d.action}`, margin, 82);
  doc.fontSize(24).font("Helvetica-Bold").fillColor("#000000")
     .text(d.ip, 0, 78, { align: "right", width: pageW - margin });

  let y = 138;

  // ── Score row 
  doc.rect(margin, y, contentW, 60).fill(COLORS.dark).stroke(COLORS.border);

  // Score circle (drawn as text block)
  doc.circle(margin + 40, y + 30, 26).fill(COLORS.bg).stroke(riskColor);
  doc.fontSize(18).font("Helvetica-Bold").fillColor(riskColor)
     .text(String(score), margin + 20, y + 19, { width: 40, align: "center" });
  doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2)
     .text("/100", margin + 20, y + 39, { width: 40, align: "center" });

  // Score meta
  doc.fontSize(11).font("Helvetica-Bold").fillColor(COLORS.white)
     .text("ABUSE CONFIDENCE SCORE", margin + 78, y + 10);
  if (d.scoreBoost > 0) {
    doc.fontSize(9).font("Helvetica").fillColor(COLORS.text2)
       .text(`Base score: ${d.baseScore} + Threat feed boost: +${d.scoreBoost}`, margin + 78, y + 27);
  }
  doc.fontSize(9).font("Helvetica").fillColor(COLORS.text2)
     .text(`Generated: ${new Date(d.meta?.scoredAt || Date.now()).toUTCString()}`, margin + 78, y + 42);

  if (d.meta?.processingMs) {
    doc.fontSize(9).fillColor(COLORS.text2)
       .text(`Processing time: ${d.meta.processingMs}ms${d.meta.cached ? " (cached)" : ""}`,
             0, y + 42, { align: "right", width: pageW - margin });
  }

  y += 76;

  // ── Two-column layout helper 
  function section(title, x, sy, w) {
    doc.rect(x, sy, w, 16).fill(COLORS.dark);
    doc.fontSize(8).font("Helvetica-Bold").fillColor(COLORS.accent)
       .text(`// ${title}`, x + 8, sy + 4);
    return sy + 20;
  }

  function row(label, value, x, ry, w, valueColor) {
    doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2)
       .text(label, x + 8, ry, { width: w * 0.4 });
    doc.fontSize(8).font("Helvetica").fillColor(valueColor || COLORS.white)
       .text(String(value || "—"), x + 8 + w * 0.4, ry, { width: w * 0.55, align: "right" });
    return ry + 13;
  }

  const colW    = (contentW - 12) / 2;
  const leftX   = margin;
  const rightX  = margin + colW + 12;

  // ── Geolocation column 
  let ly = section("GEOLOCATION", leftX, y, colW);
  ly = row("Country",  geo.country  || "—", leftX, ly, colW);
  ly = row("Region",   geo.region   || "—", leftX, ly, colW);
  ly = row("City",     geo.city     || "—", leftX, ly, colW);
  ly = row("Timezone", geo.timezone || "—", leftX, ly, colW);
  ly = row("Lat / Lon", geo.lat != null ? `${geo.lat}, ${geo.lon}` : "N/A", leftX, ly, colW);

  // ── Network column 
  let ry2 = section("NETWORK", rightX, y, colW);
  ry2 = row("ISP",       network.isp  || "—",              rightX, ry2, colW);
  ry2 = row("ASN",       network.asn  || "—",              rightX, ry2, colW);
  ry2 = row("Type",      network.type || "—",              rightX, ry2, colW);
  ry2 = row("Datacenter",intel.isDatacenter ? "Yes" : "No",rightX, ry2, colW, intel.isDatacenter ? COLORS.medium : COLORS.white);
  ry2 = row("Proxy",     intel.isProxy      ? "Detected" : "No", rightX, ry2, colW, intel.isProxy ? COLORS.high : COLORS.white);
  ry2 = row("Tor",       intel.isTor        ? "Exit Node" : "No", rightX, ry2, colW, intel.isTor ? COLORS.critical : COLORS.white);

  y = Math.max(ly, ry2) + 16;

  // ── Reverse DNS + WHOIS row 
  let ly2 = section("REVERSE DNS", leftX, y, colW);
  if (rdns.primary) {
    ly2 = row("PTR Record", rdns.primary, leftX, ly2, colW, COLORS.accent);
    ly2 = row("FCrDNS", rdns.fcrdns === true ? "Verified ✓" : rdns.fcrdns === false ? "Mismatch ⚠" : "N/A",
              leftX, ly2, colW, rdns.fcrdns === true ? COLORS.low : rdns.fcrdns === false ? COLORS.medium : COLORS.text2);
    if (rdns.hostnames?.length > 1) {
      ly2 = row("Other PTRs", `${rdns.hostnames.length - 1} more`, leftX, ly2, colW);
    }
  } else {
    doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2)
       .text("No PTR record found", leftX + 8, ly2);
    ly2 += 13;
  }

  let ry3 = section("WHOIS", rightX, y, colW);
  if (whois) {
    ry3 = row("Org Name",    whois.orgName    || "—", rightX, ry3, colW);
    ry3 = row("Country",     whois.country    || "—", rightX, ry3, colW);
    ry3 = row("Abuse Email", whois.abuseEmail || "—", rightX, ry3, colW, COLORS.accent);
    ry3 = row("Registered",  whois.registered ? new Date(whois.registered).toLocaleDateString() : "—", rightX, ry3, colW);
    ry3 = row("Age",         whois.agedays != null ? `${whois.agedays} days` : "—", rightX, ry3, colW,
              whois.agedays < 30 ? COLORS.critical : whois.agedays < 90 ? COLORS.medium : COLORS.white);
  } else {
    doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2)
       .text("WHOIS data unavailable", rightX + 8, ry3);
    ry3 += 13;
  }

  y = Math.max(ly2, ry3) + 16;

  // ── Threat feeds bar 
  let feedY = section("THREAT FEED ANALYSIS", leftX, y, contentW);
  const feedItems = [
    { label: "Feodo Tracker (C2)",    hit: feeds.feodo           },
    { label: "Spamhaus DROP",         hit: feeds.spamhaus        },
    { label: "Emerging Threats",      hit: feeds.emergingThreats },
    { label: `OTX (${feeds.otx?.pulseCount || 0} pulses)`, hit: (feeds.otx?.pulseCount || 0) > 0 }
  ];

  const feedColW = contentW / 4;
  feedItems.forEach((f, i) => {
    const fx = leftX + i * feedColW;
    const color = f.hit ? COLORS.critical : COLORS.low;
    doc.rect(fx, feedY, feedColW - 4, 20).fill(f.hit ? "rgba(255,51,85,0.1)" : COLORS.dark).stroke(color);
    doc.fontSize(7).font("Helvetica-Bold").fillColor(color)
       .text(f.hit ? "● LISTED" : "○ CLEAN", fx + 4, feedY + 4, { width: feedColW - 8 });
    doc.fontSize(6).font("Helvetica").fillColor(COLORS.text2)
       .text(f.label, fx + 4, feedY + 12, { width: feedColW - 8 });
  });

  y = feedY + 32;

  // ── Signals section 
  const sevColor = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low, info: COLORS.accent };

  y = section("THREAT SIGNALS", leftX, y, contentW);

  signals.slice(0, 12).forEach(sig => {
    // Check page overflow
    if (y > pageH - 100) { doc.addPage(); y = 50; }

    const color = sevColor[sig.severity] || COLORS.text2;
    doc.rect(leftX, y, 3, 12).fill(color);
    doc.fontSize(7).font("Helvetica-Bold").fillColor(color)
       .text(sig.category, leftX + 8, y + 2, { width: 60, continued: false });
    doc.fontSize(7).font("Helvetica").fillColor(COLORS.white)
       .text(sig.detail, leftX + 72, y + 2, { width: contentW - 130 });
    doc.fontSize(7).font("Helvetica-Bold").fillColor(color)
       .text(sig.severity.toUpperCase(), 0, y + 2, { align: "right", width: pageW - margin });
    y += 14;
  });

  y += 8;

  // ── Open ports + CVEs 
  if (intel.openPorts?.length || intel.vulns?.length || intel.shodanTags?.length) {
    if (y > pageH - 120) { doc.addPage(); y = 50; }

    y = section("SHODAN INTELLIGENCE", leftX, y, contentW);

    if (intel.openPorts?.length) {
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2).text("Open Ports:", leftX + 8, y);
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.white)
         .text(intel.openPorts.join(", "), leftX + 72, y, { width: contentW - 80 });
      y += 14;
    }
    if (intel.shodanTags?.length) {
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2).text("Tags:", leftX + 8, y);
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.accent)
         .text(intel.shodanTags.join(", "), leftX + 72, y);
      y += 14;
    }
    if (intel.vulns?.length) {
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.text2).text("CVEs:", leftX + 8, y);
      doc.fontSize(8).font("Helvetica").fillColor(COLORS.critical)
         .text(intel.vulns.slice(0, 6).join(", ") + (intel.vulns.length > 6 ? "…" : ""), leftX + 72, y);
      y += 14;
    }
    y += 8;
  }

  // ── VirusTotal 
  if (intel.virusTotal) {
    if (y > pageH - 100) { doc.addPage(); y = 50; }
    y = section("VIRUSTOTAL", leftX, y, contentW);
    const vt = intel.virusTotal;
    const vtItems = [
      { label: "Malicious",  val: vt.malicious,  color: COLORS.critical },
      { label: "Suspicious", val: vt.suspicious, color: COLORS.high },
      { label: "Harmless",   val: vt.harmless,   color: COLORS.low },
      { label: "Total Engines", val: vt.total,   color: COLORS.text2 }
    ];
    let vtX = leftX + 8;
    vtItems.forEach(item => {
      doc.fontSize(14).font("Helvetica-Bold").fillColor(item.color).text(String(item.val), vtX, y);
      doc.fontSize(7).font("Helvetica").fillColor(COLORS.text2).text(item.label, vtX, y + 16, { width: 70 });
      vtX += 80;
    });
    y += 36;
  }

  // ── Footer 
  const footerY = pageH - 36;
  doc.rect(0, footerY, pageW, 36).fill(COLORS.dark);
  doc.fontSize(7).font("Helvetica").fillColor(COLORS.text2)
     .text("Generated by IPShield — IP Risk Intelligence Platform", margin, footerY + 8);
  doc.fontSize(7).fillColor(COLORS.text2)
     .text(`ipshield-nk0w.onrender.com  ·  ${new Date().toISOString()}`, 0, footerY + 8, { align: "right", width: pageW - margin });
  doc.fontSize(7).fillColor(COLORS.text2)
     .text("This report is generated automatically and should be verified by a qualified security analyst before action.", margin, footerY + 20, { width: contentW });
}

module.exports = router;