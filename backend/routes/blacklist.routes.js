
const express = require("express");
const router  = express.Router();
const { body, param, query, validationResult } = require("express-validator");
const {
  listBlacklist, addToBlacklist, updateBlacklist,
  deleteFromBlacklist, bulkDelete, getAllActiveIPs, getStats
} = require("../store/blacklist.store");
const logger = require("../utils/logger");

const SEVERITIES = ["CRITICAL","HIGH","MEDIUM","LOW"];
const CATEGORIES = ["Malware","Botnet","C2","Scanner","Spam","Proxy","Tor","Phishing","Brute Force","Manual","Other"];

// ── Validation helpers 
const ipValidation = body("ip")
  .trim().notEmpty().withMessage("IP is required")
  .custom(ip => {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
      throw new Error("Invalid IP address format");
    return true;
  });

function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// ── GET /api/blacklist 
router.get("/", [
  query("severity").optional().isIn(SEVERITIES),
  query("status").optional().isIn(["active","expired","all"]),
  query("q").optional().trim().isLength({ max: 100 }),
  query("limit").optional().isInt({ min: 1, max: 500 }),
  query("offset").optional().isInt({ min: 0 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

  const { severity, status, q, limit = 200, offset = 0 } = req.query;
  const result = listBlacklist({ severity, status, q, limit: parseInt(limit), offset: parseInt(offset) });
  const stats  = getStats();

  res.json({ ...result, stats });
});

// ── GET /api/blacklist/stats 
router.get("/stats", (req, res) => {
  res.json(getStats());
});

// ── GET /api/blacklist/export 
router.get("/export", [
  query("fmt").optional().isIn(["txt","csv","json","nginx","iptables","cisco","paloalto","windows"])
], (req, res) => {
  const fmt     = req.query.fmt || "txt";
  const entries = getAllActiveIPs();
  const ips     = entries.map(e => e.ip);
  const ts      = new Date().toISOString();

  logger.info(`Blacklist export: ${fmt}, ${ips.length} IPs`);

  switch (fmt) {
    case "txt":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.txt"`);
      return res.send(
        `# IPShield Blacklist Export\n# Generated: ${ts}\n# Total: ${ips.length} IPs\n\n` +
        ips.join("\n")
      );

    case "csv": {
      const all = listBlacklist({ status: "active", limit: 10000 }).entries;
      const headers = ["IP","Severity","Category","Reason","Added By","Added At","Expires At","Tags"];
      const rows    = all.map(e => [
        e.ip, e.severity, e.category || "", e.reason || "",
        e.added_by || "", e.added_at || "", e.expires_at || "",
        (e.tags || []).join(";")
      ]);
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.csv"`);
      return res.send([headers, ...rows].map(r => r.map(v => `"${v}"`).join(",")).join("\n"));
    }

    case "json": {
      const all = listBlacklist({ status: "active", limit: 10000 }).entries;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.json"`);
      return res.json({ generated: ts, total: all.length, blacklist: all });
    }

    case "nginx":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.conf"`);
      return res.send(
        `# IPShield Nginx Blacklist — ${ts}\n# ${ips.length} IPs\n\ngeo $ipshield_blocked {\n  default 0;\n` +
        ips.map(ip => `  ${ip} 1;`).join("\n") +
        `\n}\n\n# In server block: if ($ipshield_blocked) { return 403; }`
      );

    case "iptables":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.sh"`);
      return res.send(
        `#!/bin/bash\n# IPShield iptables Blacklist — ${ts}\n# ${ips.length} IPs\n\n` +
        `# Flush existing IPShield chain\niptables -F IPSHIELD 2>/dev/null || iptables -N IPSHIELD\niptables -I INPUT -j IPSHIELD\n\n` +
        ips.map(ip => `iptables -A IPSHIELD -s ${ip} -j DROP`).join("\n") +
        `\n\necho "✓ ${ips.length} IPs blocked"`
      );

    case "cisco":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.txt"`);
      return res.send(
        `! IPShield Cisco ACL — ${ts}\n! ${ips.length} IPs\n!\nip access-list extended IPSHIELD_BLOCK\n` +
        ips.map((ip, i) => ` ${(i + 1) * 10} deny ip host ${ip} any log`).join("\n") +
        `\n!\ninterface GigabitEthernet0/0\n ip access-group IPSHIELD_BLOCK in`
      );

    case "paloalto":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.txt"`);
      return res.send(
        `# IPShield Palo Alto — ${ts}\n` +
        ips.map(ip => `set address "IPSHIELD_${ip.replace(/\./g,"_")}" type ip-netmask ${ip}/32`).join("\n") +
        `\nset address-group IPSHIELD_BLOCK static [ ${ips.map(ip => `IPSHIELD_${ip.replace(/\./g,"_")}`).join(" ")} ]` +
        `\nset security policy deny-ipshield from any to any source IPSHIELD_BLOCK action deny`
      );

    case "windows":
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="ipshield-blacklist-${Date.now()}.ps1"`);
      return res.send(
        `# IPShield Windows Firewall — ${ts}\n# Run as Administrator\n\n` +
        ips.map((ip, i) =>
          `New-NetFirewallRule -DisplayName "IPShield_${i + 1}" -Direction Inbound -RemoteAddress ${ip} -Action Block`
        ).join("\n") +
        `\n\nWrite-Host "✓ ${ips.length} IPs blocked"`
      );

    default:
      return res.status(400).json({ error: "Unknown format" });
  }
});

// ── POST /api/blacklist 
router.post("/", [
  ipValidation,
  body("severity").optional().isIn(SEVERITIES),
  body("category").optional().trim().isLength({ max: 100 }),
  body("reason").optional().trim().isLength({ max: 500 }),
  body("added_by").optional().trim().isLength({ max: 100 }),
  body("expires_at").optional().isISO8601().withMessage("expires_at must be ISO date"),
  body("tags").optional().isArray()
], handleValidation, (req, res) => {
  const { ip, severity = "HIGH", category = "", reason = "", added_by = "analyst", expires_at, tags = [] } = req.body;
  const entry = addToBlacklist({ ip, severity, category, reason, added_by, expires_at, tags });
  if (!entry) return res.status(500).json({ error: "Failed to add entry" });
  logger.info(`Blacklist: added ${ip} (${severity})`);
  res.status(201).json({ message: "Added to blacklist", entry });
});

// ── PUT /api/blacklist/:id 
router.put("/:id", [
  param("id").isInt({ min: 1 }),
  body("severity").optional().isIn(SEVERITIES),
  body("category").optional().trim().isLength({ max: 100 }),
  body("reason").optional().trim().isLength({ max: 500 }),
  body("expires_at").optional({ nullable: true }).isISO8601(),
  body("tags").optional().isArray()
], handleValidation, (req, res) => {
  const id    = parseInt(req.params.id);
  const entry = updateBlacklist(id, req.body);
  if (!entry) return res.status(404).json({ error: "Entry not found" });
  logger.info(`Blacklist: updated #${id}`);
  res.json({ message: "Updated", entry });
});

// ── DELETE /api/blacklist/bulk 
router.delete("/bulk", [
  body("ids").isArray({ min: 1 }).withMessage("ids array required"),
  body("ids.*").isInt({ min: 1 })
], handleValidation, (req, res) => {
  const count = bulkDelete(req.body.ids.map(Number));
  logger.info(`Blacklist: bulk deleted ${count} entries`);
  res.json({ message: `Deleted ${count} entries`, count });
});

// ── DELETE /api/blacklist/:id
router.delete("/:id", [
  param("id").isInt({ min: 1 })
], handleValidation, (req, res) => {
  const ok = deleteFromBlacklist(parseInt(req.params.id));
  if (!ok) return res.status(404).json({ error: "Entry not found" });
  logger.info(`Blacklist: deleted #${req.params.id}`);
  res.json({ message: "Deleted" });
});

module.exports = router;