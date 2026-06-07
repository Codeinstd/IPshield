
const express = require("express");
const router  = express.Router();
const spec    = require("../config/openapi"); // reuse the full spec
const { buildSwaggerHTML } = require("./docs.v1.routes");

// Override servers to point to v2
const v2spec = {
  ...spec,
  info: {
    ...spec.info,
    title:   "IPShield API — v2 (Latest)",
    version: "2.2.0",
    description: spec.info.description + `

---
## What's new in v2
| Feature | v1 | v2 |
|---------|----|----|
| IP Scoring | ✓ | ✓ |
| WHOIS / rDNS | ✓ | ✓ |
| Watchlist | ✓ | ✓ |
| Audit Log | ✓ | ✓ |
| SIEM Webhook | ✓ | ✓ |
| PDF Reports | ✓ | ✓ |
| **Blacklist Management** | ✗ | ✓ |
| **Case Management** | ✗ | ✓ |
`
  },
  servers: [
    { url: "/api/v2",                            description: "v2 Latest" },
    { url: "/api",                               description: "Default (routes to v2)" },
    { url: "https://ipshield.live/api/v2",       description: "Production v2" }
  ]
};

// Raw spec 
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json(v2spec);
});

// Swagger UI 
router.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(buildSwaggerHTML(v2spec, "v2", "#00d9ff"));
});

module.exports = router;