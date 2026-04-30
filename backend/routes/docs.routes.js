const express = require("express");
const router  = express.Router();
const spec    = require("../config/openapi");

// ── Raw OpenAPI JSON spec ─────────────────────────────────────────────────────
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*"); // allow external tools like Postman
  res.json(spec);
});

// ── Swagger UI HTML ───────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  // We serve Swagger UI assets from cdnjs (on CSP allowlist)
  // and inline the spec as a JS variable to avoid fetch() CSP issues
  const specJson = JSON.stringify(spec);

  res.setHeader("Content-Type", "text/html");
  res.send(`<!DOCTYPE html>
<html lang="en">x
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPShield API Docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; background: #0d1117; font-family: 'Inter', 'JetBrains Mono', monospace; }

    /* Header bar */
    .docs-header {
      background: #0d1117;
      border-bottom: 1px solid #1e2d3d;
      padding: 14px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 1000;
    }
    .docs-logo { color: #c9d8e8; font-size: 18px; font-weight: 700; }
    .docs-logo span { color: #00d9ff; }
    .docs-back {
      color: #6a8fa8; font-size: 12px; text-decoration: none;
      border: 1px solid #1e2d3d; padding: 6px 14px; border-radius: 6px;
    }
    .docs-back:hover { color: #00d9ff; border-color: #00d9ff; }

    /* Swagger UI overrides to match IPShield dark theme */
    .swagger-ui { background: #080c0f; }
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info    { margin: 32px 0 24px; }
    .swagger-ui .info .title { color: #c9d8e8; font-family: inherit; }
    .swagger-ui .info p,
    .swagger-ui .info li   { color: #6a8fa8; }
    .swagger-ui .info code { background: #111820; color: #00d9ff; border-radius: 4px; }
    .swagger-ui .scheme-container { background: #0d1117; padding: 12px 0; box-shadow: none; border-bottom: 1px solid #1e2d3d; }
    .swagger-ui .opblock-tag { color: #c9d8e8; border-bottom: 1px solid #1e2d3d; }
    .swagger-ui .opblock-tag:hover { background: #111820; }
    .swagger-ui .opblock { background: #0d1117; border: 1px solid #1e2d3d; border-radius: 8px; margin-bottom: 8px; }
    .swagger-ui .opblock-summary { padding: 10px 16px; }
    .swagger-ui .opblock-summary-method { border-radius: 4px; font-family: inherit; font-size: 12px; font-weight: 700; min-width: 60px; text-align: center; }
    .swagger-ui .opblock-summary-description { color: #6a8fa8; font-family: inherit; }
    .swagger-ui .opblock.opblock-get    { border-color: rgba(0,232,124,0.3); }
    .swagger-ui .opblock.opblock-post   { border-color: rgba(255,204,0,0.3); }
    .swagger-ui .opblock.opblock-delete { border-color: rgba(255,51,85,0.3); }
    .swagger-ui .opblock.opblock-get    .opblock-summary-method { background: #00e87c; color: #000; }
    .swagger-ui .opblock.opblock-post   .opblock-summary-method { background: #ffcc00; color: #000; }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method { background: #ff3355; color: #fff; }
    .swagger-ui .opblock-body-description,
    .swagger-ui .opblock-description-wrapper p { color: #6a8fa8; }
    .swagger-ui .opblock-section-header { background: #111820; border-bottom: 1px solid #1e2d3d; }
    .swagger-ui .opblock-section-header h4 { color: #c9d8e8; }
    .swagger-ui table thead tr th { color: #6a8fa8; border-bottom: 1px solid #1e2d3d; }
    .swagger-ui .parameter__name { color: #00d9ff; }
    .swagger-ui .parameter__type { color: #6a8fa8; }
    .swagger-ui input[type=text],
    .swagger-ui textarea { background: #111820; border: 1px solid #1e2d3d; color: #c9d8e8; border-radius: 4px; }
    .swagger-ui input[type=text]:focus,
    .swagger-ui textarea:focus { border-color: #00d9ff; outline: none; }
    .swagger-ui .btn { font-family: inherit; border-radius: 6px; }
    .swagger-ui .btn.execute { background: #00d9ff; color: #000; border: none; font-weight: 700; }
    .swagger-ui .btn.execute:hover { background: #33e5ff; }
    .swagger-ui .btn.cancel { background: transparent; border: 1px solid #1e2d3d; color: #6a8fa8; }
    .swagger-ui .responses-table .response-col_status { color: #00e87c; }
    .swagger-ui .response-col_description { color: #c9d8e8; }
    .swagger-ui .microlight { background: #111820; border-radius: 6px; padding: 12px; }
    .swagger-ui .model-box { background: #111820; border-radius: 6px; }
    .swagger-ui .model { color: #c9d8e8; }
    .swagger-ui .prop-type { color: #00d9ff; }
    .swagger-ui section.models { border: 1px solid #1e2d3d; border-radius: 8px; }
    .swagger-ui section.models h4 { color: #c9d8e8; }
    .swagger-ui .auth-container { background: #0d1117; }
    .swagger-ui .auth-container h4 { color: #c9d8e8; }
    .swagger-ui .auth-container .wrapper { border-color: #1e2d3d; }
    .swagger-ui .dialog-ux .modal-ux { background: #0d1117; border: 1px solid #1e2d3d; border-radius: 12px; }
    .swagger-ui .dialog-ux .modal-ux-header { border-bottom: 1px solid #1e2d3d; }
    .swagger-ui .dialog-ux .modal-ux-header h3 { color: #c9d8e8; }
    .swagger-ui .dialog-ux .modal-ux-content p,
    .swagger-ui .dialog-ux .modal-ux-content label { color: #6a8fa8; }

    /* Authorize button */
    .swagger-ui .authorization__btn { color: #00d9ff; border-color: #00d9ff; }
    .swagger-ui .unlocked { fill: #6a8fa8; }
    .swagger-ui .locked   { fill: #00d9ff; }

    #swagger-ui { max-width: 1200px; margin: 0 auto; padding: 0 24px 48px; }
  </style>
</head>
<body>
  <div class="docs-header">
    <div class="docs-logo">IP<span>Shield</span> <span style="font-size:13px;color:#3d5a72;font-weight:400;">API Documentation</span></div>
    <a href="/" class="docs-back">← Back to App</a>
  </div>

  <div id="swagger-ui"></div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-standalone-preset.min.js"></script>
  <script>
    // Inline spec — no fetch needed, avoids CSP issues
    const spec = ${specJson};

    SwaggerUIBundle({
      spec,
      dom_id:                   "#swagger-ui",
      deepLinking:              true,
      presets:                  [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      plugins:                  [SwaggerUIBundle.plugins.DownloadUrl],
      layout:                   "StandaloneLayout",
      persistAuthorization:     true,
      displayRequestDuration:   true,
      defaultModelsExpandDepth: 1,
      defaultModelExpandDepth:  1,
      tryItOutEnabled:          true,
      requestInterceptor: (req) => {
        // Auto-inject API key from localStorage if set
        const key = localStorage.getItem("ipshield_api_key");
        if (key && !req.headers["x-api-key"]) {
          req.headers["x-api-key"] = key;
        }
        return req;
      }
    });
  </script>
</body>
</html>`);
});

module.exports = router;