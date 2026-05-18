
const express = require("express");
const router  = express.Router();

const spec = {
  openapi: "3.0.3",
  info: {
    title:       "IPShield API — v1",
    description: `

> **Note:** v2 is available at \`/api/v2\` and adds **Blacklist Management** and **Case Management**.
> See [v2 docs](/api/v2/docs) to upgrade.

## Authentication
All endpoints require \`x-api-key\` header except \`/health\` and \`/docs\`.

## Rate Limits
| Endpoint | Limit |
|----------|-------|
| Global   | 200 req / 15 min |
| /score   | 30 req / min |
| /whois   | 20 req / min |
    `,
    version: "1.0.0",
    contact: { name: "IPShield", url: "https://ipshield.live" }
  },
  servers: [
    { url: "/api/v1",                            description: "v1 (stable)" },
    { url: "https://ipshield.live/api/v1",       description: "Production v1" }
  ],
  components: {
    securitySchemes: {
      ApiKeyAuth: { type: "apiKey", in: "header", name: "x-api-key" }
    }
  },
  security: [{ ApiKeyAuth: [] }],
  tags: [
    { name: "Scoring",          description: "IP risk scoring" },
    { name: "Intelligence",     description: "WHOIS and timeline" },
    { name: "Watchlist",        description: "IP monitoring" },
    { name: "Audit",            description: "Scoring history" },
    { name: "System",           description: "Health, stats, SIEM" }
  ],
  paths: {
    "/health": {
      get: {
        tags: ["System"], summary: "Health check", security: [],
        responses: { 200: { description: "Server healthy" } }
      }
    },
    "/score/{ip}": {
      get: {
        tags: ["Scoring"], summary: "Score a single IP",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" }, example: "185.220.101.1" }],
        responses: {
          200: { description: "Score result" },
          400: { description: "Invalid IP" },
          429: { description: "Rate limited" }
        }
      }
    },
    "/score/batch": {
      post: {
        tags: ["Scoring"], summary: "Batch score up to 50 IPs",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ips"],
            properties: { ips: { type: "array", items: { type: "string" }, maxItems: 50, example: ["8.8.8.8","1.1.1.1"] } }
          }}}
        },
        responses: { 200: { description: "Batch results" } }
      }
    },
    "/report/{ip}": {
      get: {
        tags: ["Scoring"], summary: "Download PDF threat report",
        parameters: [
          { name: "ip",     in: "path",  required: true, schema: { type: "string" } },
          { name: "cached", in: "query", schema: { type: "boolean", default: true } }
        ],
        responses: { 200: { description: "PDF file", content: { "application/pdf": {} } } }
      }
    },
    "/whois/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "WHOIS / RDAP deep dive",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" }, example: "8.8.8.8" }],
        responses: { 200: { description: "WHOIS result" } }
      }
    },
    "/timeline/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "Score history timeline",
        parameters: [
          { name: "ip",    in: "path",  required: true,  schema: { type: "string" } },
          { name: "limit", in: "query", required: false, schema: { type: "integer", default: 50, maximum: 200 } }
        ],
        responses: { 200: { description: "Timeline data" } }
      }
    },
    "/watchlist": {
      get: {
        tags: ["Watchlist"], summary: "List watched IPs",
        responses: { 200: { description: "Watchlist" } }
      },
      post: {
        tags: ["Watchlist"], summary: "Add IP to watchlist",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ip"],
            properties: {
              ip:            { type: "string",  example: "185.220.101.1" },
              label:         { type: "string",  example: "Tor Exit" },
              threshold:     { type: "integer", default: 30 },
              alertOnChange: { type: "boolean", default: true }
            }
          }}}
        },
        responses: { 201: { description: "Added" }, 400: { description: "Invalid or full" } }
      }
    },
    "/watchlist/{ip}": {
      delete: {
        tags: ["Watchlist"], summary: "Remove IP from watchlist",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" } }],
        responses: { 200: { description: "Removed" }, 404: { description: "Not found" } }
      }
    },
    "/watchlist/poll": {
      post: {
        tags: ["Watchlist"], summary: "Trigger immediate poll of all watched IPs",
        responses: { 200: { description: "Poll triggered" } }
      }
    },
    "/audit": {
      get: {
        tags: ["Audit"], summary: "Paginated audit log",
        parameters: [
          { name: "limit",  in: "query", schema: { type: "integer", default: 50,  maximum: 200 } },
          { name: "offset", in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Audit log" } }
      }
    },
    "/audit/search": {
      get: {
        tags: ["Audit"], summary: "Search and filter audit log",
        parameters: [
          { name: "q",        in: "query", schema: { type: "string" } },
          { name: "risk",     in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "minScore", in: "query", schema: { type: "integer" } },
          { name: "maxScore", in: "query", schema: { type: "integer" } },
          { name: "sort",     in: "query", schema: { type: "string", enum: ["date_desc","date_asc","score_desc","score_asc"], default: "date_desc" } },
          { name: "limit",    in: "query", schema: { type: "integer", default: 50 } },
          { name: "offset",   in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Filtered results" } }
      }
    },
    "/stats": {
      get: {
        tags: ["System"], summary: "Runtime statistics",
        responses: { 200: { description: "Stats" } }
      }
    },
    "/siem/status": {
      get: { tags: ["System"], summary: "SIEM webhook status", responses: { 200: { description: "Status" } } }
    },
    "/siem/test": {
      post: { tags: ["System"], summary: "Send test SIEM event", responses: { 200: { description: "Result" } } }
    },
    "/blacklist": {
      get: {
        tags: ["System"], summary: "⚠ Not available in v1",
        description: "Blacklist management requires **v2**. Use `/api/v2/blacklist`.",
        responses: {
          404: { description: "Not available in v1 — upgrade to v2" }
        }
      }
    },
    "/cases": {
      get: {
        tags: ["System"], summary: "⚠ Not available in v1",
        description: "Case management requires **v2**. Use `/api/v2/cases`.",
        responses: {
          404: { description: "Not available in v1 — upgrade to v2" }
        }
      }
    }
  }
};

// ── Raw Spec 
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json(spec);
});

// ── Swagger UI 
router.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(buildSwaggerHTML(spec, "v1", "#02bfe0"));
});

function buildSwaggerHTML(spec, version, accentColor) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPShield API ${version.toUpperCase()} Docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&amp;family=Syne:wght@400;600;700;800&amp;display=swap" rel="stylesheet">
  <style>
    body { margin:0; background:#0d1117; font-family: 'Syne','JetBrains Mono', monospace; }
    
.docs-header {
    position: sticky;
    top: 0;
    z-index: 999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 36px;
    backdrop-filter: blur(16px);
    background: rgba(5, 8, 22, 0.75);
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
    .docs-logo { color:#c9d8e8; font-size:18px; font-weight:700; font-family;'Syne'}
    .docs-logo span { color:${accentColor}; }
    .version-badge { background:rgba(0, 217, 255, 0.12); color:${accentColor}; border:1px solid ${accentColor}44; padding:3px 10px; border-radius:4px; font-size:11px; font-weight:700; }
    .docs-nav { display:flex; gap:10px; align-items:center; }
    .docs-nav a { color:#6a8fa8; font-size:11px; text-decoration:none; border:1px solid #1e2d3d; padding:5px 12px; border-radius:6px; }
    .docs-nav a:hover { color:#00d9ff; border-color:#00d9ff; }
    .docs-nav a.active { color:${accentColor}; border-color:${accentColor}; }
    .swagger-ui { background:#080c0f; }
    .swagger-ui .topbar { display:none; }
    .swagger-ui .info .title { color:#c9d8e8; }

    .swagger-ui .info .title {
    color: #ffffff;
    font-family: 'Syne';
    font-size: 36px;
    margin: 0;
    }

    .swagger-ui .info h1, .swagger-ui .info h2, .swagger-ui .info h3, .swagger-ui .info h4, .swagger-ui .info h5 {
    color: #ffffff;
    font-family: 'Syne';
    }


    .swagger-ui .model {
    color: #c9d8e8;
    margin-top: 24px;
    }

    .swagger-ui .model {
    color: #c9d8e8;
    font-family: monospace;
    font-size: 12px;
    font-weight: 300;
    font-weight: 600;
    }
    .swagger-ui .opblock-body pre.microlight {
    border-radius: 4px;
    font-size: 12px;
    hyphens: auto;
    margin: 0;
    padding: 10px;
    white-space: pre-wrap;
    word-break: break-word;
    word-wrap: break-word;
    font-family: 'JetBrains Mono', monospace;
}

    .swagger-ui section.models h4 {
    align-items: center;
    cursor: pointer;
    display: flex;
    font-family: 'JetBrains Mono', monospace;
    font-size: 16px;
    margin: 0;
    padding: 10px 20px 10px 20px;
    transition: all .2s;
    }

    .swagger-ui table thead tr th {
    color: #c9d8e8;
    border-bottom: 1px solid #1e2d3d;
    font-family: 'JetBrains Mono', monospace;
    }

      
    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #838fb0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    }


    .swagger-ui .info p {
    color: #c0ccd4;
    font-family:'JetBrains Mono', monospace ;
    }

    .swagger-ui a.nostyle, .swagger-ui a.nostyle:visited {
    color: inherit;
    cursor: pointer;
    text-decoration: inherit;
    font-family: 'Syne';
    }

    .swagger-ui .markdown p, .swagger-ui .markdown pre, .swagger-ui .renderedMarkdown p, .swagger-ui .renderedMarkdown pre {
    word-break: break-word;
    font-family:'JetBrains Mono', monospace;
    }

    .swagger-ui table thead tr td, .swagger-ui table thead tr th {
    border-bottom: 1px solid rgba(59, 65, 81, .2);
    color: #71798d;
    font-family:'JetBrains Mono', monospace ;
    font-size: 12px;
    font-weight: 700;
    padding: 12px 0;
    text-align: left;
    }

    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #b9beca;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    }

    .swagger-ui .info a {
    color: #02bfe0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    transition: all .4s;
    padding: 10px;
    }

    .swagger-ui .opblock-tag small {
    color: #60687b;
    font-family:'JetBrains Mono', monospace ;
    font-size: 14px;
    font-weight: 400;
    }

    .swagger-ui .opblock-tag {
    position: sticky;
    top: 72px;
    z-index: 5;
    margin-top: 48px;
    padding: 18px 20px;
    background: rgba(5, 8, 22, .88);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, .04);
    border-radius: 16px;
    font-size: 28px;
    font-weight: 700;
    color: #fff;
}

    .swagger-ui .opblock .opblock-summary-description {
    color: #868da0;
    font-family:'JetBrains Mono', monospace ;
    font-size: 13px;
    word-break: break-word;
    }

    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #838fb0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
}


    .docs-hero {
        position: relative;
        padding: 90px 32px 70px;
        overflow: hidden;
    }
    
    .hero-grid {
    position: absolute;
    inset: 0;
    background-image: linear-gradient(rgba(255, 255, 255, .03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, .03) 1px, transparent 1px);
    background-size: 40px 40px;
    mask-image: radial-gradient(circle at center, black 30%, transparent 80%);
    }

    .hero-content {
    position: relative;
    z-index: 2;
    max-width: 900px;
    margin: auto;
    text-align: center;
    }

    .hero-badge {
    display: inline-flex;
    padding: 8px 14px;
    border-radius: 999px;
    background: rgba(0, 217, 255, .08);
    border: 1px solid rgba(0, 217, 255, .18);
    color: var(--cyan);
    font-size: 12px;
    letter-spacing: .08em;
    text-transform: uppercase;
    }

    .hero-content h1 {
    margin: 24px 0 12px;
    font-size: 78px;
    line-height: 1;
    font-weight: 800;
    font-family: Syne, sans-serif;
    }

    .hero-content p {
    max-width: 760px;
    margin: auto;
    color: var(--muted);
    font-size: 18px;
    line-height: 1.8;
    }

    .hero-content h1 span {
    color: var(--cyan);
    }

    .docs-back {
    color: #b9beca;
    font-size: 12px;
    text-decoration: none;
    border: 1px solid #1e2d3d;
    padding: 6px 14px;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
}

    .swagger-ui .info p { color:#6a8fa8; }
    .swagger-ui .opblock-tag { color:#c9d8e8; border-bottom:1px solid #1e2d3d; }
    .swagger-ui .opblock { background:#0d1117; border:1px solid #1e2d3d; border-radius:8px; margin-bottom:8px; }
    .swagger-ui .opblock-summary-method { border-radius:4px; font-family:inherit; font-size:12px; font-weight:700; min-width:60px; text-align:center; }
    .swagger-ui .opblock.opblock-get    { border-color:rgba(0,232,124,0.3); }
    .swagger-ui .opblock.opblock-post   { border-color:rgba(255,204,0,0.3); }
    .swagger-ui .opblock.opblock-put    { border-color:rgba(0,140,255,0.3); }
    .swagger-ui .opblock.opblock-delete { border-color:rgba(255,51,85,0.3); }
    .swagger-ui .opblock.opblock-get    .opblock-summary-method { background:#00e87c; color:#000; }
    .swagger-ui .opblock.opblock-post   .opblock-summary-method { background:#ffcc00; color:#000; }
    .swagger-ui .opblock.opblock-put    .opblock-summary-method { background:#008cff; color:#fff; }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method { background:#ff3355; color:#fff; }
    .swagger-ui .scheme-container { background:#0d1117; box-shadow:none; border-bottom:1px solid #1e2d3d; }
    .swagger-ui input[type=text], .swagger-ui textarea { background:#111820; border:1px solid #1e2d3d; color:#c9d8e8; border-radius:4px; }
    .swagger-ui .btn.execute { background:${accentColor}; color:#000; border:none; font-weight:700; font-family: 'JetBrains Mono', monospace; }
    .swagger-ui .parameter__name { color:#00d9ff; }
    .swagger-ui .response-col_status { color:#00e87c; }
    .swagger-ui .microlight { background:#111820; border-radius:6px; padding:12px; }
    .swagger-ui .model-box { background:#111820; border-radius:6px; }
    .swagger-ui section.models { border:1px solid #1e2d3d; border-radius:8px; }
    .swagger-ui .auth-container { background:#0d1117; }
    .swagger-ui .dialog-ux .modal-ux { background:#0d1117; border:1px solid #1e2d3d; border-radius:12px; }
    .swagger-ui .opblock-summary-description, .swagger-ui .opblock-description-wrapper p { color:#6a8fa8; }
    .swagger-ui table thead tr th { color:#6a8fa8; border-bottom:1px solid #1e2d3d; }
    .swagger-ui .opblock-section-header { background:#111820; }
    .swagger-ui .opblock-section-header h4 { color:#c9d8e8; }
    #swagger-ui { max-width:1200px; margin:0 auto; padding:0 24px 48px; }
  </style>
</head>
<body>
  <div class="docs-header">
    <div style="display:flex;align-items:center;gap:12px;">
      <div class="docs-logo">IP<span>Shield</span></div>
      <span class="version-badge">${version.toUpperCase()}</span>
    </div>
    <div class="docs-nav">
      <a href="/api/v1/docs" class="${version === "v1" ? "active" : ""}">v1 Stable</a>
      <a href="/api/v2/docs" class="${version === "v2" ? "active" : ""}">v2 Latest</a>
      <a href="/api/versions">All Versions</a>
      <a href="/" class="docs-back">
      ← Back to App
        </a>
    </div>
    <div class="docs-hero">
    <div class="hero-grid"></div>

    <div class="hero-content">
      <div class="hero-badge">
        v1.0 • Core Intelligence API
      </div>

      <h1>
        IP<span>Shield</span>
      </h1>

      <p>
        Real-time IP reputation, threat feeds, WHOIS intelligence workflows.
      </p>
    </div>
  </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-standalone-preset.min.js"></script>
  <script>
    SwaggerUIBundle({
      spec: ${JSON.stringify(spec)},
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      layout: "StandaloneLayout",
      persistAuthorization: true,
      displayRequestDuration: true,
      tryItOutEnabled: true,
      defaultModelsExpandDepth: 1,
      requestInterceptor: req => {
        const key = localStorage.getItem("ipshield_api_key");
        if (key && !req.headers["x-api-key"]) req.headers["x-api-key"] = key;
        return req;
      }
    });
  </script>
</body>
</html>`;
}

module.exports = router;
module.exports.buildSwaggerHTML = buildSwaggerHTML;