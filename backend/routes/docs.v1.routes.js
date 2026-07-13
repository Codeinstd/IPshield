const express = require("express");
const router  = express.Router();

const spec = {
  openapi: "3.0.3",
  info: {
    title:       "IPShield API — v1",
    description: `

Note: v2 is available at \`/api/v2\` and adds **Blacklist Management** and **Case Management**.
See [v2 docs](/api/v2/docs) to upgrade.

## Authentication
All endpoints require \`x-api-key\` header except \`/health\` and \`/docs\`.

## Plans & Quotas
Every account also has a subscription plan with its own daily quota per feature,
separate from the IP-based rate limits above. Quotas reset at midnight UTC.
 
| Feature | Free | Team |
|---------|------|------|
| IP score lookups / day | 5 | 500,000 |
| Batch scoring / day | Not available | 100,000 |
| Watched IPs (max) | 1 | 10,000 |
 
Active scanning and per-account SIEM target limits are v2-only features —
see [v2 docs](/api/v2/docs) for those quotas.
 
Exceeding a quota returns \`HTTP 429\` with \`{ "error": "quota_exceeded", "plan",
"limit", "used", "upgrade_url" }\`. See [/pricing](/pricing) to upgrade.

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
    },
    schemas: {
      QuotaExceeded: {
        type: "object",
        properties: {
          error:       { type: "string", example: "quota_exceeded" },
          message:     { type: "string", example: 'Daily limit for "score" reached (5/day on the free plan).' },
          plan:        { type: "string", enum: ["free","team"], example: "free" },
          limit:       { type: "integer", example: 5 },
          used:        { type: "integer", example: 5 },
          upgrade_url: { type: "string", example: "/pricing" }
        }
      }
    },
    responses: {
      QuotaExceededResponse: {
        description: "Daily quota exceeded for this feature on the caller's current plan.",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/QuotaExceeded" } } }
      }
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
           429: { "$ref": "#/components/responses/QuotaExceededResponse" }
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
        responses: { 
          200: { description: "Batch results" },
          429: { "$ref": "#/components/responses/QuotaExceededResponse" }
       }
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
        responses: { 
          200: { description: "Watchlist" } 
        }
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
        responses: { 
          responses: {
          201: { description: "Added" },
          400: { description: "Invalid or full" },
          429: { "$ref": "#/components/responses/QuotaExceededResponse" }
      }
        }
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

// Raw Spec 
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json(spec);
});

// Swagger UI 
router.get("/",(req, res) => {
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
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon.ico/favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="96x96" href="/favicon.ico/favicon-96x96.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon.ico/favicon-16x16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&amp;family=Syne:wght@400;600;700;800&amp;display=swap" rel="stylesheet">
  <style>

    body {
    margin: 0;
    background: #121212;
    color: #c9d8e8;
    background: radial-gradient(circle at top left, rgba(0, 217, 255, .08), transparent 25%), 
    radial-gradient(circle at bottom right, rgba(0, 232, 124, .05), transparent 25%), #050816;
    font-family: 'Inter', sans-serif;
    background: #121212;
}
    
.docs-header {
    position: sticky;
    top: 0;
    z-index: 999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 36px;
    backdrop-filter: blur(16px);
    background: #171717;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

    .docs-logo {
    color: #c9d8e8;
    font-size: 18px;
    font-weight: 700;
    font-family: 'Syne';
    }

    .docs-logo span { color:${accentColor}; }
    .version-badge { background:rgba(0, 217, 255, 0.12); color:${accentColor}; border:1px solid ${accentColor}44; padding:3px 10px; border-radius:4px; font-size:11px; font-weight:700; }
    .docs-nav { display:flex; gap:10px; align-items:center; }
    .docs-nav a { color:#6a8fa8; font-size:11px; text-decoration:none; border:1px solid #1e2d3d; padding:5px 12px; border-radius:6px; }
    .docs-nav a:hover { color:#00d9ff; border-color:#00d9ff; }
    .docs-nav a.active { color:${accentColor}; border-color:${accentColor}; }
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
    font-family: 'Inter', sans-serif;
}

    .swagger-ui section.models h4 {
    align-items: center;
    cursor: pointer;
    display: flex;
    font-family: 'Inter', sans-serif;
    font-size: 16px;
    margin: 0;
    padding: 10px 20px 10px 20px;
    transition: all .2s;
    }

    .swagger-ui table thead tr th {
    color: #c9d8e8;
    border-bottom: 1px solid #1e2d3d;
    font-family: 'Inter', sans-serif;
    }

      
    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #aeb4b8;
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    }


    .swagger-ui .info p {
    color: #aeb4b8;
    font-family:'Inter', sans-serif;
    }

    .swagger-ui a.nostyle, .swagger-ui a.nostyle:visited {
    color: inherit;
    cursor: pointer;
    text-decoration: inherit;
    font-family: 'Syne';
    }

    .swagger-ui .markdown p, .swagger-ui .markdown pre, .swagger-ui .renderedMarkdown p, .swagger-ui .renderedMarkdown pre {
    word-break: break-word;
    font-family:'Inter', sans-serif;
    }

    .swagger-ui table thead tr td, .swagger-ui table thead tr th {
    border-bottom: 1px solid rgba(59, 65, 81, .2);
    color: #71798d;
    font-family:'Inter', sans-serif;
    font-size: 12px;
    font-weight: 700;
    padding: 12px 0;
    text-align: left;
    }

    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #aeb4b8;
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    }

    .swagger-ui .info a {
    color: #02bfe0;
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    transition: all .4s;
    padding: 10px;
    }

    .swagger-ui .opblock-tag small {
    color: #60687b;
    font-family:'Inter', sans-serif;
    font-size: 14px;
    font-weight: 400;
    }

    .swagger-ui .opblock-tag {
    position: sticky;
    top: 72px;
    z-index: 5;
    margin-top: 48px;
    padding: 18px 20px;
    background: #171717;
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, .04);
    border-radius: 16px;
    font-size: 28px;
    font-weight: 700;
    display: flex;
    align-items: flex-start;
    flex-direction: column;
}

    .swagger-ui .opblock .opblock-summary-description {
    color: #aeb4b8;
    font-family:'Inter', sans-serif;
    font-size: 13px;
    word-break: break-word;
    }

    .swagger-ui .info li, .swagger-ui .info p, .swagger-ui .info table {
    color: #aeb4b8;
    font-family: 'Inter', sans-serif;
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
    color: #00d9ff;
    font-size: 12px;
    letter-spacing: .08em;
    text-transform: uppercase;
    }

    .hero-content h1 {
    margin: 24px 0 12px;
    font-size: 56px;
    line-height: 1;
    font-weight: 800;
    font-family: Syne, sans-serif;
    color: #fff;
    }

    .swagger-ui .markdown code, .swagger-ui .renderedMarkdown code {
    background: rgba(0, 0, 0, .05);
    border-radius: 4px;
    color: #04d9ff;
    font-family: monospace;
    font-size: 14px;
    font-weight: 600;
    padding: 5px 7px;
    }

    .hero-content p {
    max-width: 760px;
    margin: auto;
    color: #aeb4b8;
    font-size: 18px;
    line-height: 1.8;
    }

    .hero-content h1 span {
    color: #00d9ff;
    }

    .docs-back {
    color: #b9beca;
    font-size: 12px;
    text-decoration: none;
    border: 1px solid #1e2d3d;
    padding: 6px 14px;
    border-radius: 6px;
    font-family: 'Inter', sans-serif;
    }

    /* ── Desktop nav */
    .docs-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 24px;
        position: relative;
        z-index: 100;
    }

    .docs-nav {
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .docs-nav a {
        white-space: nowrap;
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 13px;
        text-decoration: none;
        color: var(--text3, #8ab);
        border: 1px solid transparent;
        transition: all 0.15s;
    }

      .docs-nav a:hover {
          color: var(--accent, #00cfff);
          border-color: var(--accent, #00cfff);
      }

      .docs-nav a.active {
          color: var(--accent, #00cfff);
          border-color: var(--accent, #00cfff);
          background: rgba(0, 207, 255, 0.08);
      }

      .docs-nav .docs-back {
          margin-left: 8px;
          padding-left: 16px;
          border-left: 1px solid rgba(255, 255, 255, 0.1);
      }

    /* ── Hamburger button ── */
    .hamburger {
        display: none;
        flex-direction: column;
        justify-content: center;
        gap: 5px;
        width: 36px;
        height: 36px;
        padding: 6px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        cursor: pointer;
        transition: background 0.2s;
    }

    .hamburger:hover {
        background: rgba(0, 207, 255, 0.1);
        border-color: var(--accent, #00cfff);
    }

    .hamburger span {
        display: block;
        width: 100%;
        height: 2px;
        background: var(--text3, #8ab);
        border-radius: 2px;
        transition: all 0.25s ease;
        transform-origin: center;
    }

    /* Animate to X when open */
    .hamburger.open span:nth-child(1) {
        transform: translateY(7px) rotate(45deg);
    }
    .hamburger.open span:nth-child(2) {
        opacity: 0;
        transform: scaleX(0);
    }
    .hamburger.open span:nth-child(3) {
        transform: translateY(-7px) rotate(-45deg);
    }

    /* ── Overlay ── */
    .mobile-nav-overlay {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(2px);
        z-index: 200;
        opacity: 0;
        transition: opacity 0.25s ease;
    }

    .mobile-nav-overlay.visible {
        opacity: 1;
    }

    /* ── Drawer ── */
    .mobile-nav-drawer {
        position: fixed;
        top: 0;
        right: 0;
        width: min(280px, 85vw);
        height: 100vh;
        background: var(--bg2, #0d1b2a);
        border-left: 1px solid rgba(255, 255, 255, 0.08);
        z-index: 201;
        transform: translateX(100%);
        transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        display: flex;
        flex-direction: column;
        box-shadow: -8px 0 32px rgba(0, 0, 0, 0.4);
    }

    .mobile-nav-drawer.open {
        transform: translateX(0);
    }

    .mobile-nav-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .mobile-nav-close {
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 6px;
        color: var(--text3, #8ab);
        font-size: 14px;
        cursor: pointer;
        transition: all 0.15s;
    }

    .mobile-nav-close:hover {
        background: rgba(255, 80, 80, 0.1);
        border-color: #ff5050;
        color: #ff5050;
    }
    .mobile-nav-links {
        display: flex;
        flex-direction: column;
        padding: 12px;
        gap: 4px;
    }

    @media (max-width: 768px) {
      .docs-header {
        padding: 12px 16px;
      }

      .docs-hero {
        padding: 48px 20px 40px;
      }

      .hero-content h1 {
        font-size: 36px;
        margin: 16px 0 10px;
      }

      .hero-content p {
        font-size: 14px;
        line-height: 1.6;
      }

      .hero-badge {
        font-size: 11px;
        padding: 6px 12px;
      }

      #swagger-ui {
        padding: 0 12px 32px;
      }

      /* Swagger opblock tag sticky offset matches smaller header */
      .swagger-ui .opblock-tag {
        top: 56px;
        font-size: 20px;
        padding: 12px 16px;
        margin-top: 28px;
        border-radius: 10px;
      }

      .swagger-ui .table-container {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }
      
      .swagger-ui .parameter__name,
      .swagger-ui .parameter__type,
      .swagger-ui .opblock-summary-path {
        word-break: break-all;
        white-space: normal;
      }

      .swagger-ui .btn-group {
        flex-wrap: wrap;
        gap: 8px;
      }

     
      .swagger-ui .opblock-body pre.microlight {
        font-size: 11px;
        overflow-x: auto;
      }

      /* Auth modal */
      .swagger-ui .dialog-ux .modal-ux {
        width: 95vw;
        max-width: 95vw;
        margin: 0 auto;
      }

      /* Info section */
      .swagger-ui .info {
        margin: 16px 0;
      }

      .swagger-ui .info .title {
        font-size: 26px;
      }
    }

    @media (max-width: 480px) {
      .hero-content h1 {
        font-size: 28px;
      }

      .hero-content p {
        font-size: 13px;
      }

      /* Stack the execute + clear buttons vertically */
      .swagger-ui .execute-wrapper {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .swagger-ui .btn.execute,
      .swagger-ui .btn-clear {
        width: 100%;
      }

      /* Scheme container (server selector) */
      .swagger-ui .scheme-container {
        padding: 12px;
      }

     
      .swagger-ui .opblock-summary {
        padding: 8px 10px;
      }

      .swagger-ui .opblock-summary-method {
        min-width: 50px;
        font-size: 11px;
        padding: 4px 6px;
      }

      .swagger-ui .opblock-summary-path {
        font-size: 12px;
      }
    }

    .mobile-nav-links a {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 14px;
        border-radius: 8px;
        text-decoration: none;
        color: var(--text3, #8ab);
        font-size: 14px;
        border: 1px solid transparent;
        transition: all 0.15s;
    }

    .mobile-nav-links a:hover {
        background: rgba(0, 207, 255, 0.06);
        color: var(--accent, #00cfff);
        border-color: rgba(0, 207, 255, 0.2);
    }

    .mobile-nav-links a.active {
        background: rgba(0, 207, 255, 0.1);
        color: var(--accent, #00cfff);
        border-color: rgba(0, 207, 255, 0.3);
    }

    .mobile-nav-links a.docs-back {
        margin-top: auto;
        color: var(--text3, #8ab);
    }

    .mobile-nav-icon {
        font-size: 12px;
        font-weight: 700;
        width: 28px;
        height: 28px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 6px;
        flex-shrink: 0;
    }

    /* ── Mobile breakpoint ── */
    @media (max-width: 600px) {
        .docs-nav {
            display: none; /* hide desktop nav */
        }

        .hamburger {
            display: flex; /* show hamburger */
        }
    }

    .swagger-ui .info p { color:#aeb4b8; }
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
    .swagger-ui .scheme-container { background:#171717; box-shadow:none; border-bottom:1px solid #1e2d3d; }
    .swagger-ui input[type=text], .swagger-ui textarea { background:#111820; border:1px solid #1e2d3d; color:#c9d8e8; border-radius:4px; }
    .swagger-ui .btn.execute { background:${accentColor}; color:#000; border:none; font-weight:700; font-family: 'Inter', sans-serif; }
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
    <nav class="docs-nav" id="docsNav">
        <a href="/api/v1/docs" class="${version === "v1" ? "active" : ""}">v1 Stable</a>
        <a href="/api/v2/docs" class="${version === "v2" ? "active" : ""}">v2 Latest</a>
        <a href="/api/versions">All Versions</a>
        <a href="/" class="docs-back">← Back to App</a>
    </nav>
    <button class="hamburger" id="hamburger" aria-label="Toggle navigation">
        <span></span>
        <span></span>
        <span></span>
    </button>
</div>

<!-- Mobile nav modal -->
<div class="mobile-nav-overlay" id="mobileNavOverlay"></div>
<div class="mobile-nav-drawer" id="mobileNavDrawer">
    <div class="mobile-nav-header">
        <div style="display:flex;align-items:center;gap:10px;">
            <div class="docs-logo">IP<span>Shield</span></div>
            <span class="version-badge">${version.toUpperCase()}</span>
        </div>
        <button class="mobile-nav-close" id="mobileNavClose">✕</button>
    </div>
    <nav class="mobile-nav-links">
        <a href="/api/v1/docs" class="${version === "v1" ? "active" : ""}">
            <span class="mobile-nav-icon">v1</span> Stable
        </a>
        <a href="/api/v2/docs" class="${version === "v2" ? "active" : ""}">
            <span class="mobile-nav-icon">v2</span> Latest
        </a>
        <a href="/api/versions">
            <span class="mobile-nav-icon">⊞</span> All Versions
        </a>
        <a href="/" class="docs-back">
            <span class="mobile-nav-icon">←</span> Back to App
        </a>
    </nav>
</div>
    <div class="docs-hero">
        <div class="hero-grid"></div>
        <div class="hero-content">
      <div class="hero-badge">
            API DOCUMENTATION
        </div>

        <h1>
            IP<span>Shield</span>
        </h1>

        <p>
             Real-time IP reputation, threat feeds, WHOIS intelligence, blacklist management and investigation workflows.
        </p>
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

(function () {
  var hamburger = document.getElementById('hamburger');
  var overlay   = document.getElementById('mobileNavOverlay');
  var drawer    = document.getElementById('mobileNavDrawer');
  var closeBtn  = document.getElementById('mobileNavClose');

  if (!hamburger || !overlay || !drawer || !closeBtn) {
    console.warn('Mobile nav: missing element', { hamburger, overlay, drawer, closeBtn });
    return;
  }

  function openMobileNav() {
    overlay.style.display = 'block';
    requestAnimationFrame(function () {
      overlay.classList.add('visible');
      drawer.classList.add('open');
      hamburger.classList.add('open');
    });
    document.body.style.overflow = 'hidden';
  }

  function closeMobileNav() {
    overlay.classList.remove('visible');
    drawer.classList.remove('open');
    hamburger.classList.remove('open');
    document.body.style.overflow = '';
    setTimeout(function () { overlay.style.display = 'none'; }, 300);
  }

  hamburger.addEventListener('click', function () {
    drawer.classList.contains('open') ? closeMobileNav() : openMobileNav();
  });

  overlay.addEventListener('click', closeMobileNav);
  closeBtn.addEventListener('click', closeMobileNav);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeMobileNav();
  });
})();
   
  </script>
</body>
</html>`;
}

module.exports = router;
module.exports.buildSwaggerHTML = buildSwaggerHTML;