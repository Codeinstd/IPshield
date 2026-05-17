const express = require("express");
const router  = express.Router();
const spec    = require("../config/openapi");

// ── Raw OpenAPI JSON spec 
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*"); // allow external tools like Postman
  res.json(spec);
});

// ── Swagger UI HTML 
router.get("/", (req, res) => {
  // We serve Swagger UI assets from cdnjs (on CSP allowlist)
  // and inline the spec as a JS variable to avoid fetch() CSP issues
  const specJson = JSON.stringify(spec);

  res.setHeader("Content-Type", "text/html");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPShield API Docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>

  :root {
  --bg: #050816;
  --panel: rgba(13, 17, 23, 0.72);
  --panel-border: rgba(255,255,255,0.06);

  --text: #dbe7f5;
  --muted: #7f97b2;

  --cyan: #00d9ff;
  --green: #00e87c;
  --yellow: #ffcc00;
  --red: #ff4d6d;

  --shadow:
    0 10px 40px rgba(0,0,0,0.45);

  --radius: 18px;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  color: var(--text);

  background:
    radial-gradient(circle at top left, rgba(0,217,255,.08), transparent 25%),
    radial-gradient(circle at bottom right, rgba(0,232,124,.05), transparent 25%),
    #050816;

  font-family: Inter, sans-serif;
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

  background: rgba(5, 8, 22, 0.75);

  border-bottom:
    1px solid rgba(255,255,255,0.06);
}

.docs-hero {
  position: relative;

  padding:
    90px 32px 70px;

  overflow: hidden;
}

.hero-grid {
  position: absolute;
  inset: 0;

  background-image:
    linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);

  background-size: 40px 40px;

  mask-image:
    radial-gradient(circle at center, black 30%, transparent 80%);
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

  background: rgba(0,217,255,.08);

  border: 1px solid rgba(0,217,255,.18);

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

.hero-content h1 span {
  color: var(--cyan);
}

.hero-content p {
  max-width: 760px;

  margin: auto;

  color: var(--muted);

  font-size: 18px;
  line-height: 1.8;
}

.hero-actions {
  margin-top: 34px;

  display: flex;
  justify-content: center;
  gap: 16px;
}

.hero-btn {
  padding: 14px 22px;

  border-radius: 14px;

  text-decoration: none;

  font-weight: 600;

  transition: .25s ease;
}

.hero-btn.primary {
  background: var(--cyan);
  color: #000;

  box-shadow:
    0 0 25px rgba(0,217,255,.35);
}

.hero-btn.primary:hover {
  transform: translateY(-2px);
}

.hero-btn.secondary {
  border: 1px solid rgba(255,255,255,.08);

  background: rgba(255,255,255,.03);

  color: var(--text);
}

.swagger-ui .opblock {
  overflow: hidden;

  margin-bottom: 18px;

  border-radius: 20px;

  border:
    1px solid rgba(255,255,255,.05);

  background:
    rgba(13,17,23,.72);

  backdrop-filter: blur(18px);

  box-shadow: var(--shadow);

  transition:
    transform .2s ease,
    border-color .2s ease;
}

.swagger-ui .opblock:hover {
  transform: translateY(-2px);

  border-color:
    rgba(0,217,255,.25);
}

.swagger-ui .opblock-tag {
  position: sticky;
  top: 72px;

  z-index: 5;

  margin-top: 48px;

  padding: 18px 20px;

  background:
    rgba(5,8,22,.88);

  backdrop-filter: blur(12px);

  border:
    1px solid rgba(255,255,255,.04);

  border-radius: 16px;

  font-size: 28px;
  font-weight: 700;

  color: #fff;
}

.swagger-ui .opblock-summary {
  padding: 18px 22px;
}

.swagger-ui .opblock-summary-path {
  color: #dbe7f5;

  font-weight: 600;
}

.swagger-ui .opblock-summary-description {
  color: #7f97b2;
}

.swagger-ui input[type=text],
.swagger-ui textarea,
.swagger-ui select {
  background: rgba(255,255,255,.03);

  border:
    1px solid rgba(255,255,255,.08);

  border-radius: 12px;

  color: white;

  padding: 12px;
}

.swagger-ui .btn.execute {
  border: none;

  border-radius: 12px;

  background: linear-gradient(
    135deg,
    #00d9ff,
    #00e87c
  );

  color: #031018;

  font-weight: 700;

  box-shadow:
    0 10px 25px rgba(0,217,255,.25);
}

#swagger-ui {
  max-width: 1400px;

  margin: auto;

  padding:
    0 28px 120px;
}

window.addEventListener("load", () => {
  const icons = {
    Scoring: "🛰️",
    Intelligence: "🧠",
    Blacklist: "⛔",
    Cases: "📂",
    Watchlist: "👁️",
    Audit: "📜",
    System: "⚙️"
  };

  document.querySelectorAll(".opblock-tag").forEach(tag => {
    const text = tag.textContent.trim();

    if (icons[text]) {
      tag.innerHTML = \`
        <span style="margin-right:10px">
          \${icons[text]}
        </span>
        \${text}
      \`;
    }
  });
});

.swagger-ui .btn,
.swagger-ui .opblock,
.docs-back,
.hero-btn {
  transition: all .22s ease;
}

.swagger-ui .topbar {
  display: none;
}

.swagger-ui .info .title small {
  display: none;
}

.swagger-ui .scheme-container {
  background: transparent;
  box-shadow: none;
  border: none;
}

.swagger-ui section.models {
  margin-top: 50px;
}

  </style>
</head>
<body>
  <div class="docs-header">
    <div class="docs-logo">
      IP<span>Shield</span>
    </div>

    <a href="/" class="docs-back">
      ← Back to App
    </a>
  </div>

  <div class="docs-hero">
    <div class="hero-grid"></div>

    <div class="hero-content">
      <div class="hero-badge">
        v2.2.0 • Threat Intelligence API
      </div>

      <h1>
        IP<span>Shield</span>
      </h1>

      <p>
        Real-time IP reputation, threat feeds, WHOIS intelligence,
        blacklist management and investigation workflows.
      </p>

      <div class="hero-actions">
        <a href="#swagger-ui" class="hero-btn primary">
          Explore API
        </a>

        <a href="/api/openapi.json" class="hero-btn secondary">
          OpenAPI Spec
        </a>
      </div>
    </div>
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

    window.addEventListener("load", () => {
  const icons = {
    Scoring: "🛰️",
    Intelligence: "🧠",
    Blacklist: "⛔",
    Cases: "📂",
    Watchlist: "👁️",
    Audit: "📜",
    System: "⚙️"
  };

  document.querySelectorAll(".opblock-tag").forEach(tag => {
    const text = tag.textContent.trim();

    if (icons[text]) {
      tag.innerHTML =
        '<span style="margin-right:10px">' +
        icons[text] +
        '</span>' +
        text;
    }
  });
});
  </script>
</body>
</html>`);
});

module.exports = router;