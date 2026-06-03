const { requireAuth, requireRole } = require("./auth.js");

const PUBLIC_ROUTES = new Set([
  "GET /api/health",
  "GET /api/docs",
  "GET /api/v1/docs",
  "GET /api/v2/docs",
  "GET /api/docs/openapi.json",
  "GET /api/versions",
]);

const ROLE_REQUIREMENTS = {
  "GET /api/telemetry/dashboard": "admin",
  "GET /api/telemetry":           "admin",
  "DELETE /api/blacklist/bulk":   "admin",
  "DELETE /api/cases/:id":        "admin",
  "GET /api/keys":                "admin",
  "POST /api/keys":               "admin",
  "DELETE /api/keys/:id":         "admin",
  "GET /api/audit":               "readonly",
  "GET /api/audit/search":        "readonly",
  "GET /api/audit/threats":       "readonly",
  "GET /api/stats":               "readonly",
  "GET /api/blacklist":           "readonly",
  "GET /api/blacklist/stats":     "readonly",
  "GET /api/cases":               "readonly",
  "GET /api/cases/stats":         "readonly",
  "GET /api/cases/:id":           "readonly",
  "GET /api/watchlist":           "readonly",
  "GET /api/timeline/:ip":        "readonly",
  "GET /api/whois/:ip":           "readonly",
};

function applyAuth(app) {
  app._router.stack.forEach((layer) => {
    if (!layer.route) return;

    const routePath = layer.route.path;

    // Skip internal service routes — they use x-api-key directly
    if (routePath.startsWith("/api/v1/internal")) return;  // ← moved BEFORE use

    const methods = Object.keys(layer.route.methods);
    methods.forEach((method) => {
      const methodUpper = method.toUpperCase();
      const routeKey    = `${methodUpper} ${routePath}`;

      if (PUBLIC_ROUTES.has(routeKey)) return;

      const minRole = ROLE_REQUIREMENTS[routeKey] ?? "analyst";

      layer.route.stack.unshift(
        { handle: requireRole(minRole), name: "roleGuard"   },
        { handle: requireAuth,          name: "requireAuth" },
      );
    });
  });

  console.log("[auth] Route guards applied");
}

module.exports = { applyAuth }; 