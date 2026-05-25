
const { requireAuth, requireRole } = require('./auth.js');
 
const PUBLIC_ROUTES = new Set([
  'GET /api/health',
  'GET /api/docs',
  'GET /api/v1/docs',
  'GET /api/v2/docs',
  'GET /api/docs/openapi.json',
  'GET /api/versions',
]);
 
const ROLE_REQUIREMENTS = {
  // Telemetry — admin only (fixes the public dashboard vulnerability)
  'GET /api/telemetry/dashboard':  'admin',
  'GET /api/telemetry':            'admin',
 
  // Dangerous bulk operations — admin only
  'DELETE /api/blacklist/bulk':    'admin',
  'DELETE /api/cases/:id':         'admin',
 
  // API key management (if you add it later) — admin only
  'GET /api/keys':                 'admin',
  'POST /api/keys':                'admin',
  'DELETE /api/keys/:id':          'admin',
 
  // Read-only routes accessible to readonly keys
  'GET /api/audit':                'readonly',
  'GET /api/audit/search':         'readonly',
  'GET /api/audit/threats':        'readonly',
  'GET /api/stats':                'readonly',
  'GET /api/blacklist':            'readonly',
  'GET /api/blacklist/stats':      'readonly',
  'GET /api/cases':                'readonly',
  'GET /api/cases/stats':          'readonly',
  'GET /api/cases/:id':            'readonly',
  'GET /api/watchlist':            'readonly',
  'GET /api/timeline/:ip':         'readonly',
  'GET /api/whois/:ip':            'readonly',
};
 
export function applyAuth(app) {
  // Walk every registered layer and inject guards
  app._router.stack.forEach((layer) => {
    if (!layer.route) return;
 
    const routePath  = layer.route.path;
    const methods    = Object.keys(layer.route.methods);
 
    methods.forEach((method) => {
      const methodUpper = method.toUpperCase();
      const routeKey    = `${methodUpper} ${routePath}`;
 
      if (PUBLIC_ROUTES.has(routeKey)) return; // skip public routes
 
      const minRole = ROLE_REQUIREMENTS[routeKey] ?? 'analyst';
 
      // Prepend requireAuth + requireRole to the route's handler stack
      layer.route.stack.unshift(
        { handle: requireRole(minRole), name: 'roleGuard' },
        { handle: requireAuth,          name: 'requireAuth' },
      );
    });
  });
 
  console.log('[auth] Route guards applied');
}