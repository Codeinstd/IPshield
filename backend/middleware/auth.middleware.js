const EXEMPT = [
  "/health",
  "/stats", 
  "/audit",
  "/keys/activate"
];

module.exports = function authMiddleware(req, res, next) {
  // All auth is now handled per-route via requireAuth + requireRole in auth.js
  // This middleware is kept for compatibility but does no blocking
  next();
};