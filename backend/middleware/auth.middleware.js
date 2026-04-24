// auth.middleware.js — FIXED

const EXEMPT = [
  "/health",
  "/stats",
  "/audit"
];

module.exports = function authMiddleware(req, res, next) {
  if (EXEMPT.some(path => req.path.startsWith(path))) return next();

  const key = req.headers["x-api-key"] || req.query.apiKey;
  if (!key) return res.status(401).json({ error: "Unauthorized", message: "Missing x-api-key header" });
  if (key !== process.env.API_KEY) return res.status(403).json({ error: "Forbidden", message: "Invalid API key" });
  next();
};