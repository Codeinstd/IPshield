
const EXEMPT = [
  "/health",
  "/stats",
  "/audit"
];

module.exports = function authMiddleware(req, res, next) {
  if (EXEMPT.some(path => req.path.startsWith(path))) return next();

  const key = req.headers["x-api-key"] || req.query.apiKey;

  console.log("RECV:", JSON.stringify(key));
  console.log("EXPC:", JSON.stringify(process.env.API_KEY));
  console.log("MATCH:", key === process.env.API_KEY);

  if (!key) return res.status(401).json({ error: "Unauthorized", message: "Missing x-api-key header" });
  if (key !== process.env.API_KEY) return res.status(403).json({ error: "Forbidden", message: "Invalid API key" });
  next();
};