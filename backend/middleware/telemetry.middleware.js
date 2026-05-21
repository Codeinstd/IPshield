
const telemetry = require("../store/telemetry.store");

// Map Express route patterns from req.route.path + router stack
function resolveRoute(req) {
  // Try exact route match from express
  if (req.route?.path) {
    const base = req.baseUrl || "";
    return `${req.method} ${base}${req.route.path}`;
  }
  // Fall back: normalize dynamic segments
  const path = req.path
    .replace(/\/\d+/g, "/:id")
    .replace(/\/(\d{1,3}\.){3}\d{1,3}/g, "/:ip")
    .replace(/\/[0-9a-fA-F:]{7,45}/g, "/:ip");
  return `${req.method} ${path}`;
}

function getApiVersion(req) {
  if (req.baseUrl?.includes("/v1")) return "v1";
  if (req.baseUrl?.includes("/v2")) return "v2";
  return "v2";
}

function getClientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    null
  );
}

function telemetryMiddleware(req, res, next) {
  // Skip telemetry for docs, static files and health
  const path = req.path || "";
  if (
    path.includes("/docs") ||
    path.includes("/static") ||
    path === "/health" ||
    path.endsWith(".js") ||
    path.endsWith(".css") ||
    path.endsWith(".ico")
  ) {
    return next();
  }

  const startNs  = process.hrtime.bigint();
  const reqBytes = parseInt(req.headers["content-length"] || "0");

  res.on("finish", () => {
    try {
      const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;
      const resBytes   = parseInt(res.getHeader("content-length") || "0");

      telemetry.record({
        method:      req.method,
        path:        req.path,
        route:       resolveRoute(req),
        status:      res.statusCode,
        durationMs:  Math.round(durationMs),
        reqBytes,
        resBytes,
        apiKey:      req.headers["x-api-key"] || null,
        apiVersion:  getApiVersion(req),
        clientIp:    getClientIp(req),
        error:       res.statusCode >= 400 ? res.locals?.errorMessage || null : null
      });
    } catch (_) {} // Never let telemetry break anything
  });

  next();
}

module.exports = telemetryMiddleware;