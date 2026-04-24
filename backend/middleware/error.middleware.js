/**
 * error.middleware.js
 * Place in: backend/middleware/error.middleware.js
 */

const logger = require("../utils/logger");

module.exports = function errorMiddleware(err, req, res, next) {
  const status  = err.status || err.statusCode || 500;
  const isProd  = process.env.NODE_ENV === "production";

  // Log full error server-side
  logger.error(`${req.method} ${req.path} → ${status}: ${err.message}`, {
    stack:  isProd ? undefined : err.stack,
    body:   req.body,
    params: req.params
  });

  // Sentry capture if available
  if (process.env.SENTRY_DSN) {
    try {
      const Sentry = require("@sentry/node");
      Sentry.captureException(err);
    } catch (_) {}
  }

  res.status(status).json({
    error:   statusText(status),
    message: isProd && status === 500 ? "Internal server error" : err.message,
    ...(isProd ? {} : { stack: err.stack })
  });
};

function statusText(code) {
  const map = { 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests", 500: "Internal Server Error", 503: "Service Unavailable" };
  return map[code] || "Error";
}