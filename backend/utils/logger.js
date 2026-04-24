/**
 * logger.js
 * Place in: backend/utils/logger.js
 *
 * Uses winston if available, falls back to console.
 * Install optional: npm install winston
 */

let logger;

try {
  const winston = require("winston");
  const isProd  = process.env.NODE_ENV === "production";

  logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (isProd ? "info" : "debug"),
    format: isProd
      ? winston.format.combine(winston.format.timestamp(), winston.format.json())
      : winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: "HH:mm:ss" }),
          winston.format.printf(({ level, message, timestamp, ...meta }) => {
            const extras = Object.keys(meta).length ? " " + JSON.stringify(meta) : "";
            return `${timestamp} ${level}: ${message}${extras}`;
          })
        ),
    transports: [
      new winston.transports.Console(),
      ...(isProd ? [
        new winston.transports.File({ filename: "logs/error.log",    level: "error" }),
        new winston.transports.File({ filename: "logs/combined.log"              })
      ] : [])
    ]
  });
} catch (_) {
  // Fallback to console if winston not installed
  logger = {
    info:  (...a) => console.log("[INFO]",  ...a),
    warn:  (...a) => console.warn("[WARN]",  ...a),
    error: (...a) => console.error("[ERROR]", ...a),
    debug: (...a) => console.debug("[DEBUG]", ...a)
  };
}

module.exports = logger;