
const crypto = require("crypto");

function cspMiddleware(req, res, next) {
  // Generate a fresh nonce for every request
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce;

  const isProd = process.env.NODE_ENV === "production";

  const directives = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com`,
    `font-src 'self' https://fonts.gstatic.com`,
    `img-src 'self' data: https://*.basemaps.cartocdn.com https://*.cartocdn.com`,
    `connect-src 'self' https://api.ipify.org`,
    `worker-src 'self' blob:`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    isProd ? `upgrade-insecure-requests` : ``
  ].filter(Boolean).join("; ");

  res.setHeader("Content-Security-Policy", directives);
  next();
}

module.exports = cspMiddleware;