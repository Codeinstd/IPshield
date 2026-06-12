const otplib = require("otplib");
const QRCode  = require("qrcode");

const authenticator = otplib.authenticator;

if (!authenticator) {
  throw new Error("otplib authenticator not available — check version");
}

// ±30 s tolerance (one window either side)
try {
  authenticator.options = { window: 1 };
} catch (e) {
  console.warn("[mfa.service] Could not set authenticator options:", e.message);
}

/** Generate a new TOTP secret + otpauth URI for a given account label */
function generateSecret(label) {
  const secret   = authenticator.generateSecret();
  const otpauth  = authenticator.keyuri(label, "IPShield", secret);
  return { secret, otpauth };
}

/** Convert an otpauth URI to a base64 PNG data URL */
async function generateQR(otpauth) {
  return QRCode.toDataURL(otpauth);
}

/**
 * Verify a TOTP token against a secret.
 * Strips non-digits so "123 456" works too.
 * Returns false instead of throwing on any error.
 */
function verifyToken(token, secret) {
  if (!token || !secret) return false;
  const clean = String(token).replace(/\D/g, "");
  try {
    return authenticator.check(clean, secret);
  } catch (err) {
    console.error("[mfa.service] verifyToken error:", err.message);
    return false;
  }
}

module.exports = { generateSecret, generateQR, verifyToken };