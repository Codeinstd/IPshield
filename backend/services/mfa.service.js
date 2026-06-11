const otplib = require("otplib");
const QRCode = require("qrcode");
const authenticator =
  otplib.authenticator ||
  otplib.authenticator?.totp ||
  otplib.totp;

// fallback check (prevents silent crashes)
if (!authenticator) {
  throw new Error("otplib authenticator not available - check version");
}

// CONFIG (safe approach)
try {
  authenticator.options = {
    window: 1, // ±30 seconds tolerance
  };
} catch (e) {
  console.warn("Could not set authenticator options:", e.message);
}

// Generate MFA secret + QR
function generateSecret(email) {
  const secret = authenticator.generateSecret();

  const otpauth = authenticator.keyuri(
    email,
    "IPShield",
    secret
  );

  return {
    secret,
    otpauth,
  };
}


// Generate QR

async function generateQR(otpauth) {
  return QRCode.toDataURL(otpauth);
}


// VERIFY TOKEN (robust)
function verifyToken(token, secret) {
  if (!token || !secret) return false;

  const cleanToken = String(token).replace(/\D/g, "");

  try {
    return authenticator.check(cleanToken, secret);
  } catch (err) {
    console.error("MFA verify error:", err.message);
    return false;
  }
}

module.exports = {
  generateSecret,
  generateQR,
  verifyToken,
};