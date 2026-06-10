const otplib = require("otplib");
const QRCode = require("qrcode");

function generateSecret(email) {
  const secret = otplib.generateSecret();

  const otpauth = otplib.generateURI({
    secret,
    issuer: "IPShield",
    label: email,
  });

  return {
    secret,
    otpauth,
  };
}

async function generateQR(otpauth) {
  return QRCode.toDataURL(otpauth);
}

function verifyToken(token, secret) {
  return otplib.verify({
    token,
    secret,
  });
}

module.exports = {
  generateSecret,
  generateQR,
  verifyToken,
};