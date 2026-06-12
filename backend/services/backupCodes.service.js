const bcrypt = require("bcryptjs");
const crypto = require("crypto");

/**
 * Generate N backup codes — 8 uppercase hex chars each (e.g. "A3F2C9B1")
 * Stored hashed in DB, shown plain-text to user exactly once.
 */
function generateBackupCodes(count = 8) {
  return Array.from({ length: count }, () =>
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

/**
 * Hash all codes with bcrypt for DB storage.
 * Each code is hashed independently so used codes can be
 * removed from the array without re-hashing the rest.
 */
async function hashBackupCodes(codes) {
  return Promise.all(codes.map(code => bcrypt.hash(code, 10)));
}

module.exports = { generateBackupCodes, hashBackupCodes };