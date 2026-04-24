/**
 * validateEnv.js
 * Place in: backend/utils/validateEnv.js
 * Called at the very top of server.js before anything else
 */

const REQUIRED = ["ABUSE_IPDB_KEY", "IPSHIELD_API_KEY"];
const OPTIONAL = ["VIRUSTOTAL_KEY", "SLACK_WEBHOOK", "DISCORD_WEBHOOK", "SENTRY_DSN", "ALLOWED_ORIGIN", "DATABASE_URL"];

function validateEnv() {
  const missing = REQUIRED.filter(k => !process.env[k]);

  // Debug — print ALL env keys Railway injected
  console.log("All env keys:", Object.keys(process.env).join(", "));
  console.log("ABUSE_IPDB_KEY:", process.env.ABUSE_IPDB_KEY ? "SET" : "MISSING");
  console.log("IPSHIELD_API_KEY:", process.env.IPSHIELD_API_KEY ? "SET" : "MISSING");

  if (missing.length) {
    console.error("Missing:", missing.join(", "));
    process.exit(1);
  }
  console.log("✓ Environment validated");
}

module.exports = validateEnv;