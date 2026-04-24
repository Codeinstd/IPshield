/**
 * validateEnv.js
 * Place in: backend/utils/validateEnv.js
 * Called at the very top of server.js before anything else
 */

const REQUIRED = ["ABUSE_IPDB_KEY", "API_KEY"];
const OPTIONAL = ["VIRUSTOTAL_KEY", "SLACK_WEBHOOK", "DISCORD_WEBHOOK", "SENTRY_DSN", "ALLOWED_ORIGIN", "DATABASE_URL"];

function validateEnv() {
  const missing = REQUIRED.filter(k => !process.env[k]);

  if (missing.length) {
    console.error("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.error("  FATAL: Missing required environment variables:");
    missing.forEach(k => console.error(`    ✗ ${k}`));
    console.error("\n  Add these to your .env file and restart.");
    console.error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    process.exit(1);
  }

  const present = OPTIONAL.filter(k => process.env[k]);
  console.log("✓ Environment validated");
  if (present.length) console.log(`  Optional features active: ${present.join(", ")}`);
}

module.exports = validateEnv;