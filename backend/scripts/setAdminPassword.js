const bcrypt = require("bcrypt");
const db     = require("../store/db");

async function setAdminPassword() {
  const email    = process.argv[2];
  const password = process.argv[3];

  if (!email || !password) {
    console.error("Usage: node setAdminPassword.js <email> <password>");
    console.error("Example: node setAdminPassword.js admin@company.com MySecurePass123");
    process.exit(1);
  }

  if (password.length < 8) {
    console.error("Password must be at least 8 characters");
    process.exit(1);
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    // Check if admin exists
    const existing = await db.query(
      `SELECT id, name, email, role, status FROM api_keys WHERE role = 'admin'`
    );

    if (!existing.rows.length) {
      console.error("No admin account found in api_keys table.");
      console.error("Create one first via the invite system or directly:");
      console.error(`
        INSERT INTO api_keys (name, email, role, status, password_hash, daily_limit)
        VALUES ('Admin', '${email}', 'admin', 'active', '${hash}', 999999);
      `);
      process.exit(1);
    }

    // Update by email if provided, otherwise update first admin found
    const target = existing.rows.find(r => r.email === email) || existing.rows[0];

    const result = await db.query(
      `UPDATE api_keys
       SET password_hash = $1,
           email         = $2,
           status        = 'active'
       WHERE id = $3
       RETURNING id, name, email, role, status`,
      [hash, email, target.id]
    );

    const updated = result.rows[0];
    console.log("✓ Admin password set successfully");
    console.log(`  ID:     ${updated.id}`);
    console.log(`  Name:   ${updated.name}`);
    console.log(`  Email:  ${updated.email}`);
    console.log(`  Role:   ${updated.role}`);
    console.log(`  Status: ${updated.status}`);
    console.log("");
    console.log("You can now log in with:");
    console.log(`  Email:    ${email}`);
    console.log(`  Password: ${password}`);

  } catch (err) {
    console.error("Error:", err.message);
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

setAdminPassword();