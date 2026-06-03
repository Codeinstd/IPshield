const bcrypt = require("bcrypt");
const db = require("../store/db");

async function seed() {
  const email = "admin@ipshield.local";
  const password = "admin123";

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    `INSERT INTO users (email, password_hash, role)
     VALUES ($1, $2, 'admin')
     ON CONFLICT (email) DO NOTHING`,
    [email, hash]
  );

  process.exit();
}

seed();