const express   = require("express");
const router    = express.Router();
const jwt       = require("jsonwebtoken");
const db        = require("../store/db");
const { hashKey } = require("../utils/keyHash");

// POST /api/v1/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password, apiKey } = req.body;

    //  Login with API key directly 
    if (apiKey) {
      const keyHash = hashKey(apiKey);
      const result  = await db.query(
        `SELECT id, name, email, role, status
         FROM api_keys
         WHERE key_hash = $1`,
        [keyHash]
      );

      if (!result.rows.length) {
        return res.status(401).json({ error: "Invalid API key" });
      }

      const key = result.rows[0];

      if (key.status !== "active") {
        return res.status(403).json({
          error: `Account is ${key.status}`
        });
      }

      const token = jwt.sign(
        { id: key.id, name: key.name, email: key.email, role: key.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      return res.json({
        token,
        user: { id: key.id, name: key.name, email: key.email, role: key.role },
      });
    }
    // Login with email + password 
if (email && password) {
  const result = await db.query(
    `SELECT id, name, email, role, status, password_hash
     FROM api_keys
     WHERE LOWER(email) = LOWER($1) AND status = 'active'`,
    [email.trim()]
  );

  if (!result.rows.length) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const user = result.rows[0];

  if (!user.password_hash) {
    return res.status(401).json({
      error: "Password not set — use your activation link to set a password first"
    });
  }

  const bcrypt  = require("bcryptjs");
  const isValid = await bcrypt.compare(password, user.password_hash);

  if (!isValid) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  return res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
}

    return res.status(400).json({ error: "Provide apiKey or email + password" });

  } catch (err) {
    console.error("[auth/login] ERROR:", err.message);
    console.error("[auth/login] STACK:", err.stack);
    res.status(500).json({
    error:  "Login failed",
    detail: err.message, 
  });
  }
});

// POST /api/v1/auth/logout
router.post("/logout", (req, res) => {
  // JWT is stateless — client just drops the token
  res.json({ message: "Logged out" });
});

// GET /api/v1/auth/me
router.get("/me", async (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({
      id:    decoded.id,
      name:  decoded.name,
      email: decoded.email,
      role:  decoded.role,
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

module.exports = router;