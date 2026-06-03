// middleware/auth.js
const jwt = require("jsonwebtoken");
const db = require("../store/db");
const { hashKey } = require("../utils/keyHash");

async function resolveApiKey(rawKey) {
  const keyHash = hashKey(rawKey);

  const result = await db.query(
    `SELECT id, name, role, status
     FROM api_keys
     WHERE key_hash = $1`,
    [keyHash]
  );

  return result.rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    
    // 1. JWT (PRIMARY SYSTEM)
    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.auth = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
        type: "user"
      };

      return next();
    }

   
    // 2. API KEY (SECONDARY SYSTEM)
    const rawKey = req.headers["x-api-key"];
    if (rawKey) {
      const key = await resolveApiKey(rawKey);

      if (!key || key.status !== "active") {
        return res.status(403).json({ error: "Invalid API key" });
      }

      req.auth = {
        id: key.id,
        role: key.role,
        type: "api_key"
      };

      return next();
    }

    return res.status(401).json({
      error: "Unauthorized",
      message: "Missing credentials"
    });

  } catch (err) {
    return res.status(401).json({
      error: "Unauthorized",
      message: err.message
    });
  }
}

function requireRole(minRole) {
  const rank = { readonly: 0, analyst: 1, admin: 2 };

  return (req, res, next) => {
    const userRole = req.auth?.role;

    if ((rank[userRole] ?? 0) < rank[minRole]) {
      return res.status(403).json({
        error: "Forbidden",
        message: "Insufficient permissions"
      });
    }

    next();
  };
}


function clearKeyCache() { KEY_CACHE.clear(); }

module.exports = { requireAuth, requireRole, clearKeyCache };