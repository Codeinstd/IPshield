
const net = require("net");

const MAX_IPS        = 200;
const MIN_THRESHOLD  = 0;
const MAX_THRESHOLD  = 100;
const MAX_TAGS       = 20;
const MAX_TAG_LENGTH = 64;

function isValidIP(ip) {
  return typeof ip === "string" && net.isIP(ip) !== 0;
}

exports.validateBatchAndBlockBody = (req, res, next) => {
  const {
    ips,
    auto_block_threshold,
    dry_run,
    severity_map,
    tags,
    added_by,
    expires_at,
  } = req.body;

  // ── ips 
  if (!Array.isArray(ips) || ips.length === 0) {
    return res.status(400).json({
      error:   "Validation failed",
      message: "`ips` must be a non-empty array",
    });
  }
  if (ips.length > MAX_IPS) {
    return res.status(400).json({
      error:   "Validation failed",
      message: `Maximum ${MAX_IPS} IPs per request (got ${ips.length})`,
    });
  }
  const invalidIPs = ips.filter(ip => !isValidIP(ip));
  if (invalidIPs.length) {
    return res.status(400).json({
      error:   "Validation failed",
      message: `Invalid IP addresses: ${invalidIPs.slice(0, 5).join(", ")}${invalidIPs.length > 5 ? ` … (+${invalidIPs.length - 5} more)` : ""}`,
    });
  }

  // ── auto_block_threshold 
  if (auto_block_threshold !== undefined) {
    const t = Number(auto_block_threshold);
    if (!Number.isInteger(t) || t < MIN_THRESHOLD || t > MAX_THRESHOLD) {
      return res.status(400).json({
        error:   "Validation failed",
        message: "`auto_block_threshold` must be an integer between 0 and 100",
      });
    }
    req.body.auto_block_threshold = t;
  }

  // ── dry_run 
  if (dry_run !== undefined && typeof dry_run !== "boolean") {
    return res.status(400).json({
      error:   "Validation failed",
      message: "`dry_run` must be a boolean",
    });
  }

  // ── severity_map
  if (severity_map !== undefined) {
    if (typeof severity_map !== "object" || Array.isArray(severity_map)) {
      return res.status(400).json({
        error:   "Validation failed",
        message: "`severity_map` must be an object",
      });
    }
    const allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    for (const key of Object.keys(severity_map)) {
      if (!allowed.includes(key)) {
        return res.status(400).json({
          error:   "Validation failed",
          message: `Unknown severity_map key: "${key}". Allowed: ${allowed.join(", ")}`,
        });
      }
      const v = Number(severity_map[key]);
      if (!Number.isInteger(v) || v < 0 || v > 100) {
        return res.status(400).json({
          error:   "Validation failed",
          message: `severity_map.${key} must be an integer between 0 and 100`,
        });
      }
    }
  }

  // ── tags 
  if (tags !== undefined) {
    if (!Array.isArray(tags)) {
      return res.status(400).json({
        error:   "Validation failed",
        message: "`tags` must be an array of strings",
      });
    }
    if (tags.length > MAX_TAGS) {
      return res.status(400).json({
        error:   "Validation failed",
        message: `Maximum ${MAX_TAGS} tags allowed`,
      });
    }
    const badTag = tags.find(t => typeof t !== "string" || t.length > MAX_TAG_LENGTH);
    if (badTag !== undefined) {
      return res.status(400).json({
        error:   "Validation failed",
        message: `Each tag must be a string ≤ ${MAX_TAG_LENGTH} characters`,
      });
    }
  }

  // ── added_by 
  if (added_by !== undefined && (typeof added_by !== "string" || added_by.length > 128)) {
    return res.status(400).json({
      error:   "Validation failed",
      message: "`added_by` must be a string ≤ 128 characters",
    });
  }

  // ── expires_at 
  if (expires_at !== undefined && expires_at !== null) {
    const d = new Date(expires_at);
    if (isNaN(d.getTime()) || d <= new Date()) {
      return res.status(400).json({
        error:   "Validation failed",
        message: "`expires_at` must be a valid future ISO 8601 datetime or null",
      });
    }
  }

  next();
};