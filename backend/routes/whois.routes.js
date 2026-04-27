/**
 * whois.routes.js
 * Place in: backend/routes/whois.routes.js
 *
 * GET /api/whois/:ip  — full WHOIS/RDAP deep dive for an IP
 */

const express = require("express");
const router  = express.Router();
const { param, validationResult } = require("express-validator");
const { getWhoisIntel } = require("../services/whois.service");
const logger = require("../utils/logger");

router.get("/:ip",
  [
    param("ip").trim().notEmpty().custom(ip => {
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
        throw new Error("Invalid IP address");
      return true;
    })
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

    try {
      const ip     = req.params.ip;
      logger.info(`WHOIS lookup: ${ip}`);
      const result = await getWhoisIntel(ip);
      res.json(result);
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;