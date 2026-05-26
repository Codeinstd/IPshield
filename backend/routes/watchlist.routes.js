const express = require("express");
const router = express.Router();
const { requireAuth, requireRole } = require("../middleware/auth.js");
const {body,param,validationResult} = require("express-validator");



const {
  addToWatchlist,
  removeFromWatchlist,
  getWatchlist,
  isWatched,
  watchlistSize,
  updateWatchlistEntry
} = require("../store/watchlist.store");

const {
  pollWatchlist,
  getMonitorStatus
} = require("../jobs/monitor.job");

const {
  getFullIntel
} = require("../services/ipIntel.service");

const logger = require("../utils/logger");

// GET /api/watchlist
router.get(
  "/",
  async (req, res) => {
    try {
      const watchlist = await getWatchlist();

      res.json({
        total: watchlist.length,
        monitor: getMonitorStatus(),
        watchlist
      });
    } catch (err) {
      logger.error("Watchlist fetch error:", err.message);
      console.error("WATCHLIST API FAILURE:", err);

      res.status(500).json({
        error: "Failed to load watchlist"
      });
    }
  }
);

// GET /api/watchlist/status
router.get(
  "/status",
  async (req, res) => {
    res.json(getMonitorStatus());
  }
);

// POST /api/watchlist
router.post(
  "/",
  [
    body("ip")
      .trim()
      .notEmpty()
      .custom((ip) => {
        const ipv4 =
          /^(\d{1,3}\.){3}\d{1,3}$/;

        const ipv6 =
          /^[0-9a-fA-F:]{2,45}$/;

        if (!ipv4.test(ip) && !ipv6.test(ip)) {
          throw new Error("Invalid IP address");
        }

        return true;
      }),

    body("label")
      .optional()
      .trim()
      .isLength({ max: 100 }),

    body("threshold")
      .optional()
      .isInt({ min: 0, max: 100 }),

    body("alertOnChange")
      .optional()
      .isBoolean()
  ],

  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: "Validation failed",
        errors: errors.array()
      });
    }

    try {
      const size = await watchlistSize();

      if (size >= 100) {
        return res.status(400).json({
          error: "Watchlist limit reached (100 IPs max)"
        });
      }

      const {
        ip,
        label,
        threshold = 30,
        alertOnChange = true
      } = req.body;

      const alreadyExists = await isWatched(ip);

      if (alreadyExists) {
        return res.status(409).json({
          error: "IP already exists in watchlist"
        });
      }

      const entry = await addToWatchlist({
        ip,
        label,
        threshold,
        alertOnChange
      });

      logger.info(`Watchlist: added ${ip}`);

      try {
        const result = await getFullIntel(ip);

        await updateWatchlistEntry(ip, {
          last_score: result.score,
          last_risk: result.riskLevel,
          last_checked: Date.now()
        });

        return res.status(201).json({
          message: "Added to watchlist",
          entry,
          initialScore: result
        });
      } catch (_) {
        return res.status(201).json({
          message: "Added to watchlist",
          entry
        });
      }
    } catch (err) {
      logger.error("Watchlist add error:", err.message);

      return res.status(500).json({
        error: "Failed to add IP to watchlist"
      });
    }
  }
);

// DELETE /api/watchlist/:ip
router.delete(
  "/:ip",

  [
    param("ip")
      .trim()
      .notEmpty()
  ],

  async (req, res) => {
    try {
      const ip = decodeURIComponent(req.params.ip);

      const exists = await isWatched(ip);

      if (!exists) {
        return res.status(404).json({
          error: "IP not in watchlist"
        });
      }

      await removeFromWatchlist(ip);

      logger.info(`Watchlist: removed ${ip}`);

      res.json({
        message: "Removed from watchlist",
        ip
      });
    } catch (err) {
      logger.error("Watchlist delete error:", err.message);

      res.status(500).json({
        error: "Failed to remove IP"
      });
    }
  }
);

// POST /api/watchlist/poll
router.post(
  "/poll",
  async (req, res) => {
    res.json({
      message: "Poll triggered"
    });

    pollWatchlist().catch((err) => {
      logger.error(
        "Manual poll error:",
        err.message
      );
    });
  }
);

module.exports = router;