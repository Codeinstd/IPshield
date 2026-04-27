/**
 * watchlist.routes.js
 * Place in: backend/routes/watchlist.routes.js
 */

const express = require("express");
const router  = express.Router();
const { body, param, validationResult } = require("express-validator");

const {
  addToWatchlist, removeFromWatchlist,
  getWatchlist, isWatched, watchlistSize
} = require("../store/watchlist.store");

const { pollWatchlist, getMonitorStatus } = require("../jobs/monitor.job");
const { getFullIntel } = require("../services/ipIntel.service");
const { updateWatchlistEntry } = require("../store/watchlist.store");
const logger                  = require("../utils/logger");

// GET /api/watchlist
router.get("/", (req, res) => {
  res.json({ total: getWatchlist().length, monitor: getMonitorStatus(), watchlist: getWatchlist() });
});

// GET /api/watchlist/status
router.get("/status", (req, res) => {
  res.json(getMonitorStatus());
});

// POST /api/watchlist
router.post("/",
  [
    body("ip").trim().notEmpty().custom(ip => {
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
        throw new Error("Invalid IP address");
      return true;
    }),
    body("label").optional().trim().isLength({ max: 100 }),
    body("threshold").optional().isInt({ min: 0, max: 100 }),
    body("alertOnChange").optional().isBoolean()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

    if (watchlistSize() >= 100) return res.status(400).json({ error: "Watchlist limit reached (100 IPs max)" });

    const { ip, label, threshold = 30, alertOnChange = true } = req.body;
    const entry = addToWatchlist({ ip, label, threshold, alertOnChange });
    logger.info(`Watchlist: added ${ip}`);

    try {
      const result = await getFullIntel(ip);
      updateWatchlistEntry(ip, { last_score: result.score, last_risk: result.riskLevel, last_checked: Date.now() });
      res.status(201).json({ message: "Added to watchlist", entry, initialScore: result });
    } catch (_) {
      res.status(201).json({ message: "Added to watchlist", entry });
    }
  }
);

// DELETE /api/watchlist/:ip
router.delete("/:ip",
  [param("ip").trim().notEmpty()],
  (req, res) => {
    const ip = decodeURIComponent(req.params.ip);
    if (!isWatched(ip)) return res.status(404).json({ error: "IP not in watchlist" });
    removeFromWatchlist(ip);
    logger.info(`Watchlist: removed ${ip}`);
    res.json({ message: "Removed from watchlist", ip });
  }
);

// POST /api/watchlist/poll
router.post("/poll", async (req, res) => {
  res.json({ message: "Poll triggered" });
  pollWatchlist().catch(err => logger.error("Manual poll error:", err.message));
});

module.exports = router;