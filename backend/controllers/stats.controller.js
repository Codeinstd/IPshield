
const { getStatsData }  = require("../store/memory.store");
const db                = require("../store/db");
const cache             = require("../store/cache");
const { getFeedStats }  = require("../services/threatfeeds.service");

exports.getStats = (req, res) => {
  const memory = getStatsData();

  const riskDistribution = db.isAvailable()
    ? db.getRiskDistribution()
    : memory.riskDistribution;

  const totalScored = db.isAvailable()
    ? db.getTotalScored()
    : memory.total;

  res.json({
    riskDistribution,
    totalScored,
    topThreats:  db.isAvailable() ? db.getTopThreats(5) : [],
    cacheSize:   cache.size(),
    dbAvailable: db.isAvailable(),
    uptime:      Math.floor(process.uptime()),
    memoryMB:    Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    threatFeeds: getFeedStats()   // ← feed status included in stats
  });
};