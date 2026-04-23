const { getStatsData } = require("../store/memory.store");
const { getFullIntel } = require("../services/ipintel.service");


exports.getStats = (req, res) => {
  res.json(getStatsData());
};

