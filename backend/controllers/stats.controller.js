const { getStatsData } = require("../store/memory.store");

exports.getStats = (req, res) => {
  res.json(getStatsData());
};

