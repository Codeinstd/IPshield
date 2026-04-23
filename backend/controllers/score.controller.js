const { scoreIPService } = require("../services/scoring.service");
const { addAudit } = require("../store/memory.store");
const { getFullIntel } = require("../services/ipintel.service");

exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;

    const start = Date.now();

    const result = await scoreIPService(ip);

    result.meta = {
      processingMs: Date.now() - start,
      scoredAt: new Date()
    };

    addAudit(result);

    res.json(result);
  } catch (err) {
    next(err);
  }
};

exports.getScore = (req, res) => {
  res.json({ score: 75, status: "ok ⚡" });
};

