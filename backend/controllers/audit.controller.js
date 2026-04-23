const { getAuditLog } = require("../store/memory.store");
exports.getAudit = (req, res) => {
  res.json(getAuditLog());
};
