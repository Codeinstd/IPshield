const auditLog = [];

exports.addAudit = (entry) => {
  auditLog.unshift(entry);
  if (auditLog.length > 100) auditLog.pop();
};

exports.getAuditLog = () => {
  return auditLog;
};

exports.getStatsData = () => {
  const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  auditLog.forEach(e => {
    if (dist[e.riskLevel] !== undefined) {
      dist[e.riskLevel]++;
    }
  });

  return {
    riskDistribution: dist,
    total: auditLog.length
  };
};