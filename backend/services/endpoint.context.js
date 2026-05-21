
const telemetry = require("../store/telemetry.store");

function getEndpointContext(method, path) {
  const summary   = telemetry.getSummary();
 
  // Normalize path: /score/8.8.8.8 -> /score/:ip
  const routeKey  = `${method} ${path}`;
  const ep        = summary.topEndpoints.find(e => e.route === routeKey);
 
  if (!ep || ep.count === 0) {
    return { hasData: false };
  }
 
  const errPct = parseFloat(ep.errorRate);
  const health =
    errPct > 20 ? "degraded" :
    errPct > 5  ? "warning"  : "healthy";
 
  return {
    hasData:   true,
    count:     ep.count,
    errorRate: ep.errorRate,
    avgMs:     ep.avgMs,
    p50:       ep.p50,
    p95:       ep.p95,
    p99:       ep.p99,
    health,
    statuses:  ep.statuses
  };
}
 
module.exports = { getEndpointContext };