const { query } = require("./db");

// Job lifecycle

async function createJob({ jobId, ip, requestedBy, consent }) {
  const { rows } = await query(
    `INSERT INTO scan_jobs (job_id, ip, requested_by, consent)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [jobId, ip, requestedBy ?? null, !!consent]
  );

  return rows[0];
}

async function setJobRunning(jobId) {
  await query(
    `UPDATE scan_jobs
     SET status = 'running',
         started_at = NOW()
     WHERE job_id = $1`,
    [jobId]
  );
}

async function setJobDone(jobId) {
  await query(
    `UPDATE scan_jobs
     SET status = 'done',
         completed_at = NOW()
     WHERE job_id = $1`,
    [jobId]
  );
}

async function setJobFailed(jobId, error) {
  await query(
    `UPDATE scan_jobs
     SET status = 'failed',
         completed_at = NOW(),
         error = $2
     WHERE job_id = $1`,
    [jobId, String(error)]
  );
}

async function getJob(jobId) {
  const { rows } = await query(
    `SELECT
        j.*,
        COALESCE(
          json_agg(r ORDER BY r.created_at)
          FILTER (WHERE r.id IS NOT NULL),
          '[]'
        ) AS results
     FROM scan_jobs j
     LEFT JOIN scan_results r
       ON r.job_id = j.job_id
     WHERE j.job_id = $1
     GROUP BY j.id`,
    [jobId]
  );

  return rows[0] ?? null;
}

async function getRecentScans(ip, limit = 5) {
  const { rows } = await query(
    `SELECT
        j.job_id,
        j.status,
        j.created_at,
        j.completed_at,
        COALESCE(
          json_agg(r ORDER BY r.created_at)
          FILTER (WHERE r.id IS NOT NULL),
          '[]'
        ) AS results
     FROM scan_jobs j
     LEFT JOIN scan_results r
       ON r.job_id = j.job_id
     WHERE j.ip = $1
     GROUP BY j.id
     ORDER BY j.created_at DESC
     LIMIT $2`,
    [ip, limit]
  );

  return rows;
}

// Result persistence

async function saveResult({
  jobId,
  ip,
  scanner,
  raw,
  summary,
  severity,
}) {
  const { rows } = await query(
    `INSERT INTO scan_results
      (job_id, ip, scanner, raw, summary, severity)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [
      jobId,
      ip,
      scanner,
      JSON.stringify(raw),
      JSON.stringify(summary),
      severity,
    ]
  );

  return rows[0];
}

module.exports = {
  createJob,
  setJobRunning,
  setJobDone,
  setJobFailed,
  getJob,
  getRecentScans,
  saveResult,
};