
module.exports = {
  apps: [{
    name:        "ipshield",
    script:      "backend/server.js",
    instances:   "max",        // use all CPU cores
    exec_mode:   "cluster",    // cluster mode for multi-core
    watch:       false,        // never watch in production
    max_memory_restart: "500M",

    env: {
      NODE_ENV: "development",
      PORT:     3000
    },
    env_production: {
      NODE_ENV: "production",
      PORT:     3000
    },

    // Logging
    log_date_format: "YYYY-MM-DD HH:mm:ss",
    error_file:      "logs/pm2-error.log",
    out_file:        "logs/pm2-out.log",
    merge_logs:      true,

    // Restart strategy
    restart_delay:   3000,     // wait 3s before restart
    max_restarts:    10,
    min_uptime:      "10s",    // must stay up 10s to count as successful start

    // Graceful shutdown
    kill_timeout:    10000,    // 10s to shutdown cleanly
    listen_timeout:  5000
  }]
};