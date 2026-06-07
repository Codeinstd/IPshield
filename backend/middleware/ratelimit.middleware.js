const rateLimit = require("express-rate-limit");

const rateLimitHits = new Map(); 

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {

    // Track the hit
    rateLimitHits.set(req.path, (rateLimitHits.get(req.path) || 0) + 1);

    res.status(429).json({
      error: "Too many requests, slow down.",
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

app.use("/api", limiter); 

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});


module.exports = { rateLimitHits };