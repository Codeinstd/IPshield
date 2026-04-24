/**
 * score.routes.js
 * Place in: backend/routes/score.routes.js
 */

const express = require("express");
const router  = express.Router();
const { scoreIP, scoreBatch } = require("../controllers/score.controller");

router.get("/:ip",   scoreIP);
router.post("/batch", scoreBatch);

module.exports = router;