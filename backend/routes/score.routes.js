const express = require("express");
const router = express.Router();
const { scoreIP } = require("../controllers/score.controller");
const scoreController = require('../controllers/score.controller');

router.get("/:ip", scoreIP);

router.get("/:ip", (req, res) => {
  res.json({ ok: true });
});

router.get('/', scoreController.getScore);

module.exports = router;