
const express  = require("express");
const router   = express.Router();
const { scoreIP, scoreBatch }             = require("../controllers/score.controller");
const { validateIPParam, validateBatchBody } = require("../middleware/validateIP.middleware");

router.get("/:ip",    validateIPParam,   scoreIP);
router.post("/batch", validateBatchBody, scoreBatch);

module.exports = router;