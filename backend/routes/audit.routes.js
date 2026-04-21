const express = require("express");
const router = express.Router();
const { getAudit } = require("../controllers/audit.controller");

router.get("/", getAudit);

module.exports = router;