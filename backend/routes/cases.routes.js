const express = require("express");
const router  = express.Router();
const { body, param, query, validationResult } = require("express-validator");
const {
  listCases, getCase, createCase, updateCase, deleteCase,
  addCaseIP, removeCaseIP, addCaseNote, deleteCaseNote, getCaseStats
} = require("../store/cases.store");
const logger = require("../utils/logger");

const SEVERITIES = ["CRITICAL","HIGH","MEDIUM","LOW"];
const STATUSES   = ["Open","Investigating","Contained","Resolved","Closed"];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// GET /api/cases/stats
router.get("/stats", async (req, res) => {
  try {
    const stats = await getCaseStats();
    res.json(stats);
  } catch (err) {
  next(err);
}
});

// GET /api/cases
router.get("/", [
  query("status").optional().isIn(STATUSES),
  query("severity").optional().isIn(SEVERITIES),
  query("q").optional().trim().isLength({ max: 100 }),
  query("limit").optional().isInt({ min: 1, max: 200 }),
  query("offset").optional().isInt({ min: 0 }),
], validate, async (req, res) => {
  try {
    const { status, severity, q, limit = 100, offset = 0 } = req.query;
    const result = await listCases({ status, severity, q, limit: parseInt(limit), offset: parseInt(offset) });
    res.json(result);
  } catch (err) {
  next(err);
}
});

// GET /api/cases/:id
router.get("/:id", [
  param("id").isInt({ min: 1 }),
], validate, async (req, res) => {
  try {
    const c = await getCase(parseInt(req.params.id));
    if (!c) return res.status(404).json({ error: "Case not found" });
    res.json(c);
  } catch (err) {
  next(err);
}
});

// POST /api/cases
router.post("/",  [
  body("title").trim().notEmpty().isLength({ max: 200 }),
  body("description").optional().trim().isLength({ max: 2000 }),
  body("severity").optional().isIn(SEVERITIES),
  body("status").optional().isIn(STATUSES),
  body("assigned_to").optional().trim().isLength({ max: 100 }),
  body("tags").optional().isArray(),
], validate, async (req, res) => {
  try {
    const { title, description, severity, status, assigned_to, tags } = req.body;
    const c = await createCase({ title, description, severity, status, assigned_to, tags });
    if (!c) return res.status(500).json({ error: "Failed to create case" });
    logger.info(`Case created: #${c.id} — ${title}`);
    res.status(201).json(c);
  } catch (err) {
  next(err);
}
});

// PUT /api/cases/:id
router.put("/:id", [
  param("id").isInt({ min: 1 }),
  body("title").optional().trim().isLength({ max: 200 }),
  body("description").optional().trim().isLength({ max: 2000 }),
  body("severity").optional().isIn(SEVERITIES),
  body("status").optional().isIn(STATUSES),
  body("assigned_to").optional().trim().isLength({ max: 100 }),
  body("tags").optional().isArray(),
], validate, async (req, res) => {
  try {
    const id     = parseInt(req.params.id);
    const fields = { ...req.body };

    if (["Closed","Resolved"].includes(fields.status)) {
      fields.closed_at = new Date().toISOString();
    } else if (fields.status && !["Closed","Resolved"].includes(fields.status)) {
      fields.closed_at = null;
    }

    const c = await updateCase(id, fields);
    if (!c) return res.status(404).json({ error: "Case not found" });
    logger.info(`Case updated: #${id}`);
    res.json(c);
  } catch (err) {
  next(err);
}
});

// DELETE /api/cases/:id
router.delete("/:id", [
  param("id").isInt({ min: 1 }),
], validate, async (req, res) => {
  try {
    const ok = await deleteCase(parseInt(req.params.id));
    if (!ok) return res.status(404).json({ error: "Case not found" });
    logger.info(`Case deleted: #${req.params.id}`);
    res.json({ message: "Case deleted" });
  } catch (err) {
  next(err);
}
});

// POST /api/cases/:id/ips
router.post("/:id/ips",  [
  param("id").isInt({ min: 1 }),
  body("ip").trim().notEmpty().custom(ip => {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
      throw new Error("Invalid IP");
    return true;
  }),
  body("note").optional().trim().isLength({ max: 500 }),
  body("score").optional().isInt({ min: 0, max: 100 }),
  body("risk_level").optional().isIn(["CRITICAL","HIGH","MEDIUM","LOW"]),
], validate, async (req, res) => {
  try {
    const result = await addCaseIP(parseInt(req.params.id), req.body);
    if (result.duplicate) return res.status(409).json({ error: "IP already attached to this case" });
    if (result.error)     return res.status(500).json({ error: result.error });
    res.status(201).json({ message: "IP attached to case" });
  } catch (err) {
  next(err);
}
});

// DELETE /api/cases/:id/ips/:ipId
router.delete("/:id/ips/:ipId",[
  param("id").isInt({ min: 1 }),
  param("ipId").isInt({ min: 1 }),
], validate, async (req, res) => {
  try {
    await removeCaseIP(parseInt(req.params.id), parseInt(req.params.ipId));
    res.json({ message: "IP removed from case" });
  } catch (err) {
  next(err);
}
});

// POST /api/cases/:id/notes
router.post("/:id/notes", [
  param("id").isInt({ min: 1 }),
  body("note").trim().notEmpty().isLength({ max: 2000 }),
  body("author").optional().trim().isLength({ max: 100 }),
], validate, async (req, res) => {
  try {
    const { note, author } = req.body;
    const result = await addCaseNote(parseInt(req.params.id), { note, author });
    if (!result) return res.status(500).json({ error: "Failed to add note" });
    res.status(201).json(result);
  } catch (err) {
  next(err);
}
});

// DELETE /api/cases/:id/notes/:noteId
router.delete("/:id/notes/:noteId",  [
  param("id").isInt({ min: 1 }),
  param("noteId").isInt({ min: 1 }),
], validate, async (req, res) => {
  try {
    await deleteCaseNote(parseInt(req.params.id), parseInt(req.params.noteId));
    res.json({ message: "Note deleted" });
  } catch (err) {
  next(err);
}
});

const caseAccountsRouter = require("./caseAccounts.routes");
router.use("/:id/accounts", caseAccountsRouter);

module.exports = router;