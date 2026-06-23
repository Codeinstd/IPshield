const express = require("express");
const router  = express.Router();
const { body, validationResult } = require("express-validator");
const { sendEmail } = require("../services/email.service");
const COMPANY_TYPES = [
"Bank / Financial Services","Education / University","Healthcare",
"Government / Public Sector","Technology / SaaS","E-commerce / Retail",
"Telecommunications","Consulting / MSSP","Other",
];
  function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  next();
  }
  router.post("/",
    [
      body("name").trim().notEmpty().isLength({ max: 100 }).withMessage("Name is required"),
      body("email").isEmail().normalizeEmail().withMessage("Valid email required"),
      body("company").isIn(COMPANY_TYPES).withMessage("Invalid organisation type"),
      body("request_type").optional().isIn(["access", "pilot"]).withMessage("Invalid request type"),
      body("team_size").optional({ checkFalsy: true }).isString().isLength({ max: 50 }).withMessage("Invalid team size"),
        ],
      validate,
      async (req, res) => {
      const { name, email, company, request_type = "access", team_size } = req.body;
      const isPilot = request_type === "pilot";
      const ts = new Date().toLocaleString();
      // Email alert (SMTP setup)
      try {
      await sendEmail({
      to: process.env.ALERT_TO,
      subject: `[IPShield] New ${isPilot ? "Pilot" : "Access"} Request — ${name}`,
      html: `
            <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:520px;margin:0 auto;">
              <h2 style="color:#c9d8e8;margin-bottom:20px;">
                IP<span style="color:#00d9ff;">Shield</span> — New ${isPilot ? "Pilot" : "Access"} Request
              </h2>
              <table style="width:100%;border-collapse:collapse;font-size:13px;">
      ${[
                  ["Name", name],
                  ["Email", email],
                  ["Organisation", company],
                  ...(isPilot && team_size ? [["Team Size", team_size]] : []),
                  ["Submitted", ts],
                ]
                  .map(
                    ([k, v]) => `
                    <tr>
                      <td style="padding:8px 12px;color:#4a6278;border-bottom:1px solid #1e2d3d;width:120px;">
      ${k}
                      </td>
                      <td style="padding:8px 12px;color:#c9d8e8;border-bottom:1px solid #1e2d3d;">
          ${v}
                    </td>
                  </tr>
                `
                )
                .join("")}
            </table>
          </div>
        `,
          });
        } catch (err) {
    console.error("[ACCESS EMAIL ERROR]", err);
        }
    // Slack alert (reuses your existing webhook setup)
    if (process.env.SLACK_WEBHOOK_URL) {
    try {
    const slackRes = await fetch(process.env.SLACK_WEBHOOK_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
    text: `*New IPShield ${isPilot ? "Pilot" : "Access"} Request*`,
    attachments: [{
    color: isPilot ? "#00e87c" : "#00d9ff",
    fields: [
                { title: "Name",         value: name,    short: true },
                { title: "Email",        value: email,   short: true },
                { title: "Organisation", value: company, short: true },
                ...(isPilot && team_size ? [{ title: "Team Size", value: team_size, short: true }] : []),
                { title: "Submitted",    value: ts,      short: true },
              ],
    footer: "IPShield Access Requests",
                }],
              }),
            });
            if (!slackRes.ok) {
              const bodyText = await slackRes.text().catch(() => "<unreadable response body>");
              console.error(
                "[ACCESS SLACK ERROR]",
                `Slack webhook returned ${slackRes.status} ${slackRes.statusText}:`,
                bodyText
              );
            }
          } catch (err) {
            console.error("[ACCESS SLACK ERROR]", err.message, err.stack);
          }
        } else {
          console.warn("[ACCESS SLACK] SLACK_WEBHOOK_URL not set — skipping Slack notification");
        }
    res.status(200).json({ ok: true });
      }
    );
module.exports = router;