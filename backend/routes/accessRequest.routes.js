const express = require("express");
const router  = express.Router();
const { body, validationResult } = require("express-validator");

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
  ],
  validate,
  async (req, res) => {
    const { name, email, company } = req.body;
    const ts = new Date().toLocaleString();

    // ── Email alert (reuses your existing SMTP setup)
    if (process.env.SMTP_HOST) {
      try {
        const nodemailer  = require("nodemailer");
        const transporter = nodemailer.createTransport({
          host:   process.env.SMTP_HOST,
          port:   parseInt(process.env.SMTP_PORT || "587"),
          secure: process.env.SMTP_PORT === "465",
          auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
        await transporter.sendMail({
          from:    process.env.ALERT_FROM || process.env.SMTP_USER,
          to:      process.env.ALERT_TO   || process.env.SMTP_USER,
          subject: `[IPShield] New Access Request — ${name}`,
          html: `
            <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:520px;margin:0 auto;">
              <h2 style="color:#c9d8e8;margin-bottom:20px;">
                IP<span style="color:#00d9ff;">Shield</span> — New Access Request
              </h2>
              <table style="width:100%;border-collapse:collapse;font-size:13px;">
                ${[["Name",name],["Email",email],["Organisation",company],["Submitted",ts]]
                  .map(([k,v]) => `
                    <tr>
                      <td style="padding:8px 12px;color:#4a6278;border-bottom:1px solid #1e2d3d;width:120px;">${k}</td>
                      <td style="padding:8px 12px;color:#c9d8e8;border-bottom:1px solid #1e2d3d;">${v}</td>
                    </tr>`).join("")}
              </table>
              <div style="margin-top:24px;padding:12px 16px;background:#111820;border-radius:8px;border-left:3px solid #00d9ff;">
                <p style="color:#6a8fa8;font-size:12px;margin:0;">
                  Review and create an invite via the 
                  <a href="${process.env.APP_URL || ""}/dashboard" style="color:#00d9ff;">Key Manager panel</a>.
                </p>
              </div>
            </div>`,
        });
      } catch (err) {
        console.error("[access-request] SMTP error:", err.message);
      }
    }

    // ── Slack alert (reuses your existing webhook setup)
    if (process.env.SLACK_WEBHOOK_URL) {
      try {
        await fetch(process.env.SLACK_WEBHOOK_URL, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: `*New IPShield Access Request*`,
            attachments: [{
              color: "#00d9ff",
              fields: [
                { title: "Name",         value: name,    short: true },
                { title: "Email",        value: email,   short: true },
                { title: "Organisation", value: company, short: true },
                { title: "Submitted",    value: ts,      short: true },
              ],
              footer: "IPShield Access Requests",
            }],
          }),
        });
      } catch (err) {
        console.error("[access-request] Slack error:", err.message);
      }
    }

    res.status(200).json({ ok: true });
  }
);

module.exports = router;