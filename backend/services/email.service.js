
const nodemailer = require("nodemailer");

let transporter = null;

function getTransporter() {
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST || "smtp.gmail.com",
    port:   parseInt(process.env.SMTP_PORT || "465"),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendEmail({ to, subject, html }) {
   console.log("[EMAIL DEBUG] ENV AT CALL TIME:", {
    ALERT_FROM: process.env.ALERT_FROM || "designer.oladipupo@gmail.com",
    ALERT_TO:   process.env.ALERT_TO || "designer.oladipupo@gmail.com",
    SMTP_USER:  process.env.SMTP_USER,
  });
  const transport  = getTransporter();
  const fromAddr     = process.env.ALERT_FROM || "designer.oladipupo@gmail.com";
  const recipients = Array.isArray(to)
    ? to.join(",")
    : String(to).split(",").map(e => e.trim()).filter(Boolean).join(",");

  if (!fromAddr) throw new Error("ALERT_FROM is not configured");
  if (!recipients) throw new Error("No recipients specified");

  console.log("[EMAIL] from:", fromAddr, "→ to:", recipients);

  const result = await transport.sendMail({
    from: fromAddr,
    to:   recipients,
    subject,
    html,
  });

  console.log("[EMAIL RESULT]:", result.messageId);
  return { delivered: true, messageId: result.messageId };
}

async function sendInviteEmail(invite) {
  if (!invite.email) return;  // skip if no email on the invite

  return sendEmail({
    to: invite.email,
    subject: `You've been invited to IPShield`,
    html: `
      <div style="font-family:monospace;max-width:480px;margin:0 auto;">
        <h2 style="color:#02bfe0;">You're invited to IPShield</h2>
        <p>Hi ${invite.name},</p>
        <p>You've been granted <b>${invite.role}</b> access to IPShield Risk Intelligence.</p>
        <p>Click the link below to activate your account and set your password:</p>
        <p style="margin:24px 0;">
          <a href="${invite.activateUrl}"
             style="background:#02bfe0;color:#000;padding:12px 24px;
                    border-radius:6px;text-decoration:none;font-weight:700;">
            Activate Account →
          </a>
        </p>
        <p style="font-size:12px;color:#666;">
          Or copy this link:<br>
          <code>${invite.activateUrl}</code>
        </p>
        <p style="font-size:11px;color:#999;">
          This link expires in 7 days. If you weren't expecting this, ignore this email.
        </p>
      </div>
    `,
  });
}

async function sendAlertEmail(payload) {
  if (!process.env.ALERT_TO) throw new Error("ALERT_TO is not configured");
  return sendEmail({
    to: process.env.ALERT_TO,
    subject: `[IPShield] ${payload.riskLevel || "ALERT"}: ${payload.title || payload.ip}`,
    html: `
      <div style="font-family:monospace">
        <h2>${payload.riskLevel} Alert</h2>
        <p><b>IP:</b> ${payload.ip}</p>
        <p><b>Score:</b> ${payload.score}</p>
        <p><b>Type:</b> ${payload.type}</p>
      </div>
    `,
  });
}

module.exports = { sendEmail, sendAlertEmail, sendInviteEmail };