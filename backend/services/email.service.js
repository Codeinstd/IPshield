console.log("[ENV CHECK]", {
  ALERT_FROM: process.env.ALERT_FROM,
  ALERT_TO: process.env.ALERT_TO,
  SMTP_USER: process.env.SMTP_USER,
});

const nodemailer = require("nodemailer");

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: parseInt(process.env.SMTP_PORT || "465"),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  return transporter;
}

async function sendEmail({ to, subject, html }) {
  const transport = getTransporter();
  const recipients = Array.isArray(to)
    ? to.join(",")
    : String(to).split(",").map(e => e.trim()).filter(Boolean).join(",");

  console.log("[EMAIL] Sending:", { from: process.env.ALERT_FROM, to: recipients, subject });

  const result = await transport.sendMail({
    from: process.env.ALERT_FROM,
    to: recipients,
    subject,
    html,
  });

  console.log("[EMAIL RESULT]:", result.messageId);
  return { delivered: true, messageId: result.messageId };
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

module.exports = { sendEmail, sendAlertEmail };