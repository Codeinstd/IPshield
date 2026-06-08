const { Resend } = require("resend");

let resend = null;

function getResend() {
  if (resend) return resend;

  if (!process.env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is missing");
  }

  resend = new Resend(process.env.RESEND_API_KEY);
  return resend;
}

async function sendEmail({ to, subject, html }) {
  const client = getResend();

  if (!process.env.ALERT_FROM) {
    throw new Error("ALERT_FROM is not set");
  }

  const recipients = Array.isArray(to)
    ? to
    : String(to)
        .split(",")
        .map(e => e.trim())
        .filter(Boolean);

  console.log("[EMAIL] Sending:", {
    from: process.env.ALERT_FROM,
    to: recipients,
    subject,
  });

  const result = await client.emails.send({
    from: process.env.ALERT_FROM,
    to: recipients,
    subject,
    html,
  });

  console.log("[EMAIL RESULT]:", result);

  if (result?.error) {
    console.error("[RESEND ERROR]:", result.error);
    throw new Error(result.error.message || "Email send failed");
  }

  return {
    delivered: true,
    emailId: result.data?.id,
  };
}

async function sendAlertEmail(payload) {
  if (!process.env.ALERT_TO) {
    throw new Error("ALERT_TO is not configured");
  }

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

module.exports = {
  sendEmail,
  sendAlertEmail,
};