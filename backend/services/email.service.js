const { Resend } = require("resend");

let resend = null;

function getResend() {
  if (resend) return resend;

  if (!process.env.RESEND_API_KEY) {
    return null;
  }

  resend = new Resend(process.env.RESEND_API_KEY);
  return resend;
}

async function sendEmail({ to, subject, html }) {
  const client = getResend();

  if (!client) {
    return {
      skipped: true,
      reason: "RESEND_API_KEY not configured",
    };
  }

  const recipients = Array.isArray(to)
    ? to
    : String(to)
        .split(",")
        .map(email => email.trim())
        .filter(Boolean);

  const result = await client.emails.send({
    from: process.env.ALERT_FROM,
    to: recipients,
    subject,
    html,
  });

  if (result.error) {
    throw new Error(result.error.message);
  }

  return {
    delivered: true,
    emailId: result.data?.id,
  };
}

async function sendAlertEmail(payload) {
  return sendEmail({
    to: process.env.ALERT_TO,
    subject: `[IPShield] ${payload.riskLevel || "ALERT"}: ${payload.title || payload.ip}`,
    html: buildAlertTemplate(payload),
  });
}

function buildInviteTemplate(invite) {
  return `
    <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:560px;margin:0 auto;">
      <h2 style="color:#c9d8e8;">
        IP<span style="color:#00d9ff;">Shield</span> — You're invited
      </h2>

      <p style="color:#8fa8bc;">
        Hi ${invite.name},
        <br><br>
        You've been granted access to the IPShield.
        <br>
        Click below to activate your key:
      </p>

      <div style="margin:24px 0;text-align:center;">
        <a href="${invite.activateUrl}"
           style="background:#00d9ff;color:#000;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;display:inline-block;">
          Activate API Key →
        </a>
      </div>

      <p style="color:#4a6278;font-size:11px;">
        Role: ${invite.role}
        · Daily limit: ${invite.daily_limit} requests
        <br>
        This link expires in 3 days.
      </p>
    </div>
  `;
}

async function sendInviteEmail(invite) {
  return sendEmail({
    to: invite.email,
    subject: "Your IPShield API Access",
    html: buildInviteTemplate(invite),
  });
}

module.exports = {
  sendEmail,
  sendInviteEmail,
  sendAlertEmail,
};