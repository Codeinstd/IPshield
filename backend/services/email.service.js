const nodemailer = require("nodemailer");
const validator = require("validator");

let transporter = null;

/* Escape HTML to prevent injection in email templates */
function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* Create or reuse transporter */
function getTransporter() {
  if (transporter) {
    return transporter;
  }
  const port = Number(process.env.SMTP_PORT || 587);
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port,
    secure: port === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },

    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
  });

  return transporter;
}

/* Verify SMTP on startup */
async function verifySMTP() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn(
      "[EMAIL] SMTP_USER or SMTP_PASS missing. SMTP verification skipped."
    );
    return;
  }

  try {
    await getTransporter().verify();
    console.log("[EMAIL] SMTP connection verified ✓");
  } catch (err) {
    console.error("[EMAIL] SMTP verification failed:", err.message);
  }
}

/* Normalize recipients */
function normalizeRecipients(to) {
  if (Array.isArray(to)) {
    return to
      .map(email => String(email).trim())
      .filter(Boolean);
  }

  return String(to || "")
    .split(",")
    .map(email => email.trim())
    .filter(Boolean);
}

/* Send email */
async function sendEmail({
  to,
  subject,
  html,
  text,
}) {
  const fromAddr =
    process.env.ALERT_FROM ||
    process.env.SMTP_USER;

  if (!fromAddr) {
    throw new Error("ALERT_FROM or SMTP_USER must be configured");
  }

  const recipients = normalizeRecipients(to);

  if (!recipients.length) {
    throw new Error("No recipients specified");
  }

  const invalidEmails = recipients.filter(
    email => !validator.isEmail(email)
  );

  if (invalidEmails.length) {
    throw new Error(
      `Invalid recipient(s): ${invalidEmails.join(", ")}`
    );
  }

  try {
    const result = await getTransporter().sendMail({
      from: fromAddr,
      to: recipients.join(", "),
      subject,
      text: text || "Please view this message in an HTML-capable email client.",
      html,
    });

    console.log(
      `[EMAIL] Sent to ${recipients.join(", ")} (${result.messageId})`
    );

    return {
      delivered: true,
      messageId: result.messageId,
    };
  } catch (err) {
    console.error("[EMAIL ERROR]", {
      recipients,
      subject,
      error: err.message,
    });

    throw err;
  }
}

/* Invitation email */
async function sendInviteEmail(invite) {
  if (!invite?.email) {
    return;
  }

  if (!validator.isEmail(invite.email)) {
    throw new Error(`Invalid invite email: ${invite.email}`);
  }

  const name = escapeHtml(invite.name || "User");
  const role = escapeHtml(invite.role || "Member");
  const activateUrl = escapeHtml(invite.activateUrl || "");

  return sendEmail({
    to: invite.email,

    subject: "You've been invited to IPShield",

    text: `
Hi ${invite.name || "User"},

You've been granted ${invite.role || "Member"} access to IPShield.

Activate your account:

${invite.activateUrl}

This link expires in 7 days.
`.trim(),

    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;">
        <h2 style="color:#02bfe0;">
          You're invited to IPShield
        </h2>

        <p>Hi ${name},</p>

        <p>
          You've been granted
          <strong>${role}</strong>
          access to IPShield Risk Intelligence.
        </p>

        <p>
          Click the link below to activate your account
          and set your password:
        </p>

        <p style="margin:24px 0;">
          <a
            href="${activateUrl}"
            style="
              background:#02bfe0;
              color:#000;
              padding:12px 24px;
              border-radius:6px;
              text-decoration:none;
              font-weight:bold;
            "
          >
            Activate Account →
          </a>
        </p>

        <p style="font-size:12px;color:#666;">
          Or copy this link:
        </p>

        <code>${activateUrl}</code>

        <p style="font-size:11px;color:#999;margin-top:20px;">
          This link expires in 7 days.
          If you weren't expecting this email,
          you can safely ignore it.
        </p>
      </div>
    `,
  });
}

/* Security / threat alert email */
async function sendAlertEmail(payload) {
  if (!process.env.ALERT_TO) {
    throw new Error("ALERT_TO is not configured");
  }

  const riskLevel = escapeHtml(payload.riskLevel || "ALERT");
  const title = escapeHtml(payload.title || payload.ip || "Threat Detected");
  const ip = escapeHtml(payload.ip || "Unknown");
  const score = escapeHtml(payload.score || "N/A");
  const type = escapeHtml(payload.type || "Unknown");

  return sendEmail({
    to: process.env.ALERT_TO,

    subject: `[IPShield] ${riskLevel}: ${title}`,

    text: `
${riskLevel} Alert

IP: ${ip}
Score: ${score}
Type: ${type}
`.trim(),

    html: `
      <div style="font-family:Arial,sans-serif;">
        <h2>${riskLevel} Alert</h2>

        <p><strong>IP:</strong> ${ip}</p>
        <p><strong>Score:</strong> ${score}</p>
        <p><strong>Type:</strong> ${type}</p>
      </div>
    `,
  });
}

/* Verify SMTP at startup */
verifySMTP();

module.exports = {
  sendEmail,
  sendInviteEmail,
  sendAlertEmail,
  verifySMTP,
};