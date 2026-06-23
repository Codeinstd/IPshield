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

function buildBrandedEmailHTML({ heading, accentColor = "#00d9ff", rows = [], bodyHtml = "", footerHtml = "" }) {
  const rowsHtml = rows
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(
      ([k, v]) => `
              <tr>
                <td style="padding:8px 12px;color:#4a6278;border-bottom:1px solid #1e2d3d;width:140px;vertical-align:top;">
                  ${escapeHtml(k)}
                </td>
                <td style="padding:8px 12px;color:#c9d8e8;border-bottom:1px solid #1e2d3d;">
                  ${v}
                </td>
              </tr>`
    )
    .join("");

  return `
    <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:520px;margin:0 auto;">
      <h2 style="color:#c9d8e8;margin-bottom:20px;">
        IP<span style="color:#00d9ff;">Shield</span> — <span style="color:${accentColor};">${escapeHtml(heading)}</span>
      </h2>
      ${bodyHtml}
      ${rows.length ? `
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        ${rowsHtml}
      </table>` : ""}
      ${footerHtml}
    </div>`;
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

  const bodyHtml = `
    <p style="color:#c9d8e8;font-size:13px;line-height:1.7;margin-bottom:16px;">
      Hi ${name}, you've been granted <strong style="color:#00d9ff;">${role}</strong> access
      to IPShield Risk Intelligence.
    </p>
    <p style="color:#6a8fa8;font-size:12px;margin-bottom:20px;">
      Click below to activate your account and set your password.
    </p>
    <p style="margin:24px 0;">
      <a href="${activateUrl}" style="background:#00d9ff;color:#000;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;font-family:monospace;font-size:13px;letter-spacing:1px;">
        ACTIVATE ACCOUNT →
      </a>
    </p>
    <p style="font-size:11px;color:#4a6278;margin-bottom:4px;">Or copy this link:</p>
    <code style="color:#00d9ff;font-size:11px;word-break:break-all;">${activateUrl}</code>`;

  const footerHtml = `
    <p style="font-size:11px;color:#3d5a72;margin-top:24px;border-top:1px solid #1e2d3d;padding-top:16px;">
      This link expires in 7 days. If you weren't expecting this email, you can safely ignore it.
    </p>`;

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

    html: buildBrandedEmailHTML({
      heading: "You're Invited",
      bodyHtml,
      footerHtml,
    }),
  });
}

const ALERT_RISK_COLORS = {
  CRITICAL: "#FF3355",
  HIGH:     "#FF7700",
  MEDIUM:   "#FFCC00",
  LOW:      "#00E87C",
};

/* Security / threat alert email */
async function sendAlertEmail(payload) {
  if (!process.env.ALERT_TO) {
    throw new Error("ALERT_TO is not configured");
  }

  const riskLevel = escapeHtml(payload.riskLevel || "ALERT");
  const title     = escapeHtml(payload.title || payload.ip || "Threat Detected");
  const ip        = escapeHtml(payload.ip || "Unknown");
  const score     = escapeHtml(String(payload.score ?? "N/A"));
  const type      = escapeHtml(payload.type || "Unknown");
  const action    = escapeHtml(payload.action || "");
  const location  = escapeHtml(payload.location || "");
  const isp       = escapeHtml(payload.isp || "");
  const flags     = escapeHtml(payload.flags || "");

  const accentColor = ALERT_RISK_COLORS[payload.riskLevel] || "#00d9ff";

  return sendEmail({
    to: process.env.ALERT_TO,

    subject: `[IPShield] ${riskLevel}: ${title}`,

    text: `
${riskLevel} Alert

IP: ${ip}
Score: ${score}/100
Type: ${type}
${action ? `Action: ${action}\n` : ""}${location ? `Location: ${location}\n` : ""}${isp ? `ISP: ${isp}\n` : ""}${flags ? `Flags: ${flags}\n` : ""}`.trim(),

    html: buildBrandedEmailHTML({
      heading: `${payload.riskLevel || "ALERT"} Alert`,
      accentColor,
      rows: [
        ["IP",       `<span style="font-weight:700;">${ip}</span>`],
        ["Score",    `<span style="color:${accentColor};font-weight:700;">${score}/100</span>`],
        ["Risk Level", `<span style="color:${accentColor};font-weight:700;">${riskLevel}</span>`],
        ["Type",     type],
        ["Action",   action],
        ["Location", location],
        ["ISP",      isp],
        ["Flags",    flags],
      ],
    }),
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