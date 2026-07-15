const db = require("../store/db");
const {
  sendUsageWarningEmail,
  sendUsageLimitReachedEmail,
} = require("../services/email.service");

async function maybeSendQuotaNotification({
  owner,
  feature,
  plan,
  used,
  limit,
}) {
  // Skip unlimited or unavailable features
  if (limit === null || limit === false) {
    return;
  }

  // Need an owner and email address
  if (!owner?.id || !owner.email) {
    return;
  }

  const result = await db.query(
    `
    INSERT INTO usage_notifications
    (user_id, feature, day)
    VALUES ($1, $2, CURRENT_DATE)
    ON CONFLICT (user_id, feature, day)
    DO UPDATE SET updated_at = NOW()
    RETURNING *;
    `,
    [owner.id, feature]
  );

  const notification = result.rows[0];
  const percentage = (used / limit) * 100;

  if (percentage >= 80 && !notification.warning_sent) {
    await sendUsageWarningEmail({
      email: owner.email,
      feature,
      used,
      limit,
      plan,
    });

    await db.query(
      `
      UPDATE usage_notifications
      SET warning_sent = TRUE,
          warning_sent_at = NOW(),
          updated_at = NOW()
      WHERE id = $1
      `,
      [notification.id]
    );
  }

  if (used >= limit && !notification.limit_sent) {
    await sendUsageLimitReachedEmail({
      email: owner.email,
      feature,
      used,
      limit,
      plan,
    });

    await db.query(
      `
      UPDATE usage_notifications
      SET limit_sent = TRUE,
          limit_sent_at = NOW(),
          updated_at = NOW()
      WHERE id = $1
      `,
      [notification.id]
    );
  }
}

module.exports = {
  maybeSendQuotaNotification,
};