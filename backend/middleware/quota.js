const db    = require("../store/db");
const { limitFor } = require("../config/plans");

async function resolveOwner(auth) {
  if (!auth) return null;

  if (auth.type === "user") {
    const result = await db.query(
      `SELECT id, role, plan, subscription_status FROM users WHERE id = $1`,
      [auth.id]
    );
    return result.rows[0] || null;
  }

  if (auth.type === "api_key") {
    const result = await db.query(
      `SELECT u.id, u.role, u.plan, u.subscription_status
       FROM api_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.id = $1`,
      [auth.id]
    );
    return result.rows[0] || null;
  }

  return null;
}

function effectivePlan(owner) {
  if (!owner) return "free";
  if (owner.role === "admin") {
    // Locally: unlimited so development is never quota-blocked.
    // Production: team-tier limits so admins have generous headroom without
    // needing a paid subscription themselves.
    return process.env.NODE_ENV === "production" ? "team" : "enterprise";
  }
  if (owner.plan === "enterprise") return "enterprise";
  const current = owner.subscription_status === "active" || owner.subscription_status === "trialing";
  return current ? owner.plan : "free";
}

/**
 * requireQuota(feature)
 *
 * - Looks up the caller's effective plan.
 * - If the feature's limit for that plan is `false`, blocks with 403 (feature
 *   not available on this tier — upsell).
 * - If the limit is `null`, unlimited — passes through, still records usage.
 * - Otherwise checks today's usage_events counter for this owner+feature; if
 *   at or above the limit, blocks with 429. If not, increments and continues.
 *
 * Legacy API keys with no linked user_id (owner === null) fall back to the
 * free tier, matching how they'd behave if they'd just signed up today.
 */
function requireQuota(feature) {
  return async function quotaMiddleware(req, res, next) {
    try {
      const owner = await resolveOwner(req.auth);
      const plan  = effectivePlan(owner);
      const limit = limitFor(plan, feature);

      if (limit === false) {
        return res.status(403).json({
          error:   "feature_not_available",
          message: `The "${feature}" feature isn't included on the ${plan} plan.`,
          plan,
          upgrade_url: "/pricing",
        });
      }

      // Identify the counter row: prefer the linked user, fall back to the
      // api_key id itself so unlinked legacy keys still get a real per-key quota
      // rather than silently bypassing limits altogether.
      const ownerUserId = owner ? owner.id : null;
      const ownerKeyId  = (!owner && req.auth?.type === "api_key") ? req.auth.id : null;

      if (limit === null) {
        // Unlimited — still track usage for visibility, but never block.
        await incrementUsage(ownerUserId, ownerKeyId, feature);
        return next();
      }

      const used = await getUsage(ownerUserId, ownerKeyId, feature);
      if (used >= limit) {
        return res.status(429).json({
          error:      "quota_exceeded",
          message:    `Daily limit for "${feature}" reached (${limit}/day on the ${plan} plan).`,
          plan,
          limit,
          used,
          upgrade_url: "/pricing",
        });
      }

      await incrementUsage(ownerUserId, ownerKeyId, feature);
      req.quota = { plan, feature, limit, used: used + 1 };
      return next();
    } catch (err) {
      console.error("[quota]", err.message);
      // Fail open on infrastructure errors so a DB hiccup doesn't take the API down —
      // but log loudly since silent quota bypass is a real revenue gap.
      return next();
    }
  };
}

async function getUsage(userId, apiKeyId, feature) {
  const result = await db.query(
    `SELECT count FROM usage_events
     WHERE feature = $1 AND day = CURRENT_DATE
       AND ${userId ? "user_id = $2" : "api_key_id = $2"}`,
    [feature, userId || apiKeyId]
  );
  return result.rows[0]?.count || 0;
}

async function incrementUsage(userId, apiKeyId, feature) {
  const ownerCol = userId ? "user_id" : "api_key_id";
  const ownerVal = userId || apiKeyId;
  await db.query(
    `INSERT INTO usage_events (${ownerCol}, feature, day, count)
     VALUES ($1, $2, CURRENT_DATE, 1)
     ON CONFLICT (${ownerCol}, feature, day)
     DO UPDATE SET count = usage_events.count + 1, updated_at = NOW()`,
    [ownerVal, feature]
  );
}

module.exports = { requireQuota, resolveOwner, effectivePlan };