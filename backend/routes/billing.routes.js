const express = require("express");
const router  = express.Router();
const { body, validationResult } = require("express-validator");
const Stripe   = require("stripe");
const db       = require("../store/db");
const { requireAuth } = require("../middleware/auth.js");
const { PLANS, PLAN_ORDER, getPlan, planForPriceId } = require("../config/plans");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// GET /api/v2/billing/plans — public, powers the pricing page
router.get("/plans", (req, res) => {
  res.json({
    plans: PLAN_ORDER.map(id => {
      const p = PLANS[id];
      return {
        id: p.id, name: p.name, priceMonthly: p.priceMonthly,
        description: p.description, featureLimits: p.featureLimits,
      };
    }),
  });
});

// GET /api/v2/billing/me — current user's plan, status, and today's usage
router.get("/me", requireAuth, async (req, res) => {
  if (req.auth.type !== "user") {
    return res.status(403).json({ error: "user_login_required" });
  }
  try {
    const result = await db.query(
      `SELECT role, plan, subscription_status, current_period_end, cancel_at_period_end
       FROM users WHERE id = $1`,
      [req.auth.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });

    const usage = await db.query(
      `SELECT feature, count FROM usage_events WHERE user_id = $1 AND day = CURRENT_DATE`,
      [req.auth.id]
    );

    const row = result.rows[0];

    // Mirror quota.js effectivePlan() so the dashboard reflects what the
    // middleware actually enforces, not just the raw DB value.
    // Admin accounts: unlimited locally (enterprise), team limits in prod.
    let effectivePlan = row.plan;
   // Local admins bypass quotas. Reflect that in the dashboard without
// changing the actual subscription stored in the database.
if (
  row.role === "admin" &&
  process.env.NODE_ENV !== "production"
) {
  return res.json({
    ...row,
    plan: "admin",
    planDetails: {
      id: "admin",
      name: "Admin (Local)",
      featureLimits: {
        score: null,
        batch: null,
        active_scan: null,
        watchlist: null,
        siem_targets: null,
      },
    },
    usageToday: usage.rows,
  });
}

// Everyone else (including production admins) uses their actual plan.
res.json({
  ...row,
  plan: row.plan,
  planDetails: getPlan(row.plan),
  usageToday: usage.rows,
});
  } 
  
  catch (err) {
    console.error("[billing/me]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v2/billing/checkout — create a Stripe Checkout session for an upgrade
router.post("/checkout",
  requireAuth,
  [body("plan").equals("team")], // only paid plan now; free has no checkout
  validate,
  async (req, res) => {
    if (req.auth.type !== "user") {
      return res.status(403).json({ error: "user_login_required" });
    }
    try {
      const plan = getPlan(req.body.plan);
      if (!plan.stripePriceId) {
        return res.status(400).json({ error: "plan_not_purchasable" });
      }

      const userResult = await db.query(`SELECT id, email, stripe_customer_id FROM users WHERE id = $1`, [req.auth.id]);
      const user = userResult.rows[0];
      if (!user) return res.status(404).json({ error: "User not found" });

      let customerId = user.stripe_customer_id;
      if (!customerId) {
        const customer = await stripe.customers.create({
          email:    user.email,
          metadata: { user_id: String(user.id) },
        });
        customerId = customer.id;
        await db.query(`UPDATE users SET stripe_customer_id = $1, updated_at = NOW() WHERE id = $2`, [customerId, user.id]);
      }

      const baseUrl = process.env.PUBLIC_BASE_URL || "https://ipshield.live";
      const session = await stripe.checkout.sessions.create({
        mode:                 "subscription",
        customer:             customerId,
        line_items:           [{ price: plan.stripePriceId, quantity: 1 }],
        success_url:          `${baseUrl}/dashboard?upgrade=success`,
        cancel_url:           `${baseUrl}/pricing?upgrade=cancelled`,
        client_reference_id:  String(user.id),
        subscription_data:    { metadata: { user_id: String(user.id), plan: plan.id } },
        allow_promotion_codes: true,
      });

      res.json({ checkoutUrl: session.url });
    } catch (err) {
      console.error("[billing/checkout]", err.message);
      res.status(500).json({ error: "Failed to create checkout session" });
    }
  }
);

// POST /api/v2/billing/portal — Stripe customer portal link, for self-serve cancel/upgrade/payment method updates
router.post("/portal", requireAuth, async (req, res) => {
  if (req.auth.type !== "user") {
    return res.status(403).json({ error: "user_login_required" });
  }
  try {
    const result = await db.query(`SELECT stripe_customer_id FROM users WHERE id = $1`, [req.auth.id]);
    const customerId = result.rows[0]?.stripe_customer_id;
    if (!customerId) {
      return res.status(400).json({ error: "no_subscription", message: "No billing account yet — subscribe first." });
    }

    const baseUrl = process.env.PUBLIC_BASE_URL || "https://ipshield.live";
    const portalSession = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: `${baseUrl}/dashboard`,
    });
    res.json({ portalUrl: portalSession.url });
  } catch (err) {
    console.error("[billing/portal]", err.message);
    res.status(500).json({ error: "Failed to create portal session" });
  }
});

// POST /api/v2/billing/cancel — schedule cancellation at the end of the current period.
// Subscription stays active (full Team access) until current_period_end, then the
// webhook's customer.subscription.updated/deleted handler drops the user to free.
router.post("/cancel", requireAuth, async (req, res) => {
  if (req.auth.type !== "user") {
    return res.status(403).json({ error: "user_login_required" });
  }
  try {
    const result = await db.query(
      `SELECT stripe_subscription_id, subscription_status FROM users WHERE id = $1`,
      [req.auth.id]
    );
    const user = result.rows[0];
    if (!user?.stripe_subscription_id) {
      return res.status(400).json({ error: "no_subscription", message: "No active subscription to cancel." });
    }
    if (user.subscription_status !== "active" && user.subscription_status !== "trialing") {
      return res.status(400).json({ error: "not_active", message: "Subscription is not currently active." });
    }

    const sub = await stripe.subscriptions.update(user.stripe_subscription_id, {
      cancel_at_period_end: true,
    });

    // Update local state immediately rather than waiting on the webhook round-trip,
    // so the dashboard reflects the change instantly. The webhook will reconfirm this
    // on its own delivery, which is a harmless no-op duplicate write.
    await db.query(
      `UPDATE users SET cancel_at_period_end = TRUE, updated_at = NOW() WHERE id = $1`,
      [req.auth.id]
    );

    res.json({
      message: "Subscription will cancel at the end of the current billing period.",
      cancelAtPeriodEnd: true,
      currentPeriodEnd: new Date(sub.current_period_end * 1000).toISOString(),
    });
  } catch (err) {
    console.error("[billing/cancel]", err.message);
    res.status(500).json({ error: "Failed to cancel subscription" });
  }
});

// POST /api/v2/billing/resume — undo a scheduled cancellation, while still inside
// the paid period. This does NOT create a new subscription or charge anything;
// it simply un-sets cancel_at_period_end on the existing live subscription.
router.post("/resume", requireAuth, async (req, res) => {
  if (req.auth.type !== "user") {
    return res.status(403).json({ error: "user_login_required" });
  }
  try {
    const result = await db.query(
      `SELECT stripe_subscription_id, cancel_at_period_end FROM users WHERE id = $1`,
      [req.auth.id]
    );
    const user = result.rows[0];
    if (!user?.stripe_subscription_id) {
      return res.status(400).json({ error: "no_subscription", message: "No subscription to resume." });
    }
    if (!user.cancel_at_period_end) {
      return res.status(400).json({ error: "not_canceling", message: "Subscription is not scheduled to cancel." });
    }

    await stripe.subscriptions.update(user.stripe_subscription_id, {
      cancel_at_period_end: false,
    });

    await db.query(
      `UPDATE users SET cancel_at_period_end = FALSE, updated_at = NOW() WHERE id = $1`,
      [req.auth.id]
    );

    res.json({ message: "Subscription resumed — it will continue renewing as normal.", cancelAtPeriodEnd: false });
  } catch (err) {
    console.error("[billing/resume]", err.message);
    res.status(500).json({ error: "Failed to resume subscription" });
  }
});

module.exports = router;