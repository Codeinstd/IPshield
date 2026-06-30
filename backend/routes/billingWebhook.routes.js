require("dotenv").config();
const express = require("express");
const router  = express.Router();
const Stripe  = require("stripe");
const db      = require("../store/db");
const { planForPriceId } = require("../config/plans");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);


router.post("/", async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("[stripe webhook] signature verification failed:", err.message);
    return res.status(400).send(`Webhook signature verification failed`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const userId = session.client_reference_id || session.metadata?.user_id;
        if (userId && session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          await applySubscriptionToUser(userId, sub);
        }
        break;
      }

      case "customer.subscription.updated":
      case "customer.subscription.created": {
        const sub = event.data.object;
        const userId = sub.metadata?.user_id || await userIdFromCustomer(sub.customer);
        if (userId) await applySubscriptionToUser(userId, sub);
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const userId = sub.metadata?.user_id || await userIdFromCustomer(sub.customer);
        if (userId) {
          await db.query(
            `UPDATE users
             SET plan = 'free', subscription_status = 'canceled',
                 stripe_subscription_id = NULL, cancel_at_period_end = FALSE,
                 updated_at = NOW()
             WHERE id = $1`,
            [userId]
          );
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const userId = await userIdFromCustomer(invoice.customer);
        if (userId) {
          await db.query(
            `UPDATE users SET subscription_status = 'past_due', updated_at = NOW() WHERE id = $1`,
            [userId]
          );
        }
        break;
      }

      default:
        // Unhandled event types are fine to ignore — Stripe sends many we don't act on.
        break;
    }

    res.json({ received: true });
  } catch (err) {
    console.error(`[stripe webhook] handler error for ${event.type}:`, err.message);
    // Still 200 — Stripe retries on non-2xx, and most failures here are our bugs,
    // not transient ones. Log loudly instead so it surfaces in Sentry/logs.
    res.json({ received: true, warning: "handler error logged" });
  }
});

async function userIdFromCustomer(customerId) {
  const result = await db.query(`SELECT id FROM users WHERE stripe_customer_id = $1`, [customerId]);
  return result.rows[0]?.id || null;
}

async function applySubscriptionToUser(userId, subscription) {
  const priceId = subscription.items?.data?.[0]?.price?.id;
  const plan    = planForPriceId(priceId) || "free";

  await db.query(
    `UPDATE users
     SET plan = $1,
         subscription_status = $2,
         stripe_subscription_id = $3,
         current_period_end = to_timestamp($4),
         cancel_at_period_end = $5,
         updated_at = NOW()
     WHERE id = $6`,
    [
      plan,
      subscription.status,
      subscription.id,
      subscription.current_period_end,
      subscription.cancel_at_period_end || false,
      userId,
    ]
  );
}

module.exports = router;
