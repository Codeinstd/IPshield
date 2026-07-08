const PLANS = {
  free: {
    id:               "free",
    name:             "Free",
    priceYearly:     0,
    stripePriceId:    null, // no Stripe price — never goes through checkout
    description:      "Evaluate IPShield against a handful of real lookups. Request an invite code to begin.",
    featureLimits: {
      score:        5,     // IP score lookups / day
      batch:        false,
      active_scan:  false,
      watchlist:    1,     // max watched IPs
      siem_targets: 0,
    },
  },

  team: {
    id:               "team",
    name:             "Team",
    priceYearly:     70,
    stripePriceId:    process.env.STRIPE_PRICE_TEAM || "prod_Um80iodspdkeF6",
    description:      "For analysts and SOC teams running IPShield day to day — full limits, no seat minimum.",
    featureLimits: {
      score:        500000,
      batch:        100000,
      active_scan:  10000,
      watchlist:    10000,
      siem_targets: 5000,
    },
  },

};

const PLAN_ORDER = ["free", "team"];

function getPlan(planId) {
  return PLANS[planId] || PLANS.free;
}

// Map a Stripe price ID back to a plan id — used by the webhook handler.
function planForPriceId(priceId) {
  for (const plan of Object.values(PLANS)) {
    if (plan.stripePriceId && plan.stripePriceId === priceId) return plan.id;
  }
  return null;
}

// Limit for a given plan + feature. null = unlimited, false/0 = not available.
function limitFor(planId, feature) {
  const plan = getPlan(planId);
  return plan.featureLimits[feature];
}

module.exports = { PLANS, PLAN_ORDER, getPlan, planForPriceId, limitFor };