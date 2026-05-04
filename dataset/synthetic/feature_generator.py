"""Synthetic feature-planning intent generator.

Mirror of dataset/synthetic/generator.py, pivoted from rollout/migration
intents to feature-shipping intents. Each generated element is a
realistic feature spec with ground-truth signals the bench scorer can
check:

  - expected_blocking_stakeholders: personas who MUST flag blocking constraints
  - expected_axes: constraint axes that should appear
  - expected_launch_strategy: what makes sense (feature_flag, beta, etc.)
  - min_estimated_days / max_estimated_days: order-of-magnitude sanity bound
  - regulated: True if compliance review is a hard requirement

Scale: 200 elements. Smaller than the rollout dataset (10k) because
feature planning is judge-scored, harder to literal-match, and 200 is
already enough for stable α=0.05 detection of 10pp deltas.
"""

from __future__ import annotations

import json
import random
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "dataset" / "data" / "synthetic" / "feature_synthetic.jsonl"


# --- Axes ---------------------------------------------------------------

FEATURE_KINDS = [
    {"slug": "sso_oauth", "name": "OAuth SSO for {tier} tier",
     "scope_template": "{provider} SSO via OIDC, account-linking flow, "
                       "domain-based auto-provisioning",
     "blocking_personas": ["ProductPM", "EngLead", "Security"],
     "axes": ["scope", "eng", "security", "ux"],
     "launch_strategy": "feature_flag",
     "size_days": (25, 60),
     "regulated": True},
    {"slug": "billing_metered", "name": "Metered billing for {tier} tier",
     "scope_template": "usage-event collection, invoice generation, "
                       "self-serve plan changes, dunning flow",
     "blocking_personas": ["ProductPM", "EngLead", "Security", "GTM"],
     "axes": ["scope", "eng", "security", "gtm"],
     "launch_strategy": "gradual_rollout",
     "size_days": (40, 90),
     "regulated": True},
    {"slug": "realtime_collab", "name": "Real-time collaborative editing",
     "scope_template": "CRDT-based cursor sync, presence indicators, "
                       "conflict resolution UI",
     "blocking_personas": ["ProductPM", "Designer", "EngLead"],
     "axes": ["scope", "ux", "eng"],
     "launch_strategy": "beta_program",
     "size_days": (45, 100),
     "regulated": False},
    {"slug": "search_global", "name": "Global search across workspaces",
     "scope_template": "full-text + filters, result ranking, "
                       "permission-aware result filtering",
     "blocking_personas": ["ProductPM", "EngLead", "Security"],
     "axes": ["scope", "eng", "security", "ux"],
     "launch_strategy": "gradual_rollout",
     "size_days": (30, 70),
     "regulated": False},
    {"slug": "mobile_parity", "name": "Mobile feature parity for {feature}",
     "scope_template": "iOS and Android native screens, offline support, "
                       "push notification integration",
     "blocking_personas": ["ProductPM", "Designer", "EngLead", "QA"],
     "axes": ["scope", "ux", "eng", "quality"],
     "launch_strategy": "gradual_rollout",
     "size_days": (35, 80),
     "regulated": False},
    {"slug": "ai_assistant", "name": "AI assistant for {workflow}",
     "scope_template": "RAG-based answers, prompt-injection guards, "
                       "PII redaction, usage cost guardrails",
     "blocking_personas": ["ProductPM", "EngLead", "Security", "GTM"],
     "axes": ["scope", "eng", "security", "gtm"],
     "launch_strategy": "beta_program",
     "size_days": (35, 80),
     "regulated": True},
    {"slug": "analytics_export", "name": "Customer-facing analytics export",
     "scope_template": "CSV / Parquet export, scheduled delivery, "
                       "row-level security, audit trail",
     "blocking_personas": ["ProductPM", "EngLead", "Security"],
     "axes": ["scope", "eng", "security", "data"],
     "launch_strategy": "feature_flag",
     "size_days": (25, 50),
     "regulated": True},
    {"slug": "public_api_v2", "name": "Public API v2 with auth refresh",
     "scope_template": "OpenAPI spec, rate limits, OAuth2 client creds, "
                       "deprecation timeline for v1",
     "blocking_personas": ["ProductPM", "EngLead", "Security", "GTM"],
     "axes": ["scope", "eng", "security", "gtm"],
     "launch_strategy": "gradual_rollout",
     "size_days": (40, 85),
     "regulated": False},
    {"slug": "integration_native", "name": "Native {provider} integration",
     "scope_template": "OAuth-based connection, webhook receivers, "
                       "data sync, error surfacing in UI",
     "blocking_personas": ["ProductPM", "Designer", "EngLead"],
     "axes": ["scope", "ux", "eng"],
     "launch_strategy": "feature_flag",
     "size_days": (20, 50),
     "regulated": False},
    {"slug": "compliance_audit", "name": "Audit log + compliance report",
     "scope_template": "immutable event log, customer-facing audit "
                       "report, retention policy, SOC2 mapping",
     "blocking_personas": ["ProductPM", "EngLead", "Security", "GTM"],
     "axes": ["scope", "eng", "security", "gtm"],
     "launch_strategy": "full_release",
     "size_days": (30, 65),
     "regulated": True},
    {"slug": "in_app_notifications", "name": "In-app notification centre",
     "scope_template": "real-time event stream, mute / categorise, "
                       "digest email fallback, mobile push parity",
     "blocking_personas": ["ProductPM", "Designer", "EngLead"],
     "axes": ["scope", "ux", "eng"],
     "launch_strategy": "gradual_rollout",
     "size_days": (25, 55),
     "regulated": False},
    {"slug": "self_serve_signup", "name": "Self-serve {tier} signup",
     "scope_template": "free-tier provisioning, email verification, "
                       "anti-abuse rate limits, plan-change CTA",
     "blocking_personas": ["ProductPM", "EngLead", "GTM"],
     "axes": ["scope", "eng", "gtm"],
     "launch_strategy": "gradual_rollout",
     "size_days": (20, 45),
     "regulated": False},
]


PRODUCT_CONTEXTS = [
    {"slug": "b2b_saas", "name": "B2B SaaS", "modifier": "with admin/RBAC needs"},
    {"slug": "fintech", "name": "fintech", "modifier": "regulated by PCI/SOX"},
    {"slug": "healthtech", "name": "healthtech", "modifier": "regulated by HIPAA"},
    {"slug": "dev_tools", "name": "developer tools", "modifier": "API-first"},
    {"slug": "marketplace", "name": "marketplace", "modifier": "two-sided liquidity"},
    {"slug": "consumer_app", "name": "consumer app", "modifier": "high-volume B2C"},
]

SCALE_TIERS = [
    {"slug": "early", "users": "<1k MAU", "team_size": "5-15 eng", "scale_factor": 0.6},
    {"slug": "growth", "users": "10k-100k MAU", "team_size": "30-80 eng", "scale_factor": 1.0},
    {"slug": "enterprise", "users": "1M+ MAU", "team_size": "200+ eng", "scale_factor": 1.4},
]

USER_TIERS = ["free", "SMB", "Pro", "Enterprise"]
PROVIDERS = ["Google", "Microsoft", "Apple", "Slack", "GitHub", "Salesforce"]
WORKFLOWS = ["customer support", "code review", "document drafting",
             "data analysis", "lead qualification"]
FEATURE_NAMES = ["search", "comments", "notifications", "billing", "settings"]


# --- Templates ----------------------------------------------------------

INTENT_MD_TEMPLATE = """# {title}

## What

{what}

## Why

{why}

## Scope

- **In scope:** {scope_in}
- **Out of scope:** {scope_out}
- **Existing constraints:** {existing}

## Constraints

{constraints}

## What success looks like

{success}
"""


def _generate_one(rng: random.Random, kind: dict, ctx: dict, scale: dict) -> dict:
    tier = rng.choice(USER_TIERS)
    provider = rng.choice(PROVIDERS)
    workflow = rng.choice(WORKFLOWS)
    feature = rng.choice(FEATURE_NAMES)

    title = kind["name"].format(
        tier=tier, provider=provider, workflow=workflow, feature=feature,
    )
    scope_in = kind["scope_template"].format(provider=provider, tier=tier)

    # Why: drive customer outcome based on context.
    why_options = {
        "b2b_saas": "Reduce friction in admin onboarding; enterprise pipeline asks.",
        "fintech":  "Compliance-required by Q3; auditors flagged the gap.",
        "healthtech": "HIPAA-relevant; protected-health-information handling needs review.",
        "dev_tools": "Developer-experience pain in the SDK; community asks.",
        "marketplace": "Liquidity-side request; suppliers and buyers both need it.",
        "consumer_app": "Conversion-funnel improvement; analytics show drop-off here.",
    }
    why = why_options.get(ctx["slug"], "Customer-driven; on the roadmap for this quarter.")

    # Existing constraints — realistic technical-debt callouts
    existing_options = [
        "auth middleware is JWT-only; refactor needed for multi-identity support",
        "current implementation is monolithic; needs a proper service split",
        "no feature-flag infrastructure beyond environment-variable toggles",
        "design system lacks the components this feature needs",
        "test coverage in this area is below 50%",
        "current API is unversioned; this change needs a v2 surface",
    ]
    existing = rng.choice(existing_options)

    scope_out = "; ".join(rng.sample([
        "other identity providers (only the chosen one)",
        "white-label / custom branding",
        "advanced admin controls beyond defaults",
        "on-premise deployment",
        "non-English localisation",
        "advanced reporting / dashboards",
    ], 2))

    deadline_text = ""
    if rng.random() < 0.6:
        deadline_text = (
            f"- We have a Q{rng.randint(1, 4)} deadline tied to "
            f"{'sales kickoff' if ctx['slug'] in ('b2b_saas', 'dev_tools') else 'launch event'}; "
            f"leadership has asked for GA by then."
        )

    constraints_lines = [
        f"- Existing {tier}-tier users must continue working unchanged.",
        "- Self-serve where possible; minimise admin friction.",
    ]
    if kind["regulated"]:
        constraints_lines.append(
            "- Compliance: audit log of all new actions, parity with existing logging."
        )
    if ctx["slug"] == "fintech":
        constraints_lines.append("- PCI/SOX: any change involving billing data needs compliance sign-off.")
    if ctx["slug"] == "healthtech":
        constraints_lines.append("- HIPAA: PHI handling reviewed; BAA-covered subprocessors only.")
    if deadline_text:
        constraints_lines.append(deadline_text)
    constraints_lines.append(f"- Scale context: {scale['users']}, {scale['team_size']}.")

    success_lines = [
        f"- Adoption: ≥{rng.randint(20, 60)}% of eligible users in 30 days post-launch.",
        f"- No security incidents related to the change.",
        f"- Support team can resolve common issues self-serve in <{rng.randint(5, 15)} minutes.",
    ]

    intent_md = INTENT_MD_TEMPLATE.format(
        title=title,
        what=f"Build {scope_in} for our {ctx['name']} product ({ctx['modifier']}).",
        why=why,
        scope_in=scope_in,
        scope_out=scope_out,
        existing=existing,
        constraints="\n".join(constraints_lines),
        success="\n".join(success_lines),
    )

    # Scale the day estimates with the scale factor
    min_d, max_d = kind["size_days"]
    sf = scale["scale_factor"]
    min_days = int(min_d * sf)
    max_days = int(max_d * sf)

    elem_id = f"feature_synthetic/{kind['slug']}/{ctx['slug']}/{scale['slug']}/{rng.randint(0, 99999):05d}"

    return {
        "id": elem_id,
        "source": "feature_synthetic",
        "intent_md": intent_md,
        "ground_truth": {
            "kind": "feature_planning",
            "feature_slug": kind["slug"],
            "expected_blocking_stakeholders": kind["blocking_personas"],
            "expected_axes": kind["axes"],
            "expected_launch_strategy": kind["launch_strategy"],
            "min_estimated_days": min_days,
            "max_estimated_days": max_days,
            "regulated": kind["regulated"] or ctx["slug"] in ("fintech", "healthtech"),
        },
        "metadata": {
            "feature_kind": kind["slug"],
            "product_context": ctx["slug"],
            "scale_tier": scale["slug"],
        },
    }


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(2026_05_01)
    target = 200

    combos = list(product(FEATURE_KINDS, PRODUCT_CONTEXTS, SCALE_TIERS))
    rng.shuffle(combos)

    out: list[dict] = []
    seen_ids: set[str] = set()
    while len(out) < target and combos:
        kind, ctx, scale = combos[len(out) % len(combos)]
        elem = _generate_one(rng, kind, ctx, scale)
        if elem["id"] in seen_ids:
            continue
        seen_ids.add(elem["id"])
        out.append(elem)

    with OUT_PATH.open("w") as f:
        for e in out:
            f.write(json.dumps(e) + "\n")

    print(f"wrote {len(out)} elements to {OUT_PATH}")
    # Distribution sanity check
    from collections import Counter
    print("by feature_kind:", Counter(e["metadata"]["feature_kind"] for e in out))
    print("by product_context:", Counter(e["metadata"]["product_context"] for e in out))


if __name__ == "__main__":
    main()
