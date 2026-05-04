"""Template-based synthetic intent generator.

Combines five axes — tech stack, change type, organisation context,
scale tier, stakeholder mix — to produce 10k unique migration /
rollout intents that cover the input space the verified-rollout
pipeline is meant to handle.

Each axis has hand-curated entries; the cross product is ~30k
combinations. We sample uniformly to 10k. Every generated element
includes declared "expected stakeholders" as a weak ground-truth
signal: the bench runner can score "did the pipeline emit
constraints from those stakeholders?"
"""

from __future__ import annotations

import json
import random
import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "dataset" / "data" / "synthetic" / "synthetic.jsonl"


# ----- Axes ------------------------------------------------------------

TECH_STACKS = [
    {"slug": "pydantic_v1_v2", "name": "Pydantic v1 → v2", "language": "python",
     "examples": "BaseModel, validator, root_validator, Config.orm_mode, json_encoders",
     "loc_estimate": "thousands of model classes",
     "stakeholders": ["backend", "data", "consumer"]},
    {"slug": "django_4_5", "name": "Django 4.x → 5.x", "language": "python",
     "examples": "deprecated USE_DEPRECATED_PYTZ, Q.deconstruct, get_storage_class",
     "loc_estimate": "ORM models, custom managers, signals",
     "stakeholders": ["backend", "data", "security", "product"]},
    {"slug": "rails_6_7", "name": "Rails 6.x → 7.x", "language": "ruby",
     "examples": "zeitwerk autoloader, encrypted attrs, Action Cable, async queries",
     "loc_estimate": "ActiveRecord models, controllers, mailers",
     "stakeholders": ["backend", "data", "sre"]},
    {"slug": "node_16_20", "name": "Node 16 → 20 LTS", "language": "typescript",
     "examples": "fetch API native, dropping legacy openssl, perf_hooks changes",
     "loc_estimate": "package.json deps, CI matrix, runtime polyfills",
     "stakeholders": ["backend", "sre", "consumer"]},
    {"slug": "python_310_312", "name": "Python 3.10 → 3.12", "language": "python",
     "examples": "PEP 695 type aliases, removed deprecated stdlib modules",
     "loc_estimate": "type hints, removed asynchat, distutils gone",
     "stakeholders": ["backend", "sre"]},
    {"slug": "java_11_17", "name": "Java 11 → 17 LTS", "language": "java",
     "examples": "sealed classes, records, removed nashorn, --release 17",
     "loc_estimate": "build.gradle, JVM flags, frozen reflection",
     "stakeholders": ["backend", "sre", "security"]},
    {"slug": "postgres_12_16", "name": "Postgres 12 → 16", "language": None,
     "examples": "logical replication, partitioning, TLS 1.3 default",
     "loc_estimate": "schemas, migrations, replication topology",
     "stakeholders": ["data", "sre", "security"]},
    {"slug": "mysql_5_8", "name": "MySQL 5.7 → 8.0", "language": None,
     "examples": "SHA-256 default auth plugin, JSON_TABLE, removed query cache",
     "loc_estimate": "schema, replication, ORM compat",
     "stakeholders": ["data", "backend", "sre"]},
    {"slug": "mongodb_5_7", "name": "MongoDB 5 → 7", "language": None,
     "examples": "queryable encryption, CSFLE, time-series collections",
     "loc_estimate": "schema, drivers, indexing",
     "stakeholders": ["data", "security", "backend"]},
    {"slug": "k8s_1_27_1_30", "name": "Kubernetes 1.27 → 1.30", "language": None,
     "examples": "removed flowcontrol.apiserver.k8s.io/v1beta2, PSA changes",
     "loc_estimate": "manifests, controllers, admission webhooks",
     "stakeholders": ["sre", "security", "backend"]},
    {"slug": "terraform_1_5_1_8", "name": "Terraform 1.5 → 1.8", "language": None,
     "examples": "state encryption, removed legacy provisioners",
     "loc_estimate": "modules, state backends, CI",
     "stakeholders": ["sre", "security"]},
    {"slug": "react_17_19", "name": "React 17 → 19", "language": "typescript",
     "examples": "concurrent features default, removed legacy context APIs",
     "loc_estimate": "components, hooks, SSR",
     "stakeholders": ["backend", "consumer", "product"]},
    {"slug": "nextjs_13_15", "name": "Next.js 13 → 15", "language": "typescript",
     "examples": "App Router default, partial prerender, removed pages directory",
     "loc_estimate": "routing, layouts, RSC",
     "stakeholders": ["backend", "consumer", "product"]},
    {"slug": "rust_2021_2024", "name": "Rust edition 2021 → 2024", "language": "rust",
     "examples": "let-else default, async closures, removed deprecated APIs",
     "loc_estimate": "Cargo.toml, lints, traits",
     "stakeholders": ["backend"]},
    {"slug": "go_1_20_1_23", "name": "Go 1.20 → 1.23", "language": "go",
     "examples": "loopvar default, generics in stdlib, slog default",
     "loc_estimate": "modules, build tags",
     "stakeholders": ["backend", "sre"]},
    {"slug": "docker_to_oci", "name": "Docker images → OCI distribution", "language": None,
     "examples": "registry move, image manifests v2, signing",
     "loc_estimate": "CI, deploy manifests, registries",
     "stakeholders": ["sre", "security"]},
    {"slug": "openssl_1_3", "name": "OpenSSL 1.1 → 3.x", "language": None,
     "examples": "FIPS provider, deprecated low-level APIs, default TLS 1.3",
     "loc_estimate": "every TLS-using service",
     "stakeholders": ["security", "sre", "backend"]},
    {"slug": "redis_5_7", "name": "Redis 5 → 7", "language": None,
     "examples": "ACLs, Streams, Functions, RESP3",
     "loc_estimate": "client wrappers, ops",
     "stakeholders": ["backend", "sre", "data"]},
    {"slug": "elasticsearch_7_8", "name": "Elasticsearch 7 → 8", "language": None,
     "examples": "auto-security, mTLS by default, removed types",
     "loc_estimate": "indices, query DSL, drivers",
     "stakeholders": ["data", "security", "sre"]},
    {"slug": "kafka_clients_3_x", "name": "Kafka clients 2.x → 3.x", "language": None,
     "examples": "removed legacy zookeeper, KRaft, exactly-once v2",
     "loc_estimate": "producer / consumer wrappers, ops",
     "stakeholders": ["data", "sre", "backend"]},
]


CHANGE_TYPES = [
    {"slug": "schema_migration", "name": "schema migration",
     "extras": "Backfill, dual-write window, drop old columns later."},
    {"slug": "api_breaking", "name": "API breaking change",
     "extras": "Versioned endpoints, deprecation window, SDK regen."},
    {"slug": "dep_upgrade", "name": "dependency upgrade",
     "extras": "Lockfile, CI matrix, transitive surprises."},
    {"slug": "infra_cutover", "name": "infrastructure cutover",
     "extras": "DNS, traffic shifting, parallel-run window."},
    {"slug": "framework_swap", "name": "framework swap",
     "extras": "Adapter shims, partial-port window, e2e parity tests."},
    {"slug": "rename_refactor", "name": "rename refactor",
     "extras": "Codemod, shim aliases, deprecation warnings."},
    {"slug": "security_hardening", "name": "security hardening cutover",
     "extras": "Default-deny audit, allowlist migration, comms."},
    {"slug": "feature_flag_consolidation", "name": "feature-flag cleanup",
     "extras": "Audit live flags, default-on, remove dead code."},
    {"slug": "split_monolith", "name": "split a monolith service",
     "extras": "Strangler fig, traffic mirroring, data contracts."},
    {"slug": "merge_services", "name": "merge two services into one",
     "extras": "API surface union, data merge, rollback per-tenant."},
]


ORG_CONTEXTS = [
    {"slug": "small_startup", "name": "5-person startup, no compliance",
     "stakeholder_bias": "lean: skip ProductPM, Security may be pro-forma"},
    {"slug": "mid_saas", "name": "150-person B2B SaaS, SOC2 in flight",
     "stakeholder_bias": "Security and PM are real"},
    {"slug": "enterprise", "name": "5000-person enterprise, change advisory board",
     "stakeholder_bias": "every approval gate is a real human"},
    {"slug": "regulated_fintech", "name": "regulated fintech under PCI-DSS",
     "stakeholder_bias": "Security blocks; comms have legal review"},
    {"slug": "oss_project", "name": "OSS project, no central team",
     "stakeholder_bias": "ConsumerSubsystem = downstream users; PM is the maintainer"},
]


SCALE_TIERS = [
    {"slug": "tiny", "loc": "~1k LOC, 1 service", "users": "100s"},
    {"slug": "small", "loc": "~10k LOC, 3 services", "users": "10k"},
    {"slug": "medium", "loc": "~100k LOC, 10 services", "users": "1M"},
    {"slug": "large", "loc": "~1M LOC, 50 services", "users": "100M"},
    {"slug": "xlarge", "loc": "~10M LOC, 200 services", "users": "1B+"},
]


# ----- Generator -------------------------------------------------------


def _expected_stakeholders(tech: dict, ctx: dict) -> list[str]:
    base = set(tech["stakeholders"])
    if ctx["slug"] in ("enterprise", "regulated_fintech", "mid_saas"):
        base |= {"security", "product"}
    if ctx["slug"] == "oss_project":
        base |= {"consumer"}
    if ctx["slug"] == "small_startup":
        base.discard("product")
    return sorted(base)


def _intent_md(tech: dict, change: dict, ctx: dict, scale: dict) -> str:
    return (
        f"# Migrate `{tech['name']}` — {change['name']} at {scale['slug']} scale\n\n"
        f"## What\n\n"
        f"A **{ctx['name']}** is undertaking a **{change['name']}** scoped to a "
        f"`{tech['name']}` upgrade. Specifics that matter for this stack: "
        f"{tech['examples']}. {change['extras']}\n\n"
        f"## Codebase scale\n\n{scale['loc']}, serving {scale['users']} users.\n\n"
        f"## Why\n\n"
        f"The current version is reaching end-of-life / has known issues / "
        f"blocks features. The migration is required this quarter.\n\n"
        f"## Scope\n\n"
        f"- Surface area: {tech['loc_estimate']}\n"
        f"- Touchpoints: every service that depends on the changing component\n"
        f"- New version is feature-compatible but has tightened defaults\n\n"
        f"## Constraints\n\n"
        f"- Customer-visible: depends on whether the change leaks to API / UX\n"
        f"- Org context: {ctx['name']}; stakeholder bias: {ctx['stakeholder_bias']}\n"
        f"- Backwards compatibility window required during transition\n"
        f"- Rollback path must exist per-step\n"
        f"- Observability: every step must be measurable\n\n"
        f"## What success looks like\n\n"
        f"- All affected components on the new version\n"
        f"- No customer-reported regression in the 30 days after\n"
        f"- Cost / performance match or exceed pre-migration baseline\n"
    )


def _id(tech: dict, change: dict, ctx: dict, scale: dict, n: int) -> str:
    return (
        f"synthetic/{tech['slug']}/{change['slug']}/{ctx['slug']}/"
        f"{scale['slug']}/{n:05d}"
    )


def _generate_one(tech, change, ctx, scale, idx) -> dict:
    expected = _expected_stakeholders(tech, ctx)
    return {
        "id": _id(tech, change, ctx, scale, idx),
        "source": "synthetic",
        "kind": "migration_intent",
        "title": f"{tech['name']}: {change['name']} ({ctx['slug']}, {scale['slug']})",
        "intent_md": _intent_md(tech, change, ctx, scale),
        "repo": None,
        "repo_clone_url": None,
        "language": tech["language"],
        "ground_truth": {
            "kind": "outcome",
            "files_touched": None,
            "root_cause_keywords": (
                tech["examples"].lower().split(", ")
                + change["extras"].lower().split(". ")[:3]
            ),
            "outcome": None,
            "patch_uri": None,
        },
        "metadata": {
            "tags": [tech["slug"], change["slug"], ctx["slug"], scale["slug"]],
            "expected_stakeholders": expected,
            "tech_stack": tech["name"],
            "change_type": change["name"],
            "org_context": ctx["name"],
            "scale": scale["slug"],
        },
    }


def generate(n: int = 10000, *, seed: int = 1337) -> int:
    rng = random.Random(seed)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    combos = list(product(TECH_STACKS, CHANGE_TYPES, ORG_CONTEXTS, SCALE_TIERS))
    print(f"axis cross-product: {len(combos)}", file=sys.stderr)
    rng.shuffle(combos)

    written = 0
    counter_per_combo: dict[tuple, int] = {}
    with OUT_PATH.open("w") as f:
        # One pass through all unique combos.
        for combo in combos:
            tech, change, ctx, scale = combo
            key = (tech["slug"], change["slug"], ctx["slug"], scale["slug"])
            counter_per_combo[key] = counter_per_combo.get(key, 0) + 1
            elem = _generate_one(tech, change, ctx, scale,
                                 counter_per_combo[key])
            f.write(json.dumps(elem) + "\n")
            written += 1
            if written >= n:
                break
        # If we need more, second pass with reshuffled combos and incremented counter.
        while written < n:
            rng.shuffle(combos)
            for combo in combos:
                if written >= n:
                    break
                tech, change, ctx, scale = combo
                key = (tech["slug"], change["slug"], ctx["slug"], scale["slug"])
                counter_per_combo[key] = counter_per_combo.get(key, 0) + 1
                elem = _generate_one(tech, change, ctx, scale,
                                     counter_per_combo[key])
                f.write(json.dumps(elem) + "\n")
                written += 1
    print(f"[done] wrote {written} synthetic elements to {OUT_PATH}",
          file=sys.stderr)
    return written


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()
    generate(args.n, seed=args.seed)
