# What can Jev solve? A catalogue, security first

Jev answers **closed questions about a state** (`choice` / `score` / `noul`) in
~0.4–0.9 s, at ~$0.042 per million input tokens, with calibrated confidence. Any
problem that looks like *"look at this thing, pick from a fixed set, and do it
millions of times or inside a latency budget"* is a candidate. Problems that
need an explanation, generated text, counting, images, or open-ended
investigation are not.

**Status:** ✅ implemented and benchmarked in [`security/`](security/) ·
🧪 easy to add with the same pattern · ⚠️ partial fit / needs a second tier

Measured numbers come from [`security/RESULTS.md`](security/RESULTS.md) (hand-written
samples, 3 runs each, so this is a fit check rather than a real evaluation).

## Security

### AI / agent security (OWASP LLM Top 10 2026, OWASP Agentic Top 10)

This is where Jev fits best. Guardrails have to run on *every* hop of an agent loop,
so a check has to be cheap, fast and typed. An LLM judge on every tool call roughly
doubles latency and cost.

| Problem | Status | How it maps to Jev | Measured |
|---|---|---|---|
| Direct prompt injection / jailbreak (LLM01) | ✅ `prompt_injection` | `noul` injection + `choice` technique | 21/21, hard negatives 6/6 |
| Indirect injection in web pages, emails, issues, tool results (ASI01 goal hijack) | ✅ `prompt_injection` | same detector, with the source in the state | included above |
| Tool misuse / excessive agency (LLM06, ASI02): allow / confirm / block a tool call | ✅ `tool_call_guard` | `choice` action + `noul` aligned + `noul` exfil | 21/21 |
| Coding-agent shell command risk | ✅ `shell_command` | `score` 4-level impact + `noul` remote | 18/21; `rm -rf ./build` scored as destructive |
| Sensitive info disclosure in agent output (LLM02) | ✅ `dlp_outbound` | `noul` secret + `noul` PII | 18/18 |
| End-to-end agent middleware (input → tool → output) with confidence-gated escalation | ✅ [`security/guard.py`](security/guard.py) | combines the four detectors above | demo blocks a full indirect-injection → key-exfil chain |
| System-prompt leak detection in replies | 🧪 | `noul` "reveals hidden instructions" | – |
| Memory poisoning (ASI06): should this item be written to long-term memory? | 🧪 | `noul` on each memory write | – |
| Inter-agent message trust (ASI07) | 🧪 | `choice` trusted / suspicious / hostile per message | – |
| Hallucinated / slopsquatted package names suggested by an LLM | ⚠️ | `noul` plausibility; still needs a registry lookup | – |
| RAG context relevance / poisoning filter | 🧪 | `score` relevance + `noul` "contains instructions" per chunk | – |
| **Attacking the guard: adversarial evasion of a Jev classifier** | ✅ `adversarial` + `harden` | framing/authority/reviewer-instruction attacks vs behavioural-rewording + manipulation-detector + deterministic regex | real ATT&CK cmds: authority framing 55% ASR naive → 0% hardened (see below) |

### Email, fraud and social engineering

| Problem | Status | How it maps | Measured |
|---|---|---|---|
| Phishing / credential harvest (T1566) | ✅ `phishing_email` | `noul` + `choice` lure + `score` urgency | 18/18, including a real GitHub reset email and an Amazon notice |
| CEO fraud / BEC / vendor bank-detail change | ✅ `phishing_email` | same; extra context such as domain age goes in the state | included |
| Scam DMs: fake support, OTP theft, crypto doubling, advance fee | ✅ `scam_message` | `choice` ok / scam / spam / harassment | 18/18 |
| Lookalike / typosquat / homoglyph domains | ✅ `lookalike_url` | `noul` impersonation | 21/21 (tested with punycode and brand-in-subdomain) |
| Account takeover on login events (MFA fatigue, spraying, impossible travel) | ✅ `login_ato` | `noul` ATO + `choice` allow / step_up / block | 15/15, including expected travel and an explained new device |
| Invoice / payment fraud signals, refund abuse | 🧪 | `noul` per signal over the transaction JSON | – |
| Vishing / call-transcript scam detection (after speech-to-text) | 🧪 | `scam_message` on transcript chunks | – |

### SOC and detection engineering

| Problem | Status | How it maps | Measured |
|---|---|---|---|
| Tier-1 alert triage (TP / benign TP / FP), alert fatigue | ✅ `soc_triage` | `choice` disposition + `score` severity | 18/18, including an SCCM job, a Nessus window and a VPN "impossible travel" |
| **EDR / Sysmon process-event triage at the source** | ✅ `edr` | one call → malicious? + tactic + LOLBin + obfuscation + severity + response | **real data**: 72% recall / 0–1 FP over 569 Atomic Red Team techniques + 20 benign (see below) |
| LOLBin abuse (certutil, rundll32, comsvcs.dll MiniDump, mshta…) | ✅ `edr` | `noul` lolbin_abuse | comsvcs LSASS dump flagged 0.93 |
| Command-line obfuscation / encoded payload detection | ✅ `edr` | `noul` obfuscated | base64/xxd pipeline flagged 0.93 |
| MITRE ATT&CK tactic tagging of alerts | ✅ `soc_triage` / `edr` | `choice` over tactics | binary call strong; fine-grained tactic only 39% (`edr` benchmark) |
| Phishing-report mailbox triage (user-reported emails) | 🧪 | `phishing_email` | – |
| Log line anomaly / "is this worth a human" filter before an LLM investigator | ⚠️ | `noul` per event; volume works, but correlating many events needs a second tier | – |
| Incident routing to a playbook (contain / notify / queue / close) | 🧪 | `choice` (see Ken Huang's agentic SOC write-up) | – |
| Threat-intel report relevance to *our* stack | 🧪 | `score` relevance with an asset inventory in the state | – |

**The dual-use / LOLBin gap** ([`security/LOLBIN_GAP.md`](security/LOLBIN_GAP.md), via
[`security/lolbin_gap.py`](security/lolbin_gap.py)): the decade-old blue-team problem no
string-based tool could solve — attackers use the same signed binaries admins do, so signatures
can't separate them (ROC AUC 0.645 ≈ coin flip; "any rule fired" hits 100% of benign dual-use),
and LLMs are too costly to run on every event. Jev separates attack from admin on the same
dual-use commands (AUC 0.935; 73% of attacks caught at a ≤1% false-positive budget vs 4% for
signatures) at ~$0.00002/event, i.e. semantic detection at full coverage — the capability that
did not exist before. **Honest counter-check** ([`security/MUTATION_RESULTS.md`](security/MUTATION_RESULTS.md)):
mild behaviour-preserving mutations do *not* collapse precise signatures (they key on durable
artifacts), and on signature-covered attacks Jev under-performs them — so Jev is **complementary,
not a replacement**: signatures for the known-and-durable, Jev for the dual-use-and-novel.

**EDR benchmark takeaways** ([`security/EDR_RESULTS.md`](security/EDR_RESULTS.md), generated from
[`security/datasets.py`](security/datasets.py) + [`security/edr_bench.py`](security/edr_bench.py)):
Jev's binary *is-this-malicious* call is strong and well-calibrated (clean recall/FP curve, 0 FP at
threshold 0.5 on hard negatives); **Discovery is the honest weak spot** (26% recall — `ping`/`tasklist`
are dual-use and need sequence context a SIEM supplies, not a single event); **fine-grained ATT&CK
tactic labelling (39%) is much weaker than the binary signal**, so use Jev to *rank and gate* the
event firehose ahead of a SIEM/LLM tier, not as the authoritative ATT&CK mapper. It is not fully
deterministic. Where it fits perfectly: pre-filtering millions of endpoint events at ~$0.00002 each so
the expensive tiers only see what matters.

### AppSec and supply chain

| Problem | Status | How it maps | Measured |
|---|---|---|---|
| Malicious npm / PyPI install scripts (T1195.002) | ✅ `install_script` | `noul` + `choice` behaviour | 18/18, including esbuild binary fetch and husky |
| HTTP request attack classification (second-opinion WAF) | ✅ `waf_request` | `choice` over 7 attack classes | 21/24; `a < b && c > d` in a comment read as XSS at confidence ~0.45 |
| Code vulnerability class on a diff hunk (CWE Top 25) | ✅ `code_vuln` | `choice` over 7 CWEs | 21/24; a *contained* path join still flagged, at confidence ~0.5 |
| PR risk flag: does this diff touch auth, crypto, deserialization or secrets? | 🧪 | `noul` per concern; route to a deep reviewer | – |
| Dependency advisory triage: is the vulnerable function reachable in our usage? | ⚠️ | `noul` with the call site in the state; weak without real reachability data | – |
| SAST false-positive filtering | 🧪 | `choice` TP / FP over finding + code context | – |
| Secret-scanner hit validation (real vs placeholder or test fixture) | ✅ covered by `dlp_outbound` | – | placeholder and masked card both correct |

### Trust & Safety

Content moderation (toxicity, harassment, self-harm, spam) · marketplace listing
fraud · fake reviews · bot-account signals from profile JSON · CSAM *text* signals
(images need a separate classifier) — 🧪, all fit the `scam_message` pattern.

## Beyond security (from the same research)

- **Routing:** support tickets, emails, intent, which agent / model / tool to use next
- **Scoring:** lead scoring, urgency, frustration, relevance ranking, résumé screening
- **Verification:** does the evidence support the claim, does the citation match, does an LLM answer contradict its source
- **Real-time control:** game NPCs, browser-action selection, robotics or drone tactics at tens to hundreds of ms
- **Bulk labelling:** classify a corpus for a fraction of a cent

## Where Jev is the wrong tool

- **Explaining *why*.** It returns no rationale. Use it to decide, and an LLM to explain what matters.
- **Counting, arithmetic and multi-event correlation.** "More than 5 failed logins in 10 minutes" belongs in your SIEM rule, and Jev gets the result as state.
- **Images, binaries and pcaps.** It is text-only, so extract or caption first.
- **Open-ended investigation.** The pattern people converge on is a cascade: Jev on 100% of traffic, and anything under the confidence threshold goes to an LLM or a human (`AgentGuard(min_confidence=...)`).
- **Adversarial robustness must be engineered.** A naive guard *can* be moved by text that talks to the classifier — authority framing hit 55% attack success on borderline real attack commands (`security/ADVERSARIAL_EDR_RESULTS.md`). Hardening (behavioural rewording + a manipulation detector + a deterministic regex floor, fail-closed) restores 90–100% detection but adds false blocks on content that discusses attacks. Treat Jev as one calibrated layer behind deterministic checks and ahead of a human, never as the only control.

## Sources

- [TypeSafe AI – Introducing System One Models & Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
- [Ken Huang – Agentic SOC use cases with Jev](https://kenhuangus.substack.com/p/jev-returns-typed-probabilities-at)
- [CloudRaft – Top use cases of Jev (moderation, routing, guardrails)](https://www.cloudraft.io/blog/top-use-cases-of-jev-typesafe-ai-model)
- [KDnuggets – What everyone is getting wrong about Jev](https://www.kdnuggets.com/what-everyone-is-getting-wrong-about-typesafe-ais-jev)
- [Firecrawl – What is Jev](https://www.firecrawl.dev/blog/what-is-jev) · [LangChain – Building a harness with Jev](https://www.langchain.com/blog/building-a-harness-with-jev)
- [DEV – Practical guide to Jev](https://dev.to/valyuai/how-to-use-jev-a-practical-guide-to-typesafes-system-one-model-g5e)
- [OWASP Top 10 for Agentic Applications 2026 (NeuralTrust)](https://neuraltrust.ai/blog/owasp-top-10-for-agentic-applications-2026) · [OWASP LLM 2026 – Excessive agency (ReversingLabs)](https://www.reversinglabs.com/blog/owasp-top-10-for-llm-apps-excessive-agency)
- [LLM guardrails 2026: stacked classifier layer](https://www.morphllm.com/llm-guardrails)
- [AI-driven SOC alert screening survey](https://arxiv.org/pdf/2605.08316) · [Simbian AI SOC LLM benchmark](https://simbian.ai/blog/the-first-ai-soc-llm-benchmark)
- [npm/PyPI typosquatting 2026 report (DepWarden)](https://depwarden.in/blog/npm-pypi-typosquatting-2026-report) · [Supply-chain attack defense 2026](https://www.decryptiondigest.com/blog/software-supply-chain-attack-defense-dependency-confusion-typosquatting)
