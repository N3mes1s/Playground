# CVE Benchmark Results

## Progress: 45/100 advisories scanned (1.7h elapsed)

## Detection Rates
| Metric | Count | Rate |
|--------|-------|------|
| Exact match | 8 | 17.8% |
| Partial match | 0 | 0.0% |
| **Total detected** | **8** | **17.8%** |
| Missed | 20 | 44.4% |
| Errors | 17 | 37.8% |

## Self-Improvement
- Patterns learned: **22**
- Scans that improved scanner: 20

## Timing
- Elapsed: 1.7h
- Avg per advisory: 138s (wall clock with 45 done)

## By Ecosystem

| Ecosystem | Total | Exact | Partial | Miss | Error | Det% |
|-----------|-------|-------|---------|------|-------|------|
| Composer | 2 | 1 | 0 | 1 | 0 | 50% |
| Go | 6 | 1 | 0 | 5 | 0 | 17% |
| cargo | 1 | 0 | 0 | 1 | 0 | 0% |
| gomod | 1 | 0 | 0 | 1 | 0 | 0% |
| maven | 2 | 1 | 0 | 1 | 0 | 50% |
| npm | 8 | 3 | 0 | 5 | 0 | 38% |
| nuget | 2 | 1 | 0 | 1 | 0 | 50% |
| pip | 6 | 1 | 0 | 5 | 0 | 17% |
| unknown | 17 | 0 | 0 | 0 | 17 | 0% |

## All Results

| # | Status | GHSA | Package | Severity | Time |
|---|--------|------|---------|----------|------|
| 1 | FAIL | GHSA-4jqp-9qjv-57m2 | keylime | Critical | 182s |
| 2 | FAIL | GHSA-4f84-67cv-qrv3 | dydx-v4-client | Critical | 281s |
| 3 | PASS | GHSA-2ww3-72rp-wpp4 | Microsoft.SemanticKernel. | Critical | 384s |
| 4 | PASS | GHSA-25fp-8w8p-mx36 | devcode-it/openstamanager | CRITICAL | 525s |
| 5 | FAIL | GHSA-gg64-xxr9-qhjp | gogs.io/gogs | Critical | 563s |
| 6 | FAIL | GHSA-7x3h-rm86-3342 | @nyariv/sandboxjs | Critical | 654s |
| 7 | PASS | GHSA-74vm-8frp-7w68 | epyt-flow | Critical | 447s |
| 8 | FAIL | GHSA-xx6w-jxg9-2wh8 | @payloadcms/drizzle | Critical | 866s |
| 9 | FAIL | GHSA-x9p2-77v6-6vhf | github.com/dunglas/franke | Critical | 803s |
| 10 | PASS | GHSA-jr3w-9vfr-c746 | github.com/rancher/local- | Critical | 443s |
| 11 | ERR | GHSA-ggxw-g3cp-mgf8 | GHSA-ggxw-g3cp-mgf8 | ? | 900s |
| 12 | ERR | GHSA-h3q6-jfrg-3x6q | GHSA-h3q6-jfrg-3x6q | ? | 900s |
| 13 | ERR | GHSA-gjx9-j8f8-7j74 | GHSA-gjx9-j8f8-7j74 | ? | 20s |
| 14 | FAIL | GHSA-8jmm-3xwx-w974 | github.com/alist-org/alis | Critical | 774s |
| 15 | FAIL | GHSA-hrr4-3wgr-68x3 | github.com/navidrome/navi | Critical | 718s |
| 16 | ERR | GHSA-8398-gmmx-564h | GHSA-8398-gmmx-564h | ? | 900s |
| 17 | ERR | GHSA-xqg6-98cw-gxhq | GHSA-xqg6-98cw-gxhq | ? | 900s |
| 18 | PASS | GHSA-rxrv-835q-v5mh | locutus | Critical | 408s |
| 19 | FAIL | GHSA-x34r-63hx-w57f | langroid | Critical | 493s |
| 20 | PASS | GHSA-p8gp-2w28-mhwg | @signalk/set-system-time | Critical | 224s |
| 21 | FAIL | GHSA-Not-Specified | bambuddy | CRITICAL | 759s |
| 22 | ERR | GHSA-gp56-f67f-m4px | GHSA-gp56-f67f-m4px | ? | 900s |
| 23 | FAIL | GHSA-gch2-phqh-fg9q | @orval/core | CRITICAL | 579s |
| 24 | FAIL | GHSA-2733-6c58-pf27 | deephas | Critical | 374s |
| 25 | ERR | GHSA-4r2x-xpjr-7cvv | GHSA-4r2x-xpjr-7cvv | ? | 900s |
| 26 | ERR | GHSA-wj3h-wx8g-x699 | GHSA-wj3h-wx8g-x699 | ? | 900s |
| 27 | ERR | GHSA-jfpc-wj3m-qw2m | GHSA-jfpc-wj3m-qw2m | ? | 900s |
| 28 | FAIL | GHSA-vg9h-jx4v-cwx2 | dfir-unfurl | CRITICAL | 554s |
| 29 | FAIL | GHSA-c4jr-5q7w-f6r9 | github.com/siyuan-note/si | Critical | 684s |
| 30 | ERR | GHSA-99p7-6v5w-7xg8 | GHSA-99p7-6v5w-7xg8 | ? | 16s |
| 31 | FAIL | GHSA-5w5r-mf82-595p | capnp | Critical | 525s |
| 32 | ERR | GHSA-w9pf-h6m6-v89h | GHSA-w9pf-h6m6-v89h | ? | 900s |
| 33 | ERR | GHSA-8p9x-46gm-qfx2 | GHSA-8p9x-46gm-qfx2 | ? | 900s |
| 34 | ERR | GHSA-cr3w-cw5w-h3fj | GHSA-cr3w-cw5w-h3fj | ? | 900s |
| 35 | FAIL | GHSA-pgx9-497m-6c4v | sm-crypto | Critical | 644s |
| 36 | FAIL | GHSA-77p9-w6pj-rmvg | org.apache.continuum:cont | Critical | 841s |
| 37 | ERR | GHSA-796p-j2gh-9m2q | GHSA-796p-j2gh-9m2q | ? | 900s |
| 38 | FAIL | GHSA-m27r-m6rx-mhm4 | laravel/reverb | Critical | 616s |
| 39 | PASS | GHSA-7jc7-g598-2p64 | fr.opensagres.xdocreport: | Critical | 512s |
| 40 | ERR | GHSA-63m5-974w-448v | GHSA-63m5-974w-448v | ? | 900s |
| 41 | ERR | GHSA-r8w2-w357-9pjv | GHSA-r8w2-w357-9pjv | ? | 900s |
| 42 | ERR | GHSA-4gpc-rhpj-9443 | GHSA-4gpc-rhpj-9443 | ? | 900s |
| 43 | PASS | GHSA-232v-j27c-5pp6 | @mcpjam/inspector | Critical | 601s |
| 44 | FAIL | GHSA-77v3-r3jw-j2v2 | github.com/external-secre | Critical | 839s |
| 45 | FAIL | GHSA-vrgw-pc9c-qrrc | UmbracoForms | Critical | 185s |

## Learned Patterns

1. **CVE-2026-1709**: When reviewing SSL/TLS context configurations, flag any assignment where `verify_mode` is set to `ssl.CERT_OPTIONAL` or ...
2. **CVE-2025-69212**: 
When reviewing code for command injection vulnerabilities:

1. **Exhaustively search for ALL dangerous shell execution ...
3. **CVE-2026-1709**: When analyzing SSL/TLS security configurations, do not limit your search to only known SSL-related files or initializati...
4. **None**: 
SUPPLY CHAIN ATTACK DETECTION:

When reviewing Python code, actively scan for supply chain compromises and deliberately...
5. **CVE-2025-64111**: 
When reviewing file write operations (os.WriteFile, ioutil.WriteFile, etc.) that accept
user-controlled paths, verify t...
6. **CVE-2026-25641**: ```markdown
## CRITICAL CHECK: Time-of-Check-Time-of-Use (TOCTOU) via Object Coercion in Property Access

### WHAT TO DE...
7. **CVE-2026-25544**: 
When reviewing database query builder code, especially for ORMs and adapters, check for SQL injection in JSON/richText ...
8. **None**: 
**CI/CD Container Image Supply Chain Security Check:**

When analyzing repositories that build container images, verify...
9. **CVE-2026-25160**: # TLS Certificate Validation Bypass Configuration Vulnerability Detection

**Add this instruction to your security scann...
10. **CVE-2026-25579**: RESOURCE EXHAUSTION - Unbounded Numeric Input Parameters:

When reviewing code that accepts numeric parameters from user...
11. **CVE-2026-25481**: 
When reviewing AST-based validation/sanitization code (e.g., ast.NodeVisitor classes used to validate user input before...
12. **CVE-2026-25505**: ## Authentication & Secrets Security Analysis Directive

When analyzing any application code, you MUST perform the follo...
13. **CVE-2026-25141**: 
When reviewing code generation or templating logic, check for COMMENT BREAKOUT vulnerabilities:

1. **Identify string s...
14. **CVE-2026-25047**: When reviewing prototype pollution protection code, verify that the security checks themselves are not using methods tha...
15. **None**: 
When reviewing Flask applications, always check for debug mode configuration issues:

1. **Flag any use of app.run(debu...
16. **CVE-2026-25539**: 
CRITICAL: Bidirectional Path Validation for File Operations

When analyzing file operation endpoints (copy, move, write...
17. **None**: 
When reviewing Rust code, check for "Safe API Unsafe Exposure" patterns (CWE-758):

PATTERN TO DETECT:
1. Public safe f...
18. **CVE-2026-23966**: 
When analyzing cryptographic encryption/decryption functions, check for chosen-ciphertext 
oracle vulnerabilities that ...
19. **CVE-2016-15057**: 
ADDITIONAL SCANNER INSTRUCTION: API-Based Command Injection Detection

When scanning Java applications for command inje...
20. **CVE-2026-23524**: 
DESERIALIZATION ACROSS TRUST BOUNDARIES:

When reviewing unserialize() calls, treat data as UNTRUSTED if it originates ...
21. **CVE-2026-22822**: 
When reviewing Kubernetes operators and controllers that handle secrets or sensitive resources:

1. EXAMINE TEMPLATE FU...
22. **CVE-2025-68924**: When the CVE description references specific file paths, class names, or component identifiers (e.g., "Umbraco.Forms.Cor...
