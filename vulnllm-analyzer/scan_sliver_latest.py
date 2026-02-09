#!/usr/bin/env python3
"""
Scan Sliver C2 framework (latest master) for NEW vulnerabilities.
Targets the highest-risk server-side code: unauthenticated handlers,
session management, data parsing, crypto, and handler dispatch.
"""

import proxy_patch  # noqa: F401 — must be first
import json, sys, time, modal

VulnLLMModel = modal.Cls.from_name("vulnllm-analyzer", "VulnLLMModel")
model = VulnLLMModel()


# ---------------------------------------------------------------------------
# Code sections — extracted from BishopFox/sliver master (v1.7.1, 2026-02-08)
# ---------------------------------------------------------------------------
SECTIONS = [

    # 1. HTTP C2 — Unauthenticated body read + session start
    #    startSessionHandler accepts unauthenticated POST, decodes body via
    #    attacker-selected encoder, performs Age key exchange, creates session.
    #    stagerHandler serves raw shellcode to any client with a valid nonce.
    {
        "name": "HTTP C2 — unauthenticated session start + stager (server/c2/http.go)",
        "language": "go",
        "filename": "server/c2/http.go",
        "code": open("sliver-src/server/c2/http.go").read(),
    },

    # 2. DNS C2 — Full handler including session init and data handling
    #    24-bit session ID, unauthenticated INIT, message reassembly
    {
        "name": "DNS C2 — session init, data handling, message reassembly (server/c2/dns.go)",
        "language": "go",
        "filename": "server/c2/dns.go",
        "code": open("sliver-src/server/c2/dns.go").read(),
    },

    # 3. mTLS C2 — Length-prefix framing, signature verification, 2GB alloc
    #    socketReadEnvelope allocates dataLength bytes from attacker-controlled
    #    length prefix. ServerMaxMessageSize = ~2GB.
    {
        "name": "mTLS C2 — length-prefix framing + signature verification (server/c2/mtls.go)",
        "language": "go",
        "filename": "server/c2/mtls.go",
        "code": open("sliver-src/server/c2/mtls.go").read(),
    },

    # 4. WireGuard C2 — Key exchange handler (no auth) + data framing
    #    handleKeyExchangeConnection sends private keys to ANY connecting client.
    {
        "name": "WireGuard C2 — key exchange + data framing (server/c2/wireguard.go)",
        "language": "go",
        "filename": "server/c2/wireguard.go",
        "code": open("sliver-src/server/c2/wireguard.go").read(),
    },

    # 5. Session/tunnel handlers — remotely invokable by implants
    #    registerSessionHandler stores unsanitized data.
    #    tunnelCloseHandler has potential nil pointer dereference.
    #    createReverseTunnelHandler dials attacker-specified host:port.
    {
        "name": "Session + tunnel handlers — remotely invokable (server/handlers/sessions.go)",
        "language": "go",
        "filename": "server/handlers/sessions.go",
        "code": open("sliver-src/server/handlers/sessions.go").read(),
    },

    # 6. Beacon registration handler — stores implant data to DB
    {
        "name": "Beacon registration — stores implant data to DB (server/handlers/beacons.go)",
        "language": "go",
        "filename": "server/handlers/beacons.go",
        "code": open("sliver-src/server/handlers/beacons.go").read(),
    },

    # 7. Cryptography — Key exchange, encryption, replay detection
    #    CipherContext.replay is a sync.Map that grows unbounded.
    #    AgeKeyExFromImplant checks replay + HMAC.
    {
        "name": "Cryptography — key exchange, encrypt/decrypt, replay detection (server/cryptography/cryptography.go)",
        "language": "go",
        "filename": "server/cryptography/cryptography.go",
        "code": open("sliver-src/server/cryptography/cryptography.go").read(),
    },

    # 8. Operator auth middleware — bearer token, RBAC
    #    tokenAuthFunc uses SHA256-hashed token for DB lookup.
    #    Token cache uses sync.Map without eviction.
    {
        "name": "Operator auth middleware — token auth + RBAC (server/transport/middleware.go)",
        "language": "go",
        "filename": "server/transport/middleware.go",
        "code": open("sliver-src/server/transport/middleware.go").read(),
    },
]


def main():
    total = len(SECTIONS)
    results = []

    print(f"\n{'='*72}")
    print(f"  Scanning Sliver C2 (latest master) for NEW vulnerabilities")
    print(f"  Sections: {total}")
    print(f"  Mode: deep analysis (per-CWE focused + critique + voting)")
    print(f"{'='*72}\n")

    for i, section in enumerate(SECTIONS):
        name = section["name"]
        print(f"  [{i+1}/{total}] {name}")

        start = time.time()
        try:
            result = model.analyze_deep.remote(
                code=section["code"],
                language=section["language"],
                filename=section["filename"],
                top_k_cwes=5,
            )
        except Exception as e:
            elapsed = time.time() - start
            print(f"         [ERR] {e} ({elapsed:.1f}s)")
            results.append({
                "name": name,
                "error": str(e),
            })
            continue

        elapsed = time.time() - start
        verdict = result["verdict"]
        cwe = result["detected_cwe"]
        flagged = result.get("flagged_cwes", {})
        focused = result.get("focused_cwes", [])

        tag = "[VULN]" if verdict == "VULNERABLE" else "[CLEAN]"
        print(f"         {tag} {verdict} (primary: {cwe}, {elapsed:.1f}s)")
        if flagged:
            print(f"         Flagged: {flagged}")
        if focused:
            print(f"         Focused on: {focused}")

        results.append({
            "name": name,
            "verdict": verdict,
            "detected_cwe": cwe,
            "flagged_cwes": flagged,
            "focused_cwes": focused,
            "elapsed": round(elapsed, 1),
            "analysis": result.get("analysis", ""),
        })

    # Summary
    vulns = [r for r in results if r.get("verdict") == "VULNERABLE"]
    clean = [r for r in results if r.get("verdict") == "NOT VULNERABLE"]
    errors = [r for r in results if "error" in r]

    print(f"\n{'='*72}")
    print(f"  Summary: {len(vulns)} sections flagged, {len(clean)} clean, {len(errors)} errors")
    print(f"{'='*72}\n")

    for r in vulns:
        print(f"  [VULN]   {r['name']}")
        for cwe_id, source in r.get("flagged_cwes", {}).items():
            print(f"           - {cwe_id} (via {source})")
        print()

    for r in clean:
        print(f"  [CLEAN]  {r['name']}")

    # Detailed reports
    for r in results:
        if r.get("verdict") == "VULNERABLE":
            print(f"\n{'─'*72}")
            print(f"  {r['name']}")
            print(f"  Flagged CWEs: {sorted(r.get('flagged_cwes', {}).keys())}")
            print(f"{'─'*72}")
            analysis = r.get("analysis", "")
            # Print truncated analysis for each flagged CWE
            for line in analysis.split("\n"):
                print(f"  {line[:200]}")
            print()

    # Save full results
    report_path = "/tmp/sliver-latest-scan-report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
