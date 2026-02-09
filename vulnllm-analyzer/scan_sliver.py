#!/usr/bin/env python3
"""Scan Sliver C2 DNS handler for GHSA-wxrw-gvg8-fqjp (CVE-2026-25791)."""

import json
import time
import modal

# Server-side: handleC2 + handleHello — the core vulnerability
# handleC2 routes TOTP messages to handleHello without any auth check,
# and handleHello allocates sessions unconditionally.
SERVER_HANDLER_CODE = r'''
// From server/c2/dns.go — Sliver C2 Framework (BishopFox)
// SliverDNSServer handles DNS-based C2 communication

func (s *SliverDNSServer) handleC2(domain string, req *dns.Msg) *dns.Msg {
    subdomain := req.Question[0].Name[:len(req.Question[0].Name)-len(domain)]
    msg, checksum, err := s.decodeSubdata(subdomain)
    if err != nil {
        return s.nameErrorResp(req)
    }

    // TOTP Handler can be called without dns session ID
    if msg.Type == dnspb.DNSMessageType_TOTP {
        return s.handleHello(domain, msg, req)
    }

    // All other handlers require a valid dns session ID
    _, ok := s.sessions.Load(msg.ID & sessionIDBitMask)
    if !ok {
        return s.nameErrorResp(req)
    }

    switch msg.Type {
    case dnspb.DNSMessageType_NOP:
        return s.handleNOP(domain, msg, checksum, req)
    case dnspb.DNSMessageType_INIT:
        return s.handleDNSSessionInit(domain, msg, checksum, req)
    case dnspb.DNSMessageType_POLL:
        return s.handlePoll(domain, msg, checksum, req)
    case dnspb.DNSMessageType_DATA_FROM_IMPLANT:
        return s.handleDataFromImplant(domain, msg, checksum, req)
    case dnspb.DNSMessageType_DATA_TO_IMPLANT:
        return s.handleDataToImplant(domain, msg, checksum, req)
    case dnspb.DNSMessageType_CLEAR:
        return s.handleClear(domain, msg, checksum, req)
    }
    return nil
}

func (s *SliverDNSServer) handleHello(domain string, msg *dnspb.DNSMessage, req *dns.Msg) *dns.Msg {
    dnsSessionID := dnsSessionID()
    s.sessions.Store(dnsSessionID&sessionIDBitMask, &DNSSession{
        ID:                dnsSessionID & sessionIDBitMask,
        dnsIdMsgIdMap:     map[uint32]uint32{},
        outgoingMsgIDs:    []uint32{},
        outgoingBuffers:   map[uint32][]byte{},
        outgoingMutex:     &sync.RWMutex{},
        incomingEnvelopes: map[uint32]*PendingEnvelope{},
        incomingMutex:     &sync.Mutex{},
        msgCount:          uint32(0),
    })

    resp := new(dns.Msg)
    resp.SetReply(req)
    resp.Authoritative = true
    respBuf := make([]byte, 4)
    binary.LittleEndian.PutUint32(respBuf, dnsSessionID)
    for _, q := range req.Question {
        switch q.Qtype {
        case dns.TypeA:
            a := &dns.A{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.TTL},
                A:   respBuf,
            }
            resp.Answer = append(resp.Answer, a)
        }
    }
    return resp
}

// StartDNSListener - Start a DNS listener
func StartDNSListener(bindIface string, lport uint16, domains []string, canaries bool, enforceOTP bool) *SliverDNSServer {
    server := &SliverDNSServer{
        server:       &dns.Server{Addr: fmt.Sprintf("%s:%d", bindIface, lport), Net: "udp"},
        sessions:     &sync.Map{},
        messages:     &sync.Map{},
        TTL:          0,
        MaxTXTLength: defaultMaxTXTLength,
        EnforceOTP:   enforceOTP,
    }
    dns.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
        server.HandleDNSRequest(domains, canaries, writer, req)
    })
    return server
}

type SliverDNSServer struct {
    server       *dns.Server
    sessions     *sync.Map
    messages     *sync.Map
    TTL          uint32
    MaxTXTLength int
    EnforceOTP   bool
}
'''

# Client-side: getDNSSessionID + SessionInit
# getDNSSessionID fetches a session ID via unauthenticated DNS query
# SessionInit calls it before any crypto verification
CLIENT_INIT_CODE = r'''
// From implant/sliver/transports/dnsclient/dnsclient.go — Sliver C2 Framework

// SessionInit - Initialize DNS session
func (s *SliverDNSClient) SessionInit() error {
    err := s.loadResolvConf()
    if err != nil {
        return err
    }
    if len(s.resolvConf.Servers) < 1 {
        return errNoResolvers
    }
    s.resolvers = []DNSResolver{}
    for _, server := range s.resolvConf.Servers {
        s.resolvers = append(s.resolvers,
            NewGenericResolver(server, s.resolvConf.Port, s.retryWait, s.retryCount, s.queryTimeout, s.parent),
        )
    }

    err = s.getDNSSessionID() // Get a 'dns session id' -- NO AUTH CHECK
    if err != nil {
        return err
    }
    s.fingerprintResolvers() // Fingerprint the resolvers
    if len(s.resolvers) < 1 {
        return errNoResolvers
    }

    // Key agreement with server (happens AFTER unauthenticated session allocation)
    sKey := cryptography.RandomSymmetricKey()
    s.cipherCtx = cryptography.NewCipherContext(sKey)
    initData, err := cryptography.AgeKeyExToServer(sKey[:])
    if err != nil {
        return err
    }
    resolver, _ := s.randomResolver()
    initMsg := &dnspb.DNSMessage{
        ID:   s.nextMsgID(),
        Type: dnspb.DNSMessageType_INIT,
        Size: uint32(len(initData)),
    }
    respData, err := s.sendInit(resolver, s.base32, initMsg, initData)
    if err != nil {
        return err
    }
    data, err := s.cipherCtx.Decrypt(respData)
    if err != nil {
        return err
    }
    if binary.LittleEndian.Uint32(data)&sessionIDBitMask != s.dnsSessionID {
        return err
    }
    // ... start workers ...
    return nil
}

func (s *SliverDNSClient) getDNSSessionID() error {
    otpMsg, err := s.otpMsg()
    if err != nil {
        return err
    }
    otpDomain, err := s.joinSubdataToParent(otpMsg)
    if err != nil {
        return err
    }

    var a []byte
    for _, resolver := range s.resolvers {
        a, _, err = resolver.A(otpDomain)
        if err == nil {
            break
        }
    }
    if err != nil {
        return err // All resolvers failed
    }
    if len(a) < 1 {
        return errInvalidDNSSessionID
    }
    s.dnsSessionID = binary.LittleEndian.Uint32(a) & sessionIDBitMask
    if s.dnsSessionID == 0 {
        return errInvalidDNSSessionID
    }
    return nil
}

func (s *SliverDNSClient) otpMsg() (string, error) {
    otpMsg := &dnspb.DNSMessage{
        Type: dnspb.DNSMessageType_TOTP,
        ID:   uint32(0),
    }
    data, err := proto.Marshal(otpMsg)
    if err != nil {
        return "", err
    }
    msg, _ := s.base32.Encode(data)
    return string(msg), nil
}
'''

SECTIONS = [
    {
        "name": "handleC2 + handleHello (unauthenticated session allocation)",
        "code": SERVER_HANDLER_CODE,
        "language": "go",
        "filename": "server/c2/dns.go",
    },
    {
        "name": "SessionInit + getDNSSessionID (unauthenticated session fetch)",
        "code": CLIENT_INIT_CODE,
        "language": "go",
        "filename": "implant/sliver/transports/dnsclient/dnsclient.go",
    },
]


def main():
    VulnLLMModel = modal.Cls.from_name("vulnllm-analyzer", "VulnLLMModel")
    model = VulnLLMModel()

    print("\n" + "=" * 72)
    print("  Scanning Sliver C2 DNS Handler — GHSA-wxrw-gvg8-fqjp")
    print("  Expected: CWE-306 (Missing Auth) + CWE-400 (Resource Exhaustion)")
    print("  Language: Go (not in LANGUAGE_CWES — generalization test)")
    print(f"  Sections: {len(SECTIONS)}")
    print("=" * 72)

    results = []
    for i, section in enumerate(SECTIONS, 1):
        print(f"\n  [{i}/{len(SECTIONS)}] {section['name']}")
        started = time.time()
        result = model.analyze_deep.remote(
            code=section["code"],
            language=section["language"],
            filename=section["filename"],
        )
        elapsed = time.time() - started
        verdict = result["verdict"]
        primary_cwe = result["detected_cwe"]
        flagged = result.get("flagged_cwes", {})
        focused = result.get("focused_cwes", [])

        tag = "[VULN]" if verdict == "VULNERABLE" else "[CLEAN]"
        print(f"         {tag} {verdict} (primary: {primary_cwe}, {elapsed:.1f}s)")
        print(f"         Flagged: {flagged}")
        print(f"         Focused on: {focused}")
        result["section_name"] = section["name"]
        result["elapsed"] = elapsed
        results.append(result)

    # Summary
    print("\n" + "=" * 72)
    flagged_count = sum(1 for r in results if r["verdict"] == "VULNERABLE")
    print(f"  Summary: {flagged_count}/{len(SECTIONS)} sections flagged")
    print("=" * 72)
    for r in results:
        tag = "[VULN]" if r["verdict"] == "VULNERABLE" else "[CLEAN]"
        print(f"\n  {tag}   {r['section_name']}")
        if r["verdict"] == "VULNERABLE":
            for cwe_id, source in r.get("flagged_cwes", {}).items():
                print(f"           - {cwe_id} (via {source})")

    # Details
    for r in results:
        print(f"\n{'─' * 72}")
        print(f"  {r['section_name']}")
        flagged = r.get("flagged_cwes", {})
        if flagged:
            print(f"  Flagged CWEs: {sorted(flagged.keys())}")
        print(f"{'─' * 72}")
        print(f"  {r['analysis'][:2000]}")

    # Save report
    report_path = "/tmp/sliver-scan-report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
