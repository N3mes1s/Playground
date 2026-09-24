# EDR triage benchmark (real data)

Jev as a detection-engineering / EDR alert-triage layer, scored against **Atomic Red Team** attacker-technique commands (malicious, ground-truth ATT&CK technique ids) and a hand-written **admin/dev baseline** (benign hard negatives).

- Malicious: **569** events · Benign: **20** events · model `jev-latest` · threshold 0.5
- **Recall (attacks flagged): 72.1%** (410/569)
- **False-positive rate (benign flagged): 5.0%** (1/20)
- **ATT&CK tactic top-1: 39.1%** (199/509 events with a known tactic)
- Latency p50/p95: 733 / 1191 ms · cost $0.02668 for the whole run (635,303 input tokens)

Regenerate: `python -m security.datasets --art <clone> --sigma <clone>` then `python -m security.edr_bench --full`.

## Threshold sweep (recall vs false positives)

The malicious/benign call returns a calibrated probability; a detection engineer picks the operating point. Dual-use Discovery/C2 commands are what move with the threshold.

| threshold | recall | FP rate |
|---|---|---|
| 0.2 | 90.3% | 40.0% |
| 0.3 | 84.4% | 20.0% |
| 0.4 | 79.3% | 5.0% |
| 0.5 | 72.1% | 5.0% |
| 0.6 | 63.6% | 0.0% |
| 0.7 | 55.5% | 0.0% |
| 0.8 | 40.8% | 0.0% |

## Per-tactic recall and tactic-label accuracy

| ATT&CK tactic | events | attacks flagged | tactic label correct |
|---|---|---|---|
| Execution | 124 | 99/124 (80%) | 56/124 (45%) |
| Persistence | 76 | 62/76 (82%) | 35/76 (46%) |
| Privilege Escalation | 74 | 65/74 (88%) | 6/74 (8%) |
| Credential Access | 67 | 51/67 (76%) | 34/67 (51%) |
| Discovery | 57 | 15/57 (26%) | 39/57 (68%) |
| Collection | 33 | 28/33 (85%) | 6/33 (18%) |
| Exfiltration | 22 | 20/22 (91%) | 10/22 (45%) |
| Command and Control | 20 | 15/20 (75%) | 8/20 (40%) |
| Lateral Movement | 16 | 11/16 (69%) | 2/16 (12%) |
| Impact | 12 | 8/12 (67%) | 2/12 (17%) |
| Initial Access | 6 | 3/6 (50%) | 0/6 (0%) |
| Reconnaissance | 2 | 1/2 (50%) | 1/2 (50%) |

## Benign baseline (false-positive check)

| benign activity | malicious p | severity | flagged? |
|---|---|---|---|
| installing a monitoring agent | 0.51 | 2.9 | **FP** |
| sysadmin remote troubleshooting | 0.39 | 2.0 | no |
| admin checking shadow copies | 0.34 | 1.0 | no |
| installing docker on a fresh host | 0.33 | 2.9 | no |
| auth'd SUID audit by security team | 0.27 | 1.6 | no |
| admin checking own group membership | 0.25 | 1.5 | no |
| admin verifying DCs | 0.21 | 1.1 | no |
| verifying a download hash | 0.20 | 1.1 | no |
| scheduled backup | 0.18 | 1.4 | no |
| SCCM patch inventory | 0.16 | 0.7 | no |
| developer testing base64 in a REPL | 0.16 | 0.5 | no |
| encrypting a backup before upload | 0.14 | 1.4 | no |
| collecting logs for a support case | 0.13 | 1.0 | no |
| downloading a real tool | 0.12 | 1.2 | no |
| HR access review script | 0.11 | 1.3 | no |
| inventory script reading OS version | 0.11 | 0.2 | no |
| troubleshooting a port | 0.10 | 0.3 | no |
| CI deploy step | 0.09 | 1.7 | no |
| perf triage | 0.07 | 0.2 | no |
| nightly /etc backup | 0.06 | 0.4 | no |

## Sample false negatives (159 total)

| technique | test | malicious p |
|---|---|---|
| T1016.001 | Check internet connection using ping Windows | 0.07 |
| T1124 | System Time Discovery - PowerShell | 0.07 |
| T1072 | PDQ Deploy RAT | 0.08 |
| T1195.002 | Simulate npm package installation on a Linux system | 0.08 |
| T1518 | Applications Installed | 0.08 |
| T1057 | Process Discovery - tasklist | 0.09 |
| T1059.003 | Writes text to a file and displays it. | 0.09 |
| T1614.001 | Discover System Language with chcp | 0.09 |
| T1615 | Display group policy information via gpresult | 0.10 |
| T1680 | Local Storage Discovery via PSDrive | 0.10 |
| T1123 | using device audio capture commandlet | 0.11 |
| T1529 | Shutdown System - Windows | 0.11 |
| T1614.001 | Discover System Language by Registry Query | 0.11 |
| T1016.001 | Check internet connection using ping freebsd, linux or macos | 0.12 |
| T1016 | List Windows Firewall Rules | 0.12 |
| T1049 | System Network Connections Discovery with PowerShell | 0.12 |
| T1053.007 | ListCronjobs | 0.12 |
| T1112 | Modify Registry of Current User Profile - cmd | 0.12 |
| T1124 | System Time Discovery | 0.12 |
| T1202 | Indirect Command Execution - pcalua.exe | 0.12 |
