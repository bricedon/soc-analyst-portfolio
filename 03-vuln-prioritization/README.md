# 03 · Vulnerability Prioritization & Remediation Lab

> **Recruiter summary.** This lab turns a scan with 10 findings into a **risk-ranked remediation register**, an **actionable ticket** with SLA, rollback and definition of done, and a **revalidation report** from a rescan. Prioritization combines **CVSS + exploitation evidence (CISA KEV, EPSS, public exploit, attacks seen in our own logs) + exposure + asset criticality − compensating controls**, and every score explains itself. The key case: a **CVSS 7.5** VPN flaw that is known-exploited and internet-facing ranks **#1**, ahead of a **CVSS 9.8** flaw on an isolated test server that ranks **#9**.
>
> **Roles:** Vulnerability Management · Security Analyst · GRC / Risk · SOC (feeds from lab 01)
> **Stack:** Python 3 (standard library only) · CSV in/out (opens in Excel)

| Evidence | Link |
|---|---|
| Remediation register (ranked, with reasons) | [output/remediation_register.md](output/remediation_register.md) · [CSV](output/remediation_register.csv) |
| Example P1 ticket | [output/TICKET-F02.md](output/TICKET-F02.md) |
| Revalidation after rescan | [output/revalidation_2026-11-12.csv](output/revalidation_2026-11-12.csv) |
| Method and how to defend a priority | [docs/prioritization-method.md](docs/prioritization-method.md) |
| Inputs | [assets](data/assets.csv) · [scan](data/scan_results.csv) · [threat intel](data/threat_intel.csv) · [rescan](data/rescan_2026-11-12.csv) |
| Tests (8) | [test_vuln_lab.py](test_vuln_lab.py) |

## ▶️ 3-minute demo (Windows PowerShell)
```powershell
cd soc-analyst-portfolio\03-vuln-prioritization
python prioritize.py                                       # ranked register
python prioritize.py ticket F02                            # P1 ticket with 72-hour SLA
python prioritize.py revalidate data\rescan_2026-11-12.csv # what is really fixed?
python -m unittest                                         # 8 tests pass
```
Talking points: **(1)** F02 (CVSS 7.5) is #1: CISA KEV, used by ransomware, internet-facing, the entry point for every remote employee. **(2)** F01 (CVSS 9.8) is #9: isolated VLAN, no exploit, decommission planned. I would still **verify** that isolation. **(3)** F03 is only CVSS 5.3, but we **saw** it being attacked in lab 01, so it becomes P1. **(4)** The rescan shows that "patched" is not "fixed": 9 of 150 workstations are still vulnerable, F03 is overdue, and a new VPN finding appeared.

## Example output
```text
 #  ID   PRI SCORE CVSS  HOST           EXPOSURE            KEV  DUE         TITLE
------------------------------------------------------------------------------------------------------------------------
 1  F02  P1   95.0  7.5  vpn-gw01       internet            yes  2026-11-05  VPN gateway path traversal exposes session tokens
 2  F03  P1   83.2  5.3  jump-rdp01     internet            no   2026-11-09  RDP exposed to the internet without MFA
 3  F06  P1   79.2  8.8  wks-fleet      internal            yes  2026-11-09  Browser engine remote code execution (malicious web
 4  F07  P2   74.4  8.1  file01         internal            no   2026-12-02  SMBv1 protocol enabled
 ...
 9  F01  P4   27.2  9.8  lab-test07     isolated            no   2027-05-01  TestRunner agent remote code execution
```
```text
F02  P1  vpn-gw01       2026-11-05  Closed - verified by rescan
F03  P1  jump-rdp01     2026-11-09  Still open - OVERDUE
F06  P1  wks-fleet      2026-11-09  Partially remediated (9/150 hosts still vulnerable) - OVERDUE
F11  ?   A01            -           NEW finding - triage and score it
```

## What was tested
| Part | Status |
|---|---|
| `prioritize.py` (rank, ticket, revalidate), 8 unit tests | ✅ Executed (Python 3.13) |

All data is fictional. **CVE-2026-9xxxx identifiers are invented for this lab** and do not refer to real vulnerabilities; KEV and EPSS values are simulated.
