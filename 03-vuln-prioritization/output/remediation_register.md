# Remediation register

| # | Finding | Priority | Score | CVSS | Asset | Exposure | KEV | Due | Owner |
|---|---|---|---|---|---|---|---|---|---|
| 1 | F02 VPN gateway path traversal exposes session tokens | **P1** | 95.0 | 7.5 | vpn-gw01 | internet | yes | 2026-11-05 | Network team |
| 2 | F03 RDP exposed to the internet without MFA | **P1** | 83.2 | 5.3 | jump-rdp01 | internet | no | 2026-11-09 | IT Ops |
| 3 | F06 Browser engine remote code execution (malicious web page) | **P1** | 79.2 | 8.8 | wks-fleet | internal | yes | 2026-11-09 | IT Ops |
| 4 | F07 SMBv1 protocol enabled | **P2** | 74.4 | 8.1 | file01 | internal | no | 2026-12-02 | IT Ops |
| 5 | F05 Database server privilege escalation by authenticated user | **P3** | 52.2 | 8.8 | db-erp01 | internal-segmented | no | 2027-01-31 | DBA team |
| 6 | F04 Web framework reflected cross-site scripting | **P3** | 51.4 | 6.1 | web-shop01 | internet | no | 2027-01-31 | Web team |
| 7 | F08 Printer web admin uses default credentials | **P3** | 51.0 | 7.5 | mfp-printer01 | internal | no | 2027-01-31 | IT Ops |
| 8 | F09 TLS 1.0 enabled | **P4** | 31.8 | 3.7 | web-shop01 | internet | no | 2027-05-01 | Web team |
| 9 | F01 TestRunner agent remote code execution | **P4** | 27.2 | 9.8 | lab-test07 | isolated | no | 2027-05-01 | QA team |
| 10 | F10 TestRunner web console information disclosure | **P4** | 9.2 | 5.3 | lab-test07 | isolated | no | 2027-05-01 | QA team |

## Why each score
- **F02** (P1, 95.0): CVSS 7.5 x4 = 30.0; in CISA KEV since 2026-10-28 +30; used in ransomware campaigns +5; exposure internet +15; asset criticality 5/5 +15; KEV + internet-facing: emergency 72h SLA
- **F03** (P1, 83.2): CVSS 5.3 x4 = 21.2; attack OBSERVED against this asset in our logs +30; used in ransomware campaigns +5; exposure internet +15; asset criticality 4/5 +12
- **F06** (P1, 79.2): CVSS 8.8 x4 = 35.2; in CISA KEV since 2026-10-30 +30; exposure internal +5; asset criticality 3/5 +9
- **F07** (P2, 74.4): CVSS 8.1 x4 = 32.4; public exploit available +10; EPSS 0.6 >= 0.5 +10; used in ransomware campaigns +5; exposure internal +5; asset criticality 4/5 +12
- **F05** (P3, 52.2): CVSS 8.8 x4 = 35.2; public exploit available +10; exposure internal-segmented +2; asset criticality 5/5 +15; compensating control (segmentation: only app servers can connect) -10
- **F04** (P3, 51.4): CVSS 6.1 x4 = 24.4; public exploit available +10; exposure internet +15; asset criticality 4/5 +12; compensating control (WAF in blocking mode) -10
- **F08** (P3, 51.0): CVSS 7.5 x4 = 30.0; public exploit available +10; exposure internal +5; asset criticality 2/5 +6
- **F09** (P4, 31.8): CVSS 3.7 x4 = 14.8; exposure internet +15; asset criticality 4/5 +12; compensating control (WAF in blocking mode) -10
- **F01** (P4, 27.2): CVSS 9.8 x4 = 39.2; exposure isolated +0; asset criticality 1/5 +3; compensating control (isolated VLAN with no route to production) -10; decommission planned -5
- **F10** (P4, 9.2): CVSS 5.3 x4 = 21.2; exposure isolated +0; asset criticality 1/5 +3; compensating control (isolated VLAN with no route to production) -10; decommission planned -5
