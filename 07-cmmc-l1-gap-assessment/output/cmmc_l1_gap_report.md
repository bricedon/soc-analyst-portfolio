# CMMC Level 1 Gap Assessment: Northwind Precision Parts LLC (fictional)

Assessment date: 2026-11-15 · Assessor: Brice Donfack (practice assessment) · Scope: Federal Contract Information (FCI) only - no CUI

## Executive summary

- **6 of 15** Level 1 requirements are fully met (4 partial, 4 not met, 1 not assessed).
- **Annual affirmation: NOT READY.** Level 1 requires all 15 requirements to be met; a plan of action (POA&M) is **not** allowed at Level 1, so partial items must be closed before affirming.
- Highest risks: Authorized access (AC.L1-B.1.I); Flaw remediation (SI.L1-B.1.XII); External connections (AC.L1-B.1.III).
- With the planned capacity, all gaps can be closed by **2027-01-10**, then re-assessed before affirmation.

## Results by requirement

| ID | Requirement | NIST 800-171 | Status | Gap | Evidence |
|---|---|---|---|---|---|
| AC.L1-B.1.I | Authorized access | 3.1.1 | **Partial** | 3 accounts of employees who left in 2026 are still enabled | AD user export 2026-11-10; HR leaver list |
| AC.L1-B.1.II | Transaction & function control | 3.1.2 | **Met** | - | GPO report: standard users are not local administrators; screenshot of admin group |
| AC.L1-B.1.III | External connections | 3.1.20 | **Not Met** | RDP jump host published to the internet without MFA; personal cloud storage not restricted | Firewall rule export |
| AC.L1-B.1.IV | Control public information | 3.1.22 | **Met** | - | Website publishing procedure v1.2 with approval step |
| IA.L1-B.1.V | Identification | 3.5.1 | **Partial** | One shared shop-floor login used by 6 machine operators | AD user export |
| IA.L1-B.1.VI | Authentication | 3.5.2 | **Not Met** | Printer and two network switches still use factory default passwords | Device inventory |
| MP.L1-B.1.VII | Media disposal | 3.8.3 | **Not Met** | No media sanitization procedure; 11 old hard drives stored in an unlocked cabinet | Interview with IT |
| PE.L1-B.1.VIII | Limit physical access | 3.10.1 | **Met** | - | Badge system report; server closet lock photo |
| PE.L1-B.1.IX | Manage visitors & physical access | 3.10.3/3.10.4/3.10.5 | **Partial** | Visitor log exists but no written escort rule; badge reader logs not reviewed | Visitor sign-in sheet (paper) |
| SC.L1-B.1.X | Boundary protection | 3.13.1 | **Partial** | Firewall in place but logs are not reviewed by anyone | Firewall configuration |
| SC.L1-B.1.XI | Public-access system separation | 3.13.5 | **Met** | - | Website hosted by external provider; no inbound path to internal network |
| SI.L1-B.1.XII | Flaw remediation | 3.14.1 | **Not Met** | Two P1 vulnerabilities are past their remediation date (RDP exposure; browser on 9 PCs) | Vulnerability register 2026-11-12 |
| SI.L1-B.1.XIII | Malicious code protection | 3.14.2 | **Met** | - | Defender console: 34/34 endpoints protected |
| SI.L1-B.1.XIV | Update malicious code protection | 3.14.4 | **Met** | - | Defender console: signatures updated within 24 h on all endpoints |
| SI.L1-B.1.XV | System & file scanning | 3.14.5 | **Not Assessed** | No evidence received for scheduled scans and real-time scanning of downloads, email and USB | - |

## Remediation plan (ordered)

| # | ID | Action needed | Risk | Effort (h) | Quick win | Owner | Target |
|---|---|---|---|---|---|---|---|
| 1 | SI.L1-B.1.XV | No evidence received for scheduled scans and real-time scanning of downloads, email and USB | Medium | 1 | yes | IT Manager | 2026-11-22 |
| 2 | AC.L1-B.1.I | 3 accounts of employees who left in 2026 are still enabled | High | 2 | yes | IT Manager | 2026-11-22 |
| 3 | SI.L1-B.1.XII | Two P1 vulnerabilities are past their remediation date (RDP exposure; browser on 9 PCs) | High | 10 |  | IT Manager | 2026-11-29 |
| 4 | AC.L1-B.1.III | RDP jump host published to the internet without MFA; personal cloud storage not restricted | High | 16 |  | IT Manager | 2026-12-13 |
| 5 | IA.L1-B.1.VI | Printer and two network switches still use factory default passwords | Medium | 3 | yes | IT Manager | 2026-12-13 |
| 6 | MP.L1-B.1.VII | No media sanitization procedure; 11 old hard drives stored in an unlocked cabinet | Medium | 6 |  | IT Manager | 2026-12-20 |
| 7 | IA.L1-B.1.V | One shared shop-floor login used by 6 machine operators | Medium | 8 |  | Production Manager | 2026-12-27 |
| 8 | SC.L1-B.1.X | Firewall in place but logs are not reviewed by anyone | Medium | 12 |  | IT Manager | 2027-01-10 |
| 9 | PE.L1-B.1.IX | Visitor log exists but no written escort rule; badge reader logs not reviewed | Low | 3 | yes | Facilities | 2027-01-10 |

## Evidence requests

- **SI.L1-B.1.XV System & file scanning**: provide scheduled scans and real-time scanning of downloads, email and USB (owner: IT Manager).

## Links to the technical labs

- AC.L1-B.1.III: see lab 03 (F03) / 01 (INC-0001)
- IA.L1-B.1.VI: see lab 03 (F08)
- SC.L1-B.1.X: see lab 01 / 05
- SI.L1-B.1.XII: see lab 03 (revalidation)
