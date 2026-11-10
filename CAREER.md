# CV lines & STAR stories

> **Rule:** fill the `[ ]` fields **only with results you produced and can show**: a command output, a report in this repo, a commit. Leave a field empty until then. Lab work is described as lab work.

## 01 · SOC Detection & Incident Response Lab

**CV line (template)**
> Built a Python/Splunk detection lab for brute-force-then-success attacks on synthetic Windows logs (4624/4625); triaged [ __ ] alerts, wrote [ __ ] incident report(s), and [ reduced false positives by __ / added a hunting rule that caught a low-and-slow attack ] while keeping the true positive detected ([ __ ] automated tests).

**STAR (template)**
| | |
|---|---|
| **Situation** | Lab: one day of noisy Windows authentication logs (364 events, 198 failed logons) with two alerts from a brute-force detection rule. |
| **Task** | Decide for each alert: escalate or close, with evidence, and improve the detection. |
| **Action** | [ What I checked: event IDs, source IP, logon type, account privileges, activity after logon. Queries I ran. ] |
| **Result** | [ My verdicts, my escalation time, the report I wrote, the tuning I made and its measured effect. ] |
| **Lesson** | [ e.g. "A score is a hint, not proof"; "the most dangerous attack didn't trigger the rule". ] |

## Labs 02–08: CV line templates
> Same rule: fill `[ ]` only with your own results.

| Lab | CV line (template) |
|---|---|
| 02 CloudTrail & IAM | Investigated synthetic AWS CloudTrail logs to trace an IAM privilege escalation through an assumed role back to a no-MFA console login; identified [ __ ] persistence actions and wrote a pre-containment checklist. |
| 03 Vulnerability Mgmt | Built a risk-based prioritization of [ __ ] findings combining CVSS, CISA KEV, EPSS, exposure and asset criticality; produced a remediation register, an SLA-driven ticket and a rescan-based revalidation. |
| 04 Phishing Triage | Built a Python .eml triage tool (SPF/DKIM/DMARC, lookalike domains, link and attachment analysis); classified [ __ ] reported emails, including a BEC that passed email authentication. |
| 05 Beaconing Hunt | Hunted C2 beaconing in [ __ ] connection records using interval regularity and destination prevalence; separated a 60-second beacon from legitimate periodic traffic. |
| 06 Linux Investigation | Reconstructed a Linux SSH compromise from auth.log (brute force, sudo misuse, UID-0 backdoor, cron persistence) and defined rebuild and hardening steps. |
| 07 CMMC L1 | Performed a practice CMMC Level 1 gap assessment (15 requirements mapped to NIST SP 800-171), produced an affirmation-readiness decision and a capacity-based remediation plan. |
| 08 Endpoint Detection | Wrote [ __ ] process-creation detections (Python + Sigma, validated with pySigma) for macro, encoded-PowerShell, LOLBin and renamed-binary techniques, with a narrow allowlist that keeps detection intact. |

**STAR:** use the same template as lab 01 for each lab you present. Situation = the lab scenario, Task = the decision, Action = your queries and reasoning, Result = your verdict and the measured effect of your improvement.

---

### How I describe my experience (honest framing)
- **Professional:** 5+ years at Amazon (Sep 2021–present) in operations monitoring, triage, root-cause analysis and SLA-driven escalation, including Tier I IT support (Oct 2025–Jan 2026). No professional SOC role yet.
- **Transferable:** watching real-time dashboards for threshold breaches → alert triage; CAPA and audits → verifying that a fix worked; SOP escalation under SLA → incident escalation.
- **Lab:** the projects in this repository, on synthetic data.
