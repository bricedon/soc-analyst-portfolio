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

## 02 · AWS CloudTrail & IAM Investigation Lab
_Template added when the lab is published._

## 03 · Vulnerability Prioritization & Remediation Lab
_Template added when the lab is published._

---

### How I describe my experience (honest framing)
- **Professional:** 5+ years at Amazon (Sep 2021–present) in operations monitoring, triage, root-cause analysis and SLA-driven escalation, including Tier I IT support (Oct 2025–Jan 2026). No professional SOC role yet.
- **Transferable:** watching real-time dashboards for threshold breaches → alert triage; CAPA and audits → verifying that a fix worked; SOP escalation under SLA → incident escalation.
- **Lab:** the projects in this repository, on synthetic data.
