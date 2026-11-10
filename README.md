<div align="center">

# 🛡️ Security Operations Portfolio

**Hands-on, reproducible labs for SOC, incident response, detection engineering, cloud/IAM security, and vulnerability management.**
Every lab runs locally on Windows with Python. It uses only synthetic data, includes tests, and ends with a written analyst decision.

</div>

| # | Lab | What it proves | Roles | Demo |
|---|---|---|---|---|
| 01 | [**SOC Detection & Incident Response**](01-soc-detection-ir) | Detect brute force → successful logon in noisy Windows logs, triage a true positive vs a false positive, build a timeline, write the incident report, find what the rule misses | SOC Analyst · IR · Detection Eng · Threat Hunting | [3-min demo](01-soc-detection-ir#️-3-minute-demo-windows-powershell) |
| 02 | **AWS CloudTrail & IAM Investigation** *(in progress)* | Investigate IAM privilege changes: authorized change vs denied attempt vs successful suspicious escalation; decide on containment | Cloud Security · IAM · IR | - |
| 03 | **Vulnerability Prioritization & Remediation** *(in progress)* | Rank findings by exposure, asset criticality and exploitation evidence, not CVSS alone; remediation ticket and re-validation | Vulnerability Mgmt · Security Analyst · GRC | - |

## Skills by role
| Role | Where to look |
|---|---|
| **SOC Analyst** | 01: alert triage, evidence vs missing evidence, escalation decision |
| **Incident Response** | 01: timeline, containment with verification steps · 02: containment decision |
| **Detection Engineering** | 01: rule logic, scoring, false-positive tuning, documented blind spots, tests |
| **Threat Hunting** | 01: low-and-slow attack the rule does not catch |
| **Cloud Security / IAM** | 02 |
| **Vulnerability Management / GRC** | 03 |

## Quick start
```powershell
git clone https://github.com/bricedon/soc-analyst-portfolio
cd soc-analyst-portfolio\01-soc-detection-ir
python detect.py
python -m unittest
```
Requirements: Python 3.8+ (standard library only). Splunk is optional.

## About this portfolio
- **Honest scope:** these are **lab** projects on synthetic data, not production incidents. See [PROVENANCE.md](PROVENANCE.md) for what was AI-assisted, what I executed, and what I improved.
- **Data:** fictional company, users, and hosts; external IPs from RFC 5737 documentation ranges.

Built by **Brice Albert Donfack** · CompTIA CySA+, PenTest+, Security+, Network+ · AWS Cloud Practitioner · [GitHub profile](https://github.com/bricedon)
