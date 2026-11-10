<div align="center">

# 🛡️ Security Operations Portfolio

**8 hands-on, reproducible labs across SOC, incident response, detection engineering, threat hunting, cloud/IAM, vulnerability management and GRC.**
Every lab runs locally on Windows with Python. It uses only synthetic data, includes automated tests (69 in total), and ends with a written analyst decision.

![Python](https://img.shields.io/badge/Python_3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk_SPL-000000?style=flat-square&logo=splunk&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma_rules-0A7BBB?style=flat-square)
![AWS](https://img.shields.io/badge/AWS_CloudTrail-232F3E?style=flat-square&logo=amazonaws&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-C8202F?style=flat-square)
![Tests](https://img.shields.io/badge/tests-69_passing-2EA44F?style=flat-square)

</div>

## 📂 Labs

| # | Lab | The question it answers | Roles |
|---|---|---|---|
| 01 | [**SOC Detection & Incident Response**](01-soc-detection-ir) | Brute force → successful logon in noisy Windows logs: true positive or false positive? Escalate? What does the rule miss? | SOC · IR · Detection Eng · Threat Hunting |
| 02 | [**AWS CloudTrail & IAM Investigation**](02-cloudtrail-iam-investigation) | Who really created a backdoor admin and stopped CloudTrail, and what do we check before containment? | Cloud Security · IAM · IR |
| 03 | [**Vulnerability Prioritization & Remediation**](03-vuln-prioritization) | Why does a CVSS 7.5 come before a CVSS 9.8? Ticket, SLA, and proof the fix worked | Vulnerability Mgmt · Security Analyst · GRC |
| 04 | [**Phishing Email Triage**](04-phishing-triage) | Which reported emails are malicious, including a CEO fraud that passes SPF/DKIM/DMARC, and what do we block (and never block)? | SOC · Email Security · IR |
| 05 | [**Network Beaconing (C2) Hunt**](05-network-beaconing) | Which host is calling home in 10,559 connections, without flagging NTP and the endpoint agent? | Threat Hunting · SOC · Network Security |
| 06 | [**Linux SSH Compromise Investigation**](06-linux-ssh-investigation) | From auth.log: SSH guessing → root script → second root account → crontab. Clean or rebuild? | SOC · IR · Linux Security |
| 07 | [**CMMC Level 1 Gap Assessment**](07-cmmc-l1-gap-assessment) | Can a defense supplier honestly sign its annual affirmation? Prioritized remediation plan | GRC · Compliance · DoD supply chain |
| 08 | [**Endpoint Process Detection (Sysmon + Sigma)**](08-endpoint-process-detection) | Macro → encoded PowerShell → certutil → persistence; a renamed binary; a narrow allowlist | Detection Eng · SOC · IR |

## 🎯 Find what matters for your role
| Role | Start with |
|---|---|
| **SOC Analyst** | 01 → 04 → 08 |
| **Incident Response** | 01 → 06 → 02 |
| **Detection Engineering** | 08 → 01 (`docs/detection-rule.md`) → 05 |
| **Threat Hunting** | 05 → 01 (low-and-slow case) |
| **Cloud Security / IAM** | 02 |
| **Vulnerability Management** | 03 |
| **GRC / Compliance (CMMC, NIST 800-171)** | 07 → 03 |

## 🔗 One story across the labs
The labs share a fictional company, CORP, and one fictional attacker. The C2 address **203.0.113.99** shows up as a beacon (05), a Linux download (06) and a macro download cradle (08). The RDP attack in **01** becomes a P1 vulnerability in **03** and a failed CMMC requirement in **07**. Security operations, vulnerability management and compliance feed each other.

## ⚡ Quick start
```powershell
git clone https://github.com/bricedon/soc-analyst-portfolio
cd soc-analyst-portfolio\01-soc-detection-ir
python detect.py
python -m unittest
```
Each lab folder has a **recruiter summary**, a **3-minute demo**, example output, links to evidence, and a "What was tested" table. Requirements: Python 3.8+ (standard library only). Splunk is optional.

## About this portfolio
- **Honest scope:** these are **lab** projects on synthetic data, not production incidents. [PROVENANCE.md](PROVENANCE.md) shows what was AI-assisted, what I executed, and what I improved.
- **Data:** fictional company, people and hosts; external IPs from RFC 5737 documentation ranges; CVE-2026-9xxxx IDs are invented.
- **Training:** each lab has an exercise (in French, my first language) and a separate solution; see [TRAINING-PLAN.md](TRAINING-PLAN.md).

Built by **Brice Albert Donfack** · CompTIA CySA+, PenTest+, Security+, Network+ · CSAP · CNSP · CNVP · ISC2 CC · AWS Cloud Practitioner · [GitHub profile](https://github.com/bricedon)
