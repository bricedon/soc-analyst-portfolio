# 07 · CMMC Level 1 Gap Assessment Lab (GRC)

> **Recruiter summary.** A practice **CMMC Level 1** assessment for a fictional 32-person machine shop that holds Federal Contract Information for a defense prime contractor. The tool maps evidence to the **15 Level 1 requirements** (FAR 52.204-21) and their **NIST SP 800-171** equivalents. It decides whether the company can sign its **annual affirmation**: it cannot, because Level 1 allows **no POA&M**. It then builds a prioritized, capacity-based remediation plan and an evidence request list. Findings link back to the technical labs: RDP exposure (labs 01 and 03), overdue patches (lab 03), default passwords (lab 03).
>
> **Roles:** GRC / Compliance Analyst · Security Analyst · ISSO (junior) · Consultant for DoD suppliers
> **Stack:** Python 3 (standard library) · CSV / Markdown · CMMC 2.0 (32 CFR Part 170), FAR 52.204-21, NIST SP 800-171

| Evidence | Link |
|---|---|
| Gap report (executive summary, results, plan) | [output/cmmc_l1_gap_report.md](output/cmmc_l1_gap_report.md) |
| Remediation plan (opens in Excel) | [output/remediation_plan.csv](output/remediation_plan.csv) |
| Inputs | [requirements](data/requirements.csv) · [assessment](data/assessment.csv) · [company profile](data/company_profile.csv) |
| Tests (7) | [test_cmmc_lab.py](test_cmmc_lab.py) |

## ▶️ 3-minute demo
```powershell
cd soc-analyst-portfolio\07-cmmc-l1-gap-assessment
python assess.py
python assess.py --hours-per-week 4     # less IT capacity -> later dates: a business conversation, not just a technical one
python -m unittest
```
Talking points: **(1)** 6 of 15 met; "Partial" is still a fail at Level 1. **(2)** Order: get the missing evidence first, then high risk, then quick wins: disabling 3 former employees' accounts takes 2 hours and closes a high-risk gap. **(3)** Compliance and security meet here: the overdue patches from lab 03 are what fail SI.L1-B.1.XII.

## Example output
```text
Status: Met 6 | Partial 4 | Not Met 4 | Not Assessed 1
Annual affirmation: NOT READY (all 15 must be Met; no POA&M at Level 1)

 #  ID              STATUS        RISK     HRS  TARGET      GAP
 1  SI.L1-B.1.XV    Not Assessed  Medium     1  2026-11-22  No evidence received for scheduled scans and real-time sca
 2  AC.L1-B.1.I     Partial       High       2  2026-11-22  3 accounts of employees who left in 2026 are still enabled
 3  SI.L1-B.1.XII   Not Met       High      10  2026-11-29  Two P1 vulnerabilities are past their remediation date (RD
 4  AC.L1-B.1.III   Not Met       High      16  2026-12-13  RDP jump host published to the internet without MFA; perso
```

## Important limits
This is a **practice** assessment with fictional data. Requirement text is summarized; an official Level 1 self-assessment follows the DoD *CMMC Level 1 Assessment Guide* and its assessment objectives, and the result is entered in SPRS with an annual affirmation by a senior official.

## What was tested
✅ `assess.py` and 7 unit tests (Python 3.13).
