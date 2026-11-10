# 01 · SOC Detection & Incident Response Lab

> **Recruiter summary.** This project detects **brute-force attacks that end in a successful Windows logon**. It is tested on a noisy, reproducible day of synthetic Windows Security logs (364 events). It covers the full analyst loop: **detect → enrich → triage → timeline → incident report → tune**. It includes a **malicious** case (RDP compromise of an admin account, with a backdoor admin account created), a **benign alert** (stale password after a password change), and an **edge case the rule misses on purpose** (a low-and-slow attack), to show that I understand detection limits as well as detections.
>
> **Roles:** SOC Analyst · Incident Response · Detection Engineering · Threat Hunting
> **Stack:** Python 3 (standard library only) · Splunk SPL · PowerShell · MITRE ATT&CK T1110.001, T1078, T1136, T1098

| Evidence | Link |
|---|---|
| Detection logic, scoring, false positives, blind spots | [docs/detection-rule.md](docs/detection-rule.md) |
| Detection output (alerts + timelines) | [output/alerts.md](output/alerts.md) |
| Splunk queries (detection + triage + scoping) | [splunk/queries.spl](splunk/queries.spl) |
| Incident report template | [reports/incident-report-template.md](reports/incident-report-template.md) |
| Tests (15) | [test_soc_lab.py](test_soc_lab.py) |
| Who did what (AI vs me) | [../PROVENANCE.md](../PROVENANCE.md) |

---

## ▶️ 3-minute demo (Windows PowerShell)
```powershell
git clone https://github.com/bricedon/soc-analyst-portfolio
cd soc-analyst-portfolio\01-soc-detection-ir

python generate_logs.py            # 1. rebuild the same log day (deterministic, seed 42)
python detect.py                   # 2. run the detection: 2 alerts, scored and explained
python detect.py --timeline ALERT-001   # 3. the attack story, event by event
python -m unittest                 # 4. 15 tests pass
```
Talking points: **(1)** 198 of 364 events are failed logons, mostly noise. **(2)** The rule only fires when failures are followed by a success, and the score explains every point. **(3)** ALERT-001: brute force at 02:13, RDP success at 02:19, a new admin account by 02:24. **(4)** ALERT-002 also fires, but it is a password-change false positive. **(5)** The rule misses a low-and-slow attack on `k.chen`, which I found by hunting.

## Example output
```text
Analyzed 364 events (198 failed logons). Alerts: 2

ALERT      SEV     SCORE  USER       SOURCE IP       TARGET      FAILS  SUCCESS AT
--------------------------------------------------------------------------------------------
ALERT-001  High      100  a.morgan   203.0.113.45    SRV-RDP01      14  2026-10-14T02:19:58Z
ALERT-002  Low         5  j.rivera   10.10.20.117    SRV-FILE01      9  2026-10-14T09:11:22Z

ALERT-001: source IP is external (+20); target host is internet-exposed (+5); account is privileged (+15); special privileges assigned at logon (4672) (+5); account created / group membership changed after logon (+20); same IP tried other usernames (+5)
ALERT-002: user changed own password shortly before (stale credential pattern) (-20); source is the user's assigned workstation (-15)
```
```text
Timeline for ALERT-001 (a.morgan from 203.0.113.45)

2026-10-14T02:13:05Z  4625  SRV-RDP01   Logon FAILED                     user=amorgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC0000064
2026-10-14T02:13:14Z  4625  SRV-RDP01   Logon FAILED                     user=alex.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC0000064
2026-10-14T02:13:24Z  4625  SRV-RDP01   Logon FAILED                     user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC000006A
                     ...  12 more identical failures  ...
2026-10-14T02:18:46Z  4625  SRV-RDP01   Logon FAILED                     user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC000006A
2026-10-14T02:19:58Z  4624  SRV-RDP01   Logon success                    user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=10
2026-10-14T02:19:59Z  4672  SRV-RDP01   Special privileges assigned      user=a.morgan
2026-10-14T02:24:10Z  4720  SRV-DC01    User account CREATED             by=a.morgan target=support_tmp
2026-10-14T02:24:48Z  4732  SRV-DC01    Member ADDED to local/domain group by=a.morgan member=support_tmp group=Administrators
```

## The three planted cases
| Case | What happens | Rule result | Correct analyst decision |
|---|---|---|---|
| **Malicious** | External IP guesses usernames, then 14 passwords for an IT admin; RDP success; new account added to Administrators | Fires · **High** | Escalate immediately, contain |
| **Benign alert** | User changes password; a mapped drive on his own PC keeps the old one; 9 failures, then success | Fires · **Low** | Verify with the user, close, tune |
| **Edge case** | 3 failures every ~25 min for 3.5 h from an external IP, then RDP success | **Missed** (never 5 in 10 min) | Found by hunting → new detection (week 2) |

Background noise: normal logons, typos, a backup service with admin privileges every hour, a scanner service failing all day with a stale password, and internet scanning of the RDP server.

## Local path, no Splunk needed
```powershell
$ev = Get-Content .\data\events.jsonl | ConvertFrom-Json
$ev | Where-Object EventCode -eq 4625 | Group-Object TargetUserName, IpAddress |
    Sort-Object Count -Descending | Select-Object -First 6 Count, Name
```
Optional: upload `data/events.jsonl` to Splunk Free (source type `_json`) and run [splunk/queries.spl](splunk/queries.spl).

## What was tested
| Part | Status |
|---|---|
| `generate_logs.py`, `detect.py`, 15 unit tests | ✅ Executed (Python 3.13, Linux build environment) |
| PowerShell investigation commands above | ✅ Executed in PowerShell 7 (Linux); to confirm on Windows PowerShell 5.1 |
| Splunk queries | ⚠️ Written, **not executed** (no Splunk available); validation is a training exercise |

All data is synthetic. External IPs use RFC 5737 documentation ranges. No real company, employee, or employer data.
