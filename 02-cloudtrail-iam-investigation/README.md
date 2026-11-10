# 02 · AWS CloudTrail & IAM Investigation Lab

> **Recruiter summary.** This lab investigates **IAM privilege changes** in AWS CloudTrail **without needing an AWS account**. A Python tool reads real-format CloudTrail JSON. It resolves **who is really behind each call**, for example `DevOpsAutomation/mlee` traced back to user `mlee`'s login without MFA, and a new access key traced back to the session that created it. It also checks each change against **change tickets**, flags risk factors, and groups findings into incidents with a **pre-containment checklist**. The data contains an **authorized** change, a **denied** attempt, and a **successful escalation**: a backdoor admin user is created, then CloudTrail logging is stopped.
>
> **Roles:** Cloud Security Analyst · IAM · Incident Response · SOC
> **Stack:** Python 3 (standard library only) · CloudTrail JSON · Athena/CloudTrail Lake SQL · MITRE ATT&CK T1078.004, T1136.003, T1098.001, T1562.008

| Evidence | Link |
|---|---|
| Findings and incidents (generated) | [output/findings.md](output/findings.md) |
| Investigation method, field guide, SQL queries | [docs/investigation-guide.md](docs/investigation-guide.md) |
| Raw data (CloudTrail format) | [data/cloudtrail.json](data/cloudtrail.json) · [change tickets](data/change_tickets.csv) · [identities](data/identities.csv) |
| Tests (9) | [test_cloudtrail_lab.py](test_cloudtrail_lab.py) |

## ▶️ 3-minute demo (Windows PowerShell)
```powershell
cd soc-analyst-portfolio\02-cloudtrail-iam-investigation
python generate_events.py           # same 52 CloudTrail records every time
python investigate.py               # 7 sensitive actions -> 1 authorized, 2 denied, 4 suspicious
python investigate.py --actor mlee  # the identity chain: login without MFA -> role -> new admin user -> logging stopped
python -m unittest                  # 9 tests pass
```
Talking points: **(1)** `devon.admin`'s change matches ticket CHG-2041, with MFA, from the corporate IP, during the ticket window. **(2)** `ci-deploy` was denied, but a CI key used from an internet IP is itself a **leaked key**: "blocked" does not mean "safe". **(3)** At 03:41, `mlee` signs in without MFA from an unknown IP. By 03:56 there is a new admin user with a key, and CloudTrail is stopped. **(4)** At 14:05 the real Min Lee signs in **with** MFA from the office, so the 03:41 login was most likely a stolen password.

## Example output
```text
TIME (UTC)            ACTION            ACTOR                   CRED ORIGIN  TARGET       RESULT        VERDICT
----------------------------------------------------------------------------------------------------------------------
2026-10-20T03:47:14Z  CreateUser        DevOpsAutomation/mlee   mlee         backup-svc2  Success       SUSPICIOUS [Critical]
2026-10-20T03:48:02Z  AttachUserPolicy  DevOpsAutomation/mlee   mlee         backup-svc2  Success       SUSPICIOUS [Critical]
2026-10-20T03:48:38Z  CreateAccessKey   DevOpsAutomation/mlee   mlee         backup-svc2  Success       SUSPICIOUS [Critical]
2026-10-20T03:56:13Z  StopLogging       backup-svc2             mlee         org-trail    Success       SUSPICIOUS [Critical]
2026-10-20T11:03:33Z  AttachUserPolicy  ci-deploy               ci-deploy    ci-deploy    AccessDenied  BLOCKED ATTEMPT [Medium]
2026-10-20T11:03:52Z  CreateAccessKey   ci-deploy               ci-deploy    ci-deploy    AccessDenied  BLOCKED ATTEMPT [Medium]
2026-10-20T15:12:40Z  AttachUserPolicy  devon.admin             devon.admin  intern.qa    Success       AUTHORIZED (CHG-2041) [Info]
```
"Credential origin" is the credential that started the chain. It is **not** proof of which person typed the commands. That difference is the key judgment in this lab.

## The three planted cases
| Case | Evidence | Correct decision |
|---|---|---|
| Authorized change | Ticket CHG-2041 matches actor, action, target, policy and time window; MFA; corporate IP | Close; no action |
| Denied attempt | `ci-deploy` key from 203.0.113.77 (expected: internal build servers only) tries to grant itself AdministratorAccess | Not an escalation, but a **leaked key**: rotate and deactivate it, find where it leaked |
| Successful escalation | No-MFA login, off-hours, unknown IP → AssumeRole → CreateUser + AdministratorAccess + CreateAccessKey → new key used → StopLogging | Critical incident: run the pre-containment checks, then contain |

## What was tested
| Part | Status |
|---|---|
| Generator, investigation tool, 9 unit tests | ✅ Executed (Python 3.13) |
| Athena / CloudTrail Lake SQL in the guide | ⚠️ Written, **not executed** (no AWS account used, by design) |

All data is synthetic. Account 111122223333 is the example account ID from AWS documentation; IPs come from RFC 5737 documentation ranges.
