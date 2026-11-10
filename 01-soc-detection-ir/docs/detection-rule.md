# Detection Rule: Brute Force Followed by Successful Logon

| Field | Value |
|---|---|
| **Name** | `BruteForceThenSuccess` |
| **Data source** | Windows Security log: 4625 (failed logon), 4624 (successful logon); enrichment from 4672, 4720, 4723/4724, 4732 |
| **Logic** | ≥ 5 failures for the **same user + same source IP** within a **sliding 10-minute** window, then a 4624 for that user + IP within **30 minutes** after the last failure |
| **ATT&CK** | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) → [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/); follow-on [T1136.001 Create Local/Domain Account](https://attack.mitre.org/techniques/T1136/), [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Reference implementation** | [`detect.py`](../detect.py) (tested) · Splunk version: [`splunk/queries.spl`](../splunk/queries.spl) Q1 (not executed here) |

## Why "failures **then success**"?
Failed logons alone are constant noise. On this lab day, 198 of 364 events are 4625 failures: internet scanning, typos, and a misconfigured scanner service. Alerting on failures alone would bury the analyst. A success right after a burst means the guessing **may have worked**. That is the moment an analyst must look.

## Enrichment and risk score (triage aid, not a verdict)
| Signal | Points | Why it matters |
|---|---|---|
| Base: burst + success | +40 | |
| Source IP is external (not RFC 1918) | +20 | Most legitimate admin access comes from inside |
| Target is internet-exposed | +5 | Known attack surface |
| Account is privileged | +15 | Higher impact if compromised |
| 4672 special privileges at logon | +5 | Admin-level session |
| 4720 / 4732 etc. by the user within 60 min | +20 | Persistence / privilege change right after access |
| Same IP tried other usernames | +5 | Guessing behavior, not one confused user |
| User changed own password ≤ 2 h before | −20 | Classic stale-credential false positive |
| Source = user's assigned workstation | −15 | Expected device |

Severity: **High ≥ 80 · Medium 50–79 · Low < 50**. The score explains its reasons line by line, so the analyst can disagree with it.

## Known false-positive sources
- Password change followed by an old saved credential (mapped drive, phone mail profile, scheduled task). **ALERT-002 in this lab.**
- Shared kiosk / shift accounts where many people type the password.
- Vulnerability scanners using credentials.

Tuning options (test each one against the known-bad case so you do not lose it):
allow-list scanner IPs, lower the score for internal sources with a recent password change, suppress repeats for the same user + device for 24 h after a ticket confirms a benign cause.

## Known blind spots (what this rule will NOT catch)
| Blind spot | Example in this lab | Better detection |
|---|---|---|
| **Low and slow**: under 5 failures per 10 minutes | `k.chen` from 198.51.100.23: 27 failures over ~3.5 h, then success at 13:48 | Long-window aggregation (e.g. ≥ 10 failures in 4 h), or "first success from a never-seen external IP" |
| **Password spraying**: 1–2 tries per user across many users | (not planted; the internet noise is similar) | Count distinct users per source IP |
| **Distributed attack**: many IPs, same user | - | Group by user only |
| Success through another protocol (VPN, OWA) | - | Correlate other log sources |

## Validation
- Unit tests (`test_soc_lab.py`) prove: the malicious case fires as **High**, the benign case fires as **Low**, the low-and-slow case is **missed** by the default rule and **found** with a 4-hour window.
- A real-world check that is still missing: running the rule on production-like data and measuring the alert volume per day.
