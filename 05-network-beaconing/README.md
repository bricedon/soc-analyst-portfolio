# 05 · Network Beaconing (C2) Hunt Lab

> **Recruiter summary.** A **threat-hunting** lab on 10,559 Zeek-style connection records from 30 workstations over 8 hours. Infected machines "call home" on a schedule; people browsing the web do not. The tool scores every source → destination pair on **timing regularity** (coefficient of variation), **size regularity**, duration, **prevalence** (how many hosts use the destination) and **upload ratio**. It finds a 60-second C2 beacon and a slow, jittery **upload every ~45 minutes** (possible exfiltration). It does this without being fooled by the perfectly regular, but legitimate, endpoint agent and NTP traffic.
>
> **Roles:** Threat Hunter · SOC Analyst · Network Security · Detection Engineering
> **Stack:** Python 3 (standard library) · Zeek conn.log fields · MITRE ATT&CK T1071.001, T1029, T1041

| Evidence | Link |
|---|---|
| Ranked candidates (CSV) | [output/beacon_candidates.csv](output/beacon_candidates.csv) |
| Allowlist with owner and review date | [data/allowlist.csv](data/allowlist.csv) |
| Tests (7) | [test_beacon_lab.py](test_beacon_lab.py) |

## ▶️ 3-minute demo
```powershell
cd soc-analyst-portfolio\05-network-beaconing
python generate_conn.py
python beacon_hunt.py
python beacon_hunt.py --show 10.10.20.113 203.0.113.99   # see the 60-second rhythm
python beacon_hunt.py --no-allowlist                      # what the allowlist hides, and why prevalence still helps
python -m unittest
```
Talking points: **(1)** Regular timing alone is not enough: NTP and the endpoint agent are *more* regular than the malware. **Prevalence** (30 hosts use them) and an **owned allowlist with a review date** handle that. **(2)** The real beacon: 462 connections, a median of 59.8 s, CV 0.03, one host, an external IP. **(3)** The slow one sends 40–260 KB **out** every ~45 minutes. If I raise `--min-conns` to 12, it disappears. Every threshold creates a blind spot.

## Example output
```text
SCORE  VERDICT       SRC            DST             PORT  CONNS MEDIAN GAP    CV HOSTS
--------------------------------------------------------------------------------------------
 98.3  LIKELY BEACON 10.10.20.113   203.0.113.99    443     462      59.8s 0.028     1
 90.0  LIKELY BEACON 10.10.20.108   198.51.100.200  443      11    2862.9s 0.151     1
 35.0  allowlisted   10.10.20.109   10.10.10.5      123      29    1024.0s   0.0    30
```

## Next steps an analyst would take
Pull the host's process / EDR data for the connecting process. Check DNS (which domain resolved to that IP?) and the TLS certificate / JA3 in Zeek `ssl.log`. Isolate the host if confirmed, then block the destination and hunt for it on other hosts.

## What was tested
✅ Generator, hunt tool, 7 unit tests (Python 3.13). All traffic is synthetic; external IPs are RFC 5737 documentation addresses.
