# Prioritization method

## Why not CVSS alone?
CVSS base score measures **how severe a flaw is in general**. It does not know whether the system faces the internet, whether attackers are using the flaw right now, or whether the server runs payroll or a test lab. Teams that patch by CVSS alone spend their first week on findings that are dangerous on paper, while the one being exploited waits.

## Inputs
| Input | Question it answers | Source in real life |
|---|---|---|
| CVSS base | How bad is the flaw itself? | Scanner, NVD |
| CISA KEV | Is it **known to be exploited** in the wild? | cisa.gov KEV catalog |
| EPSS | **Probability** of exploitation in the next 30 days | FIRST.org EPSS |
| Public exploit / ransomware use | How easy and attractive is it? | Vendor / threat intel |
| Observed in our environment | Are we **already** being attacked through it? | SIEM / EDR (lab 01) |
| Exposure | Who can reach it? | Asset inventory, firewall rules |
| Asset criticality | What breaks if it is compromised? | Business impact analysis |
| Compensating controls | What reduces the risk until we patch? | WAF, segmentation, MFA |

## Score
```
CVSS x 4                         0-40
+ exploitation evidence          up to +45 (observed or KEV +30, else public exploit +10, EPSS>=0.5 +10, ransomware +5)
+ exposure                       internet 15 · internal 5 · segmented 2 · isolated 0
+ criticality x 3                3-15
- compensating control           -10
- decommission planned           -5
```
P1 ≥ 75 (7 days; **72 h** if KEV and internet-facing) · P2 55–74 (30 days) · P3 35–54 (90 days) · P4 < 35 (next cycle or risk acceptance).

The weights are a **documented choice**, not a law. What matters in an interview is that you can explain them and change them when the business disagrees.

## Defending "lower CVSS first" (F02 vs F01)
| | F02, VPN gateway | F01, test server |
|---|---|---|
| CVSS | 7.5 | **9.8** |
| Exploited in the wild | **Yes (KEV), used by ransomware** | No |
| EPSS | **0.94** | 0.004 |
| Reachable by attackers | **Internet, every attacker** | Isolated VLAN, no route |
| Business impact | **All remote staff, entry to the network** | QA tests, decommission in December |

*"I fix F02 first because it is being exploited right now, anyone on the internet can reach it, and it is our front door. F01 is more severe on paper, but an attacker would first need to get inside an isolated network. I still schedule F01, and I verify the isolation claim with a firewall rule review, because my ranking depends on it."*

## Remediation lifecycle
`Detect → Prioritize → Ticket (owner, SLA, plan, rollback) → Fix → Rescan → Close only with evidence`
"Patched" is a claim; a clean rescan is the evidence. Partial fixes and overdue items are reported, not hidden.

## When you cannot fix in time
Document a **risk acceptance or exception**: the finding, the reason, the compensating controls, an expiry date, and the approval of the asset owner. Without that, the item stays overdue in the register.
