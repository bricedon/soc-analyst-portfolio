# P1 remediation ticket: F02 - VPN gateway path traversal exposes session tokens

| Field | Value |
|---|---|
| Asset | vpn-gw01 (Remote-access VPN appliance (all staff)), 1 host(s) |
| Owner / assignee | Network team |
| Vulnerability | CVE-2026-90020 - CVSS 7.5 |
| Risk score / priority | 95.0 / **P1** (rank #1) |
| Detected | 2026-11-02 |
| **Due date (SLA)** | **2026-11-05** |

## Why this priority
- CVSS 7.5 x4 = 30.0
- in CISA KEV since 2026-10-28 +30
- used in ransomware campaigns +5
- exposure internet +15
- asset criticality 5/5 +15
- KEV + internet-facing: emergency 72h SLA

## Required action
Apply vendor firmware 9.4.7; then invalidate all VPN sessions and rotate admin credentials

## Change plan
1. Schedule the change (emergency change if the SLA is 72 hours) and notify users of the expected impact.
2. Take a backup / configuration snapshot of vpn-gw01 before the change.
3. Apply the fix.
4. Test the service works (functional check by Network team).

## Rollback
Restore the snapshot / previous version if the service fails the functional check, then escalate to the security team the same day. Rolling back reopens the risk.

## Definition of done (validation evidence)
- [ ] Rescan of vpn-gw01 no longer reports CVE-2026-90020 (attach the rescan export)
- [ ] Version / configuration check output attached
- [ ] For credential-related fixes: credentials rotated and old sessions invalidated
- [ ] Register status changed to "Closed - verified"
