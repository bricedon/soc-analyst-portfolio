# CloudTrail IAM findings

| Time (UTC) | Action | Actor | Credential origin | Target | Policy | Result | Verdict | Severity |
|---|---|---|---|---|---|---|---|---|
| 2026-10-20T03:47:14Z | CreateUser | DevOpsAutomation/mlee | mlee | backup-svc2 | - | Success | SUSPICIOUS | Critical |
| 2026-10-20T03:48:02Z | AttachUserPolicy | DevOpsAutomation/mlee | mlee | backup-svc2 | AdministratorAccess | Success | SUSPICIOUS | Critical |
| 2026-10-20T03:48:38Z | CreateAccessKey | DevOpsAutomation/mlee | mlee | backup-svc2 | - | Success | SUSPICIOUS | Critical |
| 2026-10-20T03:56:13Z | StopLogging | backup-svc2 | mlee | org-trail | - | Success | SUSPICIOUS | Critical |
| 2026-10-20T11:03:33Z | AttachUserPolicy | ci-deploy | ci-deploy | ci-deploy | AdministratorAccess | AccessDenied | BLOCKED ATTEMPT | Medium |
| 2026-10-20T11:03:52Z | CreateAccessKey | ci-deploy | ci-deploy | ci-deploy | - | AccessDenied | BLOCKED ATTEMPT | Medium |
| 2026-10-20T15:12:40Z | AttachUserPolicy | devon.admin | devon.admin | intern.qa | ReadOnlyAccess | Success | AUTHORIZED (CHG-2041) | Info |

## IAM-INC-01 - Critical - origin mlee from 203.0.113.200

Actions SUCCEEDED. Window 2026-10-20T03:47:14Z -> 2026-10-20T03:56:13Z.

- `2026-10-20T03:47:14Z` **CreateUser** on `backup-svc2` - New IAM identity (possible persistence). Risks: source IP 203.0.113.200 not in known networks; no MFA in the session chain; outside the owner's normal hours. Chain: DevOpsAutomation/mlee <- assumed by mlee at 2026-10-20T03:44:34Z from 203.0.113.200
- `2026-10-20T03:48:02Z` **AttachUserPolicy** on `backup-svc2` - FULL control of every AWS service and resource. Risks: source IP 203.0.113.200 not in known networks; no MFA in the session chain; grants AdministratorAccess; outside the owner's normal hours. Chain: DevOpsAutomation/mlee <- assumed by mlee at 2026-10-20T03:44:34Z from 203.0.113.200
- `2026-10-20T03:48:38Z` **CreateAccessKey** on `backup-svc2` - New long-term credential (persistence / exfiltration of access). Risks: source IP 203.0.113.200 not in known networks; no MFA in the session chain; outside the owner's normal hours. Chain: DevOpsAutomation/mlee <- assumed by mlee at 2026-10-20T03:44:34Z from 203.0.113.200
- `2026-10-20T03:56:13Z` **StopLogging** on `org-trail` - CloudTrail logging STOPPED (defense evasion). Risks: source IP 203.0.113.200 not in known networks; no MFA in the session chain; audit logging tampered; outside the owner's normal hours; actor backup-svc2 was created today; uses an access key created today. Chain: backup-svc2 <- key AKIANYRVD7RXINFRPYZ4 created at 2026-10-20T03:48:38Z by DevOpsAutomation/mlee

Checks before containment:
- [ ] Confirm with the identity owner OUT-OF-BAND (phone / manager), not through the possibly compromised account.
- [ ] List every credential involved: access keys (aws iam list-access-keys), console passwords, active role sessions.
- [ ] Check what else the attacker identities touched (all CloudTrail events by those keys and IPs, all regions).
- [ ] Check the business impact of disabling: is the role/user used by production pipelines or applications?
- [ ] Look for other persistence: new users, new keys, changed role trust policies, new policy versions, Lambda/EC2 created.
- [ ] If logging was stopped: re-enable it FIRST and check other evidence (organization trail, S3 access logs, GuardDuty).
- [ ] Preserve evidence (export CloudTrail records) before deleting anything.

## IAM-INC-02 - Medium - origin ci-deploy from 203.0.113.77

All attempts DENIED. Window 2026-10-20T11:03:33Z -> 2026-10-20T11:03:52Z.

- `2026-10-20T11:03:33Z` **AttachUserPolicy** on `ci-deploy` - FULL control of every AWS service and resource. Risks: source IP 203.0.113.77 not in known networks; grants AdministratorAccess. Chain: ci-deploy
- `2026-10-20T11:03:52Z` **CreateAccessKey** on `ci-deploy` - New long-term credential (persistence / exfiltration of access). Risks: source IP 203.0.113.77 not in known networks. Chain: ci-deploy
