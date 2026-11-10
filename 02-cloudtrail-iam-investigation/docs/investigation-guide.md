# CloudTrail IAM Investigation Guide

## 1. The CloudTrail fields that answer "who, what, where, result"
| Question | Field | Watch out for |
|---|---|---|
| Who (caller) | `userIdentity.type`, `.arn`, `.userName` | `AssumedRole` means a role session: find who assumed it |
| Who (really) | AssumeRole event whose `responseElements.credentials.accessKeyId` = the session's `accessKeyId`; `sessionContext.sourceIdentity` | Role session names can be chosen freely by the caller, so they are not proof |
| MFA | `additionalEventData.MFAUsed` (ConsoleLogin), `sessionContext.attributes.mfaAuthenticated` | Long-term access keys (AKIA…) never carry MFA |
| What | `eventSource` + `eventName` | `read_only` events are still useful for reconnaissance |
| On what | `requestParameters` (`userName`, `policyArn`, `roleArn`…) | |
| Result | `errorCode` (`AccessDenied`…) | No `errorCode` = success |
| From where | `sourceIPAddress`, `userAgent` | An AWS service shows a hostname instead of an IP |

## 2. Method
1. **List sensitive actions** (IAM writes, key creation, logging changes).
2. **Resolve the identity chain** back to the first credential.
3. **Check authorization**: change ticket (actor + action + target + time window).
4. **Score risk factors**: unknown IP, no MFA, off-hours, admin policy, identity or key created today, logging tampered.
5. **Group into incidents** by credential origin + source IP.
6. **Assess impact**: what can the attacker do now with the permissions they gained?
7. **Run the pre-containment checks**, then contain. Disabling the wrong role can stop production.

## 3. Containment options for this lab (in order)
| Action | AWS CLI (for reference, not executed) | Verify |
|---|---|---|
| Restart logging | `aws cloudtrail start-logging --name org-trail` | `get-trail-status` → `IsLogging: true` |
| Deactivate the backdoor key | `aws iam update-access-key --user-name backup-svc2 --access-key-id <id> --status Inactive` | `list-access-keys` shows Inactive; no new events with that key |
| Detach admin, then delete the user | `aws iam detach-user-policy ...`, `delete-access-key`, `delete-user` | `get-user` returns NoSuchEntity |
| Contain `mlee` | Reset the console password; deny active sessions (the "Revoke active sessions" option on the role, or a policy with `aws:TokenIssueTime` condition) | Next ConsoleLogin requires the new password + MFA |
| Fix the root cause | Enforce MFA for console users; restrict who can assume DevOpsAutomation | IAM credential report shows MFA on all users |
| Rotate leaked `ci-deploy` key | Create a new key in the CI secret store, deactivate the old one | Pipeline green with the new key; old key unused |

## 4. Equivalent SQL (Athena over CloudTrail logs, or CloudTrail Lake)
> ⚠️ Written for reference, **not executed** in this lab (no AWS account used). Table name `cloudtrail_logs` is an example.

```sql
-- All sensitive IAM / logging writes, with result and caller
SELECT eventtime, eventname, useridentity.arn AS caller, sourceipaddress,
       errorcode, requestparameters
FROM cloudtrail_logs
WHERE eventsource IN ('iam.amazonaws.com', 'cloudtrail.amazonaws.com')
  AND eventname IN ('CreateUser','CreateAccessKey','AttachUserPolicy','PutUserPolicy',
                    'AttachRolePolicy','PutRolePolicy','StopLogging','DeleteTrail')
ORDER BY eventtime;

-- Console logins without MFA
SELECT eventtime, useridentity.username, sourceipaddress,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No';

-- Who assumed a given role
SELECT eventtime, useridentity.arn AS caller, sourceipaddress,
       json_extract_scalar(requestparameters, '$.roleArn') AS role
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
  AND json_extract_scalar(requestparameters, '$.roleArn') LIKE '%DevOpsAutomation%';
```

## 5. ATT&CK mapping
T1078.004 Valid Accounts: Cloud Accounts · T1136.003 Create Account: Cloud Account · T1098.001 Account Manipulation: Additional Cloud Credentials · T1562.008 Impair Defenses: Disable or Modify Cloud Logs
