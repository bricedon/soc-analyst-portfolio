#!/usr/bin/env python3
"""
Synthetic AWS CloudTrail generator for the CloudTrail & IAM Investigation Lab.

One day (2026-10-20, UTC) in the fictional AWS account 111122223333
(the account ID AWS uses in its documentation). Records follow the real
CloudTrail JSON structure (eventVersion 1.08 fields).

Planted cases
  CASE-1  Authorized change   devon.admin (MFA, corporate IP) attaches ReadOnlyAccess
                              to intern.qa - matches change ticket CHG-2041.
  CASE-2  Denied attempt      ci-deploy access key, from an unknown IP, tries to attach
                              AdministratorAccess to itself and create a new key -> AccessDenied.
  CASE-3  Suspicious success  mlee signs in WITHOUT MFA from an unknown IP at 03:41, assumes
                              DevOpsAutomation, creates user backup-svc2, gives it
                              AdministratorAccess and an access key; the new key is used
                              minutes later and CloudTrail logging is stopped.

Noise: read-only API calls, MFA console logins, an application role reading S3,
a Lambda role, and the security team's scheduled audit role.

Usage:  python generate_events.py           # writes data/cloudtrail.json (+ context CSVs)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

ACCOUNT = "111122223333"
REGION = "us-east-1"
DAY = datetime(2026, 10, 20, tzinfo=timezone.utc)
CORP_IPS = ["198.51.100.10", "198.51.100.11"]          # corporate egress (fictional)
UA_CONSOLE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0"
UA_CLI = "aws-cli/2.17.0 Python/3.11.9 Windows/10 exe/AMD64"
UA_SDK = "Boto3/1.35.10 Python/3.12.4 Linux/6.1"


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.records = []

    def uid(self) -> str:
        return str(uuid.UUID(int=self.r.getrandbits(128), version=4))

    def key(self, prefix="AKIA") -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        return prefix + "".join(self.r.choice(alphabet) for _ in range(16))

    @staticmethod
    def user_identity(user: str, key: str, mfa: bool, console: bool = False) -> dict:
        ident = {
            "type": "IAMUser",
            "principalId": "AIDA" + user.upper().replace(".", "").replace("-", "")[:12].ljust(12, "X"),
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT,
            "accessKeyId": key,
            "userName": user,
        }
        if console or key.startswith("ASIA"):
            ident["sessionContext"] = {"attributes": {"mfaAuthenticated": str(mfa).lower(),
                                                      "creationDate": DAY.strftime("%Y-%m-%dT00:00:00Z")}}
        return ident

    @staticmethod
    def role_identity(role: str, session: str, key: str, source_identity: str = None, mfa: bool = False) -> dict:
        ident = {
            "type": "AssumedRole",
            "principalId": f"AROA{role.upper()[:12].ljust(12, 'X')}:{session}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
            "accountId": ACCOUNT,
            "accessKeyId": key,
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId": f"AROA{role.upper()[:12].ljust(12, 'X')}",
                                  "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}", "accountId": ACCOUNT,
                                  "userName": role},
                "attributes": {"mfaAuthenticated": str(mfa).lower(), "creationDate": DAY.strftime("%Y-%m-%dT00:00:00Z")},
            },
        }
        if source_identity:
            ident["sessionContext"]["sourceIdentity"] = source_identity
        return ident

    def add(self, ts: datetime, source: str, name: str, ident: dict, ip: str, ua: str,
            params=None, response=None, error: str = None, read_only: bool = None, extra=None) -> None:
        rec = {
            "eventVersion": "1.08",
            "userIdentity": ident,
            "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source,
            "eventName": name,
            "awsRegion": REGION,
            "sourceIPAddress": ip,
            "userAgent": ua,
            "requestParameters": params,
            "responseElements": response,
            "requestID": self.uid(),
            "eventID": self.uid(),
            "readOnly": read_only if read_only is not None else name.startswith(("Get", "List", "Describe", "Lookup")),
            "eventType": "AwsApiCall" if name != "ConsoleLogin" else "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": ACCOUNT,
        }
        if error:
            rec["errorCode"] = error
            rec["errorMessage"] = (f"User: {ident['arn']} is not authorized to perform: "
                                   f"{source.split('.')[0]}:{name} because no identity-based policy allows the action")
        if extra:
            rec.update(extra)
        self.records.append(rec)

    def at(self, h, m=0, s=0):
        return DAY + timedelta(hours=h, minutes=m, seconds=s)

    # ------------------------------------------------------------------ noise
    def noise(self) -> None:
        r = self.r
        staff = {"devon.admin": True, "mlee": False, "sara.ops": True, "intern.qa": False}
        reads = [("ec2.amazonaws.com", "DescribeInstances"), ("s3.amazonaws.com", "ListBuckets"),
                 ("iam.amazonaws.com", "ListUsers"), ("cloudwatch.amazonaws.com", "DescribeAlarms"),
                 ("ec2.amazonaws.com", "DescribeSecurityGroups"), ("iam.amazonaws.com", "GetUser")]
        for user, is_admin in staff.items():
            if user == "mlee":
                login_h = 14   # mlee's normal working-hours login (MFA) - the 03:41 one is the suspicious one
            else:
                login_h = r.randint(13, 15)
            t = self.at(login_h, r.randint(0, 59), r.randint(0, 59))
            ip = r.choice(CORP_IPS)
            mfa = True
            self.add(t, "signin.amazonaws.com", "ConsoleLogin", self.user_identity(user, "", mfa, console=True), ip,
                     UA_CONSOLE, response={"ConsoleLogin": "Success"},
                     extra={"additionalEventData": {"MFAUsed": "Yes" if mfa else "No", "LoginTo": "https://console.aws.amazon.com/"}})
            key = self.key("ASIA")
            for _ in range(r.randint(4, 9)):
                t += timedelta(minutes=r.randint(1, 25), seconds=r.randint(0, 59))
                src, name = r.choice(reads)
                self.add(t, src, name, self.user_identity(user, key, mfa, console=True), ip, UA_CONSOLE)
        # application role reading S3 all day
        for h in range(0, 24, 2):
            t = self.at(h, r.randint(0, 59), r.randint(0, 59))
            ident = self.role_identity("WebAppRole", "i-0a1b2c3d4e5f60718", self.key("ASIA"))
            self.add(t, "s3.amazonaws.com", "GetObject", ident, "10.20.1.15", UA_SDK,
                     params={"bucketName": "corp-app-assets", "key": f"img/{r.randint(1, 999)}.png"}, read_only=True)
        # scheduled security audit (read-only) at 06:00
        t = self.at(6, 0, 5)
        for name in ("GetAccountAuthorizationDetails", "ListAccessKeys", "GetCredentialReport"):
            ident = self.role_identity("SecurityAuditRole", "audit-scheduler", self.key("ASIA"))
            self.add(t, "iam.amazonaws.com", name, ident, "198.51.100.10", UA_SDK)
            t += timedelta(seconds=7)

    # ------------------------------------------------------------------ cases
    def case_authorized(self) -> None:
        ident = self.user_identity("devon.admin", self.key("ASIA"), True, console=True)
        t = self.at(15, 12, 40)
        self.add(t, "iam.amazonaws.com", "AttachUserPolicy", ident, CORP_IPS[0], UA_CONSOLE,
                 params={"userName": "intern.qa", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, read_only=False)

    def case_denied(self) -> None:
        key = self.key()
        ident = self.user_identity("ci-deploy", key, False)
        ip = "203.0.113.77"
        t = self.at(11, 3, 2)
        self.add(t, "sts.amazonaws.com", "GetCallerIdentity", ident, ip, UA_CLI, read_only=True)
        t += timedelta(seconds=31)
        self.add(t, "iam.amazonaws.com", "AttachUserPolicy", ident, ip, UA_CLI,
                 params={"userName": "ci-deploy", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                 error="AccessDenied", read_only=False)
        t += timedelta(seconds=19)
        self.add(t, "iam.amazonaws.com", "CreateAccessKey", ident, ip, UA_CLI,
                 params={"userName": "ci-deploy"}, error="AccessDenied", read_only=False)

    def case_suspicious(self) -> None:
        ip = "203.0.113.200"
        t = self.at(3, 41, 17)
        self.add(t, "signin.amazonaws.com", "ConsoleLogin", self.user_identity("mlee", "", False, console=True), ip,
                 UA_CONSOLE, response={"ConsoleLogin": "Success"},
                 extra={"additionalEventData": {"MFAUsed": "No", "LoginTo": "https://console.aws.amazon.com/"}})
        mlee = self.user_identity("mlee", self.key("ASIA"), False, console=True)
        t += timedelta(minutes=2, seconds=5)
        self.add(t, "iam.amazonaws.com", "ListAttachedUserPolicies", mlee, ip, UA_CONSOLE, params={"userName": "mlee"})
        t += timedelta(minutes=1, seconds=12)
        role_key = self.key("ASIA")
        self.add(t, "sts.amazonaws.com", "AssumeRole", mlee, ip, UA_CONSOLE,
                 params={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/DevOpsAutomation", "roleSessionName": "mlee",
                         "sourceIdentity": "mlee"},
                 response={"credentials": {"accessKeyId": role_key, "expiration": "Oct 20, 2026, 4:44:34 AM"},
                           "assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/DevOpsAutomation/mlee"},
                           "sourceIdentity": "mlee"}, read_only=False)
        role = self.role_identity("DevOpsAutomation", "mlee", role_key, source_identity="mlee")
        t += timedelta(minutes=2, seconds=40)
        self.add(t, "iam.amazonaws.com", "CreateUser", role, ip, UA_CONSOLE,
                 params={"userName": "backup-svc2"}, response={"user": {"userName": "backup-svc2"}}, read_only=False)
        t += timedelta(seconds=48)
        self.add(t, "iam.amazonaws.com", "AttachUserPolicy", role, ip, UA_CONSOLE,
                 params={"userName": "backup-svc2", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                 read_only=False)
        t += timedelta(seconds=36)
        new_key = self.key()
        self.add(t, "iam.amazonaws.com", "CreateAccessKey", role, ip, UA_CONSOLE,
                 params={"userName": "backup-svc2"},
                 response={"accessKey": {"userName": "backup-svc2", "accessKeyId": new_key, "status": "Active"}},
                 read_only=False)
        svc = self.user_identity("backup-svc2", new_key, False)
        t += timedelta(minutes=6, seconds=3)
        self.add(t, "sts.amazonaws.com", "GetCallerIdentity", svc, ip, UA_CLI)
        t += timedelta(seconds=22)
        self.add(t, "s3.amazonaws.com", "ListBuckets", svc, ip, UA_CLI)
        t += timedelta(minutes=1, seconds=10)
        self.add(t, "cloudtrail.amazonaws.com", "StopLogging", svc, ip, UA_CLI,
                 params={"name": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"}, read_only=False)

    def build(self):
        self.noise()
        self.case_authorized()
        self.case_denied()
        self.case_suspicious()
        self.records.sort(key=lambda x: x["eventTime"])
        return {"Records": self.records}


def write_context(out: str) -> None:
    with open(os.path.join(out, "change_tickets.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ticket", "requested_by", "approved_by", "actor", "action", "target", "policy", "window_start_utc", "window_end_utc"])
        w.writerow(["CHG-2041", "qa.lead", "it.manager", "devon.admin", "AttachUserPolicy", "intern.qa",
                    "arn:aws:iam::aws:policy/ReadOnlyAccess", "2026-10-20T14:00:00Z", "2026-10-20T18:00:00Z"])
    with open(os.path.join(out, "known_networks.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["cidr", "description"])
        w.writerow(["198.51.100.10/31", "Corporate office egress"])
        w.writerow(["10.0.0.0/8", "VPC internal"])
    with open(os.path.join(out, "identities.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["identity", "type", "owner", "purpose", "expected_mfa", "normal_hours_utc"])
        rows = [("devon.admin", "IAMUser", "Devon Price", "Cloud administrator", "yes", "13-23"),
                ("sara.ops", "IAMUser", "Sara Ortiz", "Operations engineer", "yes", "13-23"),
                ("mlee", "IAMUser", "Min Lee", "Developer", "yes", "13-23"),
                ("intern.qa", "IAMUser", "QA intern", "Testing", "yes", "13-22"),
                ("ci-deploy", "IAMUser", "Platform team", "CI pipeline - deploys from build servers only (10.0.0.0/8)", "no", "any"),
                ("DevOpsAutomation", "Role", "Platform team", "Infrastructure automation; can manage IAM users", "n/a", "any"),
                ("WebAppRole", "Role", "Web team", "Application reads corp-app-assets", "n/a", "any"),
                ("SecurityAuditRole", "Role", "Security team", "Daily read-only audit", "n/a", "06")]
        w.writerows(rows)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Generate synthetic CloudTrail events.")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    data = Gen(a.seed).build()
    with open(os.path.join(a.out, "cloudtrail.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=1)
        fh.write("\n")
    write_context(a.out)
    print(f"Wrote {len(data['Records'])} CloudTrail records to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
