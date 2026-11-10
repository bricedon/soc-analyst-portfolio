#!/usr/bin/env python3
"""
CloudTrail IAM investigation tool (local, no AWS account needed).

Finds every sensitive IAM / logging change in a CloudTrail file and answers the
questions an analyst must answer before containment:

    WHO did it (resolving assumed roles back to the human or key behind them)?
    WHAT action, on WHICH identity, with WHAT impact?
    Did it SUCCEED or was it denied?
    Was it AUTHORIZED (matching change ticket) or not?
    Which RISK FACTORS apply (no MFA, unknown IP, off-hours, admin policy, logging tampered)?

Usage:
    python investigate.py                       # findings + incidents, writes output/
    python investigate.py --actor mlee          # full activity timeline for one identity (incl. its role sessions)
    python investigate.py --file other.json     # any CloudTrail file with {"Records": [...]}
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from collections import OrderedDict
from datetime import datetime
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))

# Sensitive actions and what they mean for an attacker.
SENSITIVE = {
    "CreateUser": "New IAM identity (possible persistence)",
    "CreateAccessKey": "New long-term credential (persistence / exfiltration of access)",
    "CreateLoginProfile": "Console password set on a user (persistence)",
    "UpdateLoginProfile": "Console password changed (account takeover)",
    "AttachUserPolicy": "Permissions granted to a user",
    "AttachRolePolicy": "Permissions granted to a role",
    "AttachGroupPolicy": "Permissions granted to a group",
    "PutUserPolicy": "Inline permissions written on a user",
    "PutRolePolicy": "Inline permissions written on a role",
    "AddUserToGroup": "User added to a group (inherits its permissions)",
    "CreatePolicyVersion": "Policy rewritten (can silently escalate everyone using it)",
    "UpdateAssumeRolePolicy": "Role trust changed (who can assume the role)",
    "DeactivateMFADevice": "MFA removed",
    "StopLogging": "CloudTrail logging STOPPED (defense evasion)",
    "DeleteTrail": "CloudTrail trail DELETED (defense evasion)",
    "UpdateTrail": "CloudTrail trail modified",
    "PutEventSelectors": "CloudTrail event selection changed",
}

POLICY_IMPACT = {
    "AdministratorAccess": "FULL control of every AWS service and resource",
    "IAMFullAccess": "Can create users and grant itself any permission (equivalent to admin)",
    "PowerUserAccess": "Full access except IAM management",
    "ReadOnlyAccess": "Read-only access to all services (can still read sensitive data)",
    "SecurityAudit": "Read-only security configuration",
}


# --------------------------------------------------------------------------- loading

def load_records(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    records = data["Records"] if isinstance(data, dict) else data
    records.sort(key=lambda r: r["eventTime"])
    return records


def load_csv(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- identity resolution

class Identities:
    """Resolves 'who is really behind this call'."""

    def __init__(self, records: List[Dict]):
        self.role_key_origin: Dict[str, Dict] = {}     # temp key from AssumeRole -> caller
        self.created_keys: Dict[str, Dict] = {}         # access key id -> creation record
        self.console_mfa: Dict[str, Dict] = {}          # user -> last ConsoleLogin record (by time)
        for r in records:
            name = r["eventName"]
            if name == "AssumeRole" and not r.get("errorCode"):
                key = ((r.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId")
                if key:
                    self.role_key_origin[key] = r
            if name == "CreateAccessKey" and not r.get("errorCode"):
                ak = (r.get("responseElements") or {}).get("accessKey") or {}
                if ak.get("accessKeyId"):
                    self.created_keys[ak["accessKeyId"]] = r

    @staticmethod
    def short(ident: Dict) -> str:
        t = ident.get("type")
        if t == "IAMUser":
            return ident.get("userName", "?")
        if t == "AssumedRole":
            return ident["arn"].split("assumed-role/")[-1]           # Role/session
        if t == "Root":
            return "ROOT"
        if t == "AWSService":
            return ident.get("invokedBy", "AWS service")
        return ident.get("arn", "?")

    def chain(self, ident: Dict) -> List[str]:
        """List of hops from the calling identity back to its origin."""
        hops = [self.short(ident)]
        key = ident.get("accessKeyId", "")
        if ident.get("type") == "AssumedRole":
            origin = self.role_key_origin.get(key)
            src = (ident.get("sessionContext") or {}).get("sourceIdentity")
            if origin:
                hops.append(f'assumed by {self.short(origin["userIdentity"])} at {origin["eventTime"]} from {origin["sourceIPAddress"]}')
            elif src:
                hops.append(f"sourceIdentity={src}")
        if key in self.created_keys:
            c = self.created_keys[key]
            hops.append(f'key {key} created at {c["eventTime"]} by {self.short(c["userIdentity"])}')
        return hops

    def human_origin(self, ident: Dict) -> str:
        if ident.get("type") == "AssumedRole":
            origin = self.role_key_origin.get(ident.get("accessKeyId", ""))
            if origin:
                return self.human_origin(origin["userIdentity"])
            src = (ident.get("sessionContext") or {}).get("sourceIdentity")
            if src:
                return src
        key = ident.get("accessKeyId", "")
        if key in self.created_keys:
            return self.human_origin(self.created_keys[key]["userIdentity"])
        return self.short(ident)


def mfa_used(record: Dict) -> Optional[bool]:
    if record["eventName"] == "ConsoleLogin":
        return (record.get("additionalEventData") or {}).get("MFAUsed") == "Yes"
    attrs = ((record["userIdentity"].get("sessionContext") or {}).get("attributes") or {})
    if "mfaAuthenticated" in attrs:
        return attrs["mfaAuthenticated"] == "true"
    return None   # long-term access key: MFA not applicable / unknown


# --------------------------------------------------------------------------- analysis

def in_networks(ip: str, networks: List[Dict]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True   # AWS service hostnames such as "lambda.amazonaws.com"
    return any(addr in ipaddress.ip_network(n["cidr"], strict=False) for n in networks)


def match_ticket(record: Dict, actor: str, tickets: List[Dict]) -> Optional[str]:
    params = record.get("requestParameters") or {}
    target = params.get("userName") or params.get("roleName") or params.get("groupName") or ""
    t = parse_time(record["eventTime"])
    for tk in tickets:
        if (tk["actor"] == actor and tk["action"] == record["eventName"] and tk["target"] == target
                and (not tk.get("policy") or tk["policy"] == params.get("policyArn"))
                and parse_time(tk["window_start_utc"]) <= t <= parse_time(tk["window_end_utc"])):
            return tk["ticket"]
    return None


def outside_hours(record: Dict, origin: str, identities: Dict[str, Dict]) -> bool:
    info = identities.get(origin)
    if not info or info["normal_hours_utc"] in ("any", ""):
        return False
    hour = parse_time(record["eventTime"]).hour
    parts = info["normal_hours_utc"].split("-")
    start, end = int(parts[0]), int(parts[-1])
    return not (start <= hour <= end)


def analyze(records: List[Dict], tickets: List[Dict], networks: List[Dict], identities: Dict[str, Dict]) -> List[Dict]:
    ids = Identities(records)
    findings = []
    login_mfa: Dict[str, bool] = {}
    for r in records:
        if r["eventName"] == "ConsoleLogin":
            login_mfa[r["userIdentity"].get("userName", "")] = mfa_used(r)
        if r["eventName"] not in SENSITIVE:
            continue
        ident = r["userIdentity"]
        actor = ids.short(ident)
        origin = ids.human_origin(ident)
        params = r.get("requestParameters") or {}
        policy = (params.get("policyArn") or "").split("/")[-1]
        target = (params.get("userName") or params.get("roleName") or params.get("groupName")
                  or str(params.get("name", "-")).split("/")[-1])
        denied = bool(r.get("errorCode"))
        ticket = None if denied else match_ticket(r, actor, tickets)
        mfa = mfa_used(r)
        if mfa is None and origin in login_mfa:
            mfa = login_mfa[origin]

        risks = []
        if not in_networks(r["sourceIPAddress"], networks):
            risks.append(f'source IP {r["sourceIPAddress"]} not in known networks')
        if mfa is False:
            risks.append("no MFA in the session chain")
        if policy in ("AdministratorAccess", "IAMFullAccess"):
            risks.append(f"grants {policy}")
        if r["eventName"] in ("StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail"):
            risks.append("audit logging tampered")
        if outside_hours(r, origin, identities):
            risks.append("outside the owner's normal hours")
        if any(f["action"] == "CreateUser" and f["target"] == actor and not f["denied"] for f in findings):
            risks.append(f"actor {actor} was created today")
        if len(ids.chain(ident)) > 1 and ident.get("accessKeyId") in ids.created_keys:
            risks.append("uses an access key created today")

        if denied:
            verdict, severity = "BLOCKED ATTEMPT", "Medium" if risks else "Low"
        elif ticket and not risks:
            verdict, severity = f"AUTHORIZED ({ticket})", "Info"
        else:
            verdict = "SUSPICIOUS"
            severity = "Critical" if len(risks) >= 3 else "High" if risks else "Medium"

        findings.append(OrderedDict(
            time=r["eventTime"], action=r["eventName"], actor=actor, origin=origin,
            chain=ids.chain(ident), target=target, policy=policy or "-",
            impact=POLICY_IMPACT.get(policy, SENSITIVE[r["eventName"]]),
            source_ip=r["sourceIPAddress"], error=r.get("errorCode", ""), denied=denied,
            ticket=ticket or "", risks=risks, verdict=verdict, severity=severity, event_id=r["eventID"],
        ))
    return findings


def group_incidents(findings: List[Dict]) -> List[Dict]:
    """One incident per (human origin, source IP) for non-authorized findings."""
    incidents: "OrderedDict[tuple, Dict]" = OrderedDict()
    for f in findings:
        if f["verdict"].startswith("AUTHORIZED"):
            continue
        key = (f["origin"], f["source_ip"])
        inc = incidents.setdefault(key, {"origin": f["origin"], "source_ip": f["source_ip"], "findings": []})
        inc["findings"].append(f)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out = []
    for n, inc in enumerate(incidents.values(), start=1):
        sev = min((f["severity"] for f in inc["findings"]), key=lambda s: order.get(s, 9))
        succeeded = [f for f in inc["findings"] if not f["denied"]]
        inc.update(incident_id=f"IAM-INC-{n:02d}", severity=sev,
                   first=inc["findings"][0]["time"], last=inc["findings"][-1]["time"],
                   outcome="Actions SUCCEEDED" if succeeded else "All attempts DENIED",
                   identities_touched=sorted({f["target"] for f in succeeded if f["target"] != "-"}))
        out.append(inc)
    out.sort(key=lambda i: order.get(i["severity"], 9))
    return out


PRE_CONTAINMENT_CHECKS = [
    "Confirm with the identity owner OUT-OF-BAND (phone / manager), not through the possibly compromised account.",
    "List every credential involved: access keys (aws iam list-access-keys), console passwords, active role sessions.",
    "Check what else the attacker identities touched (all CloudTrail events by those keys and IPs, all regions).",
    "Check the business impact of disabling: is the role/user used by production pipelines or applications?",
    "Look for other persistence: new users, new keys, changed role trust policies, new policy versions, Lambda/EC2 created.",
    "If logging was stopped: re-enable it FIRST and check other evidence (organization trail, S3 access logs, GuardDuty).",
    "Preserve evidence (export CloudTrail records) before deleting anything.",
]


# --------------------------------------------------------------------------- output

def actor_timeline(records: List[Dict], name: str) -> List[str]:
    ids = Identities(records)
    rows = []
    for r in records:
        ident = r["userIdentity"]
        if name.lower() not in (ids.short(ident).lower(), ids.human_origin(ident).lower()) \
                and name.lower() not in ids.short(ident).lower():
            continue
        status = r.get("errorCode") or "OK"
        params = r.get("requestParameters") or {}
        detail = ", ".join(f"{k}={v}" for k, v in params.items() if k in ("userName", "policyArn", "roleArn", "name", "bucketName"))
        mfa = mfa_used(r)
        rows.append(f'{r["eventTime"]}  {ids.short(ident):<28} {r["eventName"]:<24} {status:<12} '
                    f'{r["sourceIPAddress"]:<15} mfa={"-" if mfa is None else mfa}  {detail}')
    return rows


def write_outputs(findings, incidents, out_dir) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"findings": findings, "incidents": incidents}, fh, indent=2)
    lines = ["# CloudTrail IAM findings", "",
             "| Time (UTC) | Action | Actor | Credential origin | Target | Policy | Result | Verdict | Severity |",
             "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        lines.append(f'| {f["time"]} | {f["action"]} | {f["actor"]} | {f["origin"]} | {f["target"]} | {f["policy"]} | '
                     f'{f["error"] or "Success"} | {f["verdict"]} | {f["severity"]} |')
    for inc in incidents:
        lines += ["", f'## {inc["incident_id"]} - {inc["severity"]} - origin {inc["origin"]} from {inc["source_ip"]}',
                  "", f'{inc["outcome"]}. Window {inc["first"]} -> {inc["last"]}.', ""]
        for f in inc["findings"]:
            lines.append(f'- `{f["time"]}` **{f["action"]}** on `{f["target"]}` - {f["impact"]}. '
                         f'Risks: {"; ".join(f["risks"]) or "none"}. Chain: {" <- ".join(f["chain"])}')
        if inc["outcome"].startswith("Actions"):
            lines += ["", "Checks before containment:"] + [f"- [ ] {c}" for c in PRE_CONTAINMENT_CHECKS]
    with open(os.path.join(out_dir, "findings.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def print_report(records, findings, incidents) -> None:
    print(f"Analyzed {len(records)} CloudTrail records. Sensitive IAM/logging actions: {len(findings)}\n")
    print(f"{'TIME (UTC)':<21} {'ACTION':<17} {'ACTOR':<23} {'CRED ORIGIN':<12} {'TARGET':<12} {'RESULT':<13} VERDICT")
    print("-" * 118)
    for f in findings:
        print(f'{f["time"]:<21} {f["action"]:<17} {f["actor"][:23]:<23} {f["origin"][:12]:<12} {f["target"][:12]:<12} '
              f'{(f["error"] or "Success"):<13} {f["verdict"]} [{f["severity"]}]')
    print("\nINCIDENTS")
    for inc in incidents:
        print(f'\n{inc["incident_id"]}  {inc["severity"]}  origin={inc["origin"]}  ip={inc["source_ip"]}  {inc["outcome"]}')
        for f in inc["findings"]:
            print(f'   {f["time"]}  {f["action"]:<17} {f["target"]:<12} {f["impact"]}')
            if f["risks"]:
                print(f'      risks: {"; ".join(f["risks"])}')
        if inc["identities_touched"]:
            print(f'   identities changed: {", ".join(inc["identities_touched"])}')


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Investigate IAM changes in CloudTrail (local).")
    p.add_argument("--file", default=os.path.join(HERE, "data", "cloudtrail.json"))
    p.add_argument("--data", default=os.path.join(HERE, "data"), help="folder with change_tickets.csv, known_networks.csv, identities.csv")
    p.add_argument("--out", default=os.path.join(HERE, "output"))
    p.add_argument("--actor", help="print the timeline of one identity (user, role or session)")
    a = p.parse_args(argv)

    records = load_records(a.file)
    if a.actor:
        rows = actor_timeline(records, a.actor)
        print(f"Timeline for '{a.actor}' ({len(rows)} events)\n")
        print("\n".join(rows) if rows else "No events.")
        return 0
    tickets = load_csv(os.path.join(a.data, "change_tickets.csv"))
    networks = load_csv(os.path.join(a.data, "known_networks.csv"))
    identities = {row["identity"]: row for row in load_csv(os.path.join(a.data, "identities.csv"))}
    findings = analyze(records, tickets, networks, identities)
    incidents = group_incidents(findings)
    write_outputs(findings, incidents, a.out)
    print_report(records, findings, incidents)
    print(f"\nWrote output/findings.md and output/findings.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
