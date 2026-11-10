#!/usr/bin/env python3
"""
Synthetic Windows Security log generator for the SOC Detection & IR Lab.

Creates ONE day (2026-10-14, UTC) of authentication events for a fictional
company "CORP" with realistic background noise and three planted scenarios:

  SCN-A  Malicious   RDP brute force from an external IP against an IT admin,
                     followed by a successful logon, admin privileges (4672),
                     a new account (4720) and its addition to Administrators (4732).
  SCN-B  Benign      A user changes his password (4723); a mapped drive on his own
                     workstation still has the old saved password -> burst of failures,
                     then success once he updates it. The rule fires: a false positive.
  SCN-C  Edge case   "Low and slow" password guessing from an external IP:
                     3 failures every ~25 minutes, then a success. Never 5 failures in
                     10 minutes, so the threshold rule does NOT fire.

Noise: normal workstation / file-server logons, typos followed by success,
a service account with special privileges every hour, a misconfigured scanner
service that fails all day, and internet background scanning of the RDP server.

All names, IPs (RFC 5737 documentation ranges for "external" addresses) and hosts
are fictional. Output is deterministic for a given --seed.

Usage:
    python generate_logs.py                 # writes data/events.jsonl and data/events.csv
    python generate_logs.py --seed 7 --out data
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List

DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)
DOMAIN = "CORP"

FAILURE_REASONS = {
    "0xC000006A": "Unknown user name or bad password (wrong password)",
    "0xC0000064": "Unknown user name or bad password (user does not exist)",
    "0xC0000234": "Account locked out",
}

USERS = [
    # username, full name, department, privileged, assigned workstation
    ("a.morgan", "Alex Morgan", "IT", True, "WKS-0101"),
    ("j.rivera", "Jose Rivera", "Finance", False, "WKS-0117"),
    ("k.chen", "Kelly Chen", "HR", False, "WKS-0122"),
    ("m.ali", "Mohamed Ali", "Operations", False, "WKS-0103"),
    ("s.patel", "Sana Patel", "Finance", False, "WKS-0104"),
    ("d.okafor", "David Okafor", "IT", True, "WKS-0105"),
    ("l.nguyen", "Linh Nguyen", "Operations", False, "WKS-0106"),
    ("r.brown", "Rachel Brown", "Sales", False, "WKS-0107"),
    ("t.wilson", "Tom Wilson", "Sales", False, "WKS-0108"),
    ("p.garcia", "Paula Garcia", "HR", False, "WKS-0109"),
    ("c.kim", "Chris Kim", "Operations", False, "WKS-0110"),
    ("e.martin", "Emma Martin", "Finance", False, "WKS-0111"),
    ("b.johnson", "Ben Johnson", "Operations", False, "WKS-0112"),
    ("n.diallo", "Nadia Diallo", "Sales", False, "WKS-0113"),
    ("g.lopez", "Gabriel Lopez", "Operations", False, "WKS-0114"),
    ("h.schmidt", "Hanna Schmidt", "Legal", False, "WKS-0115"),
    ("i.rossi", "Ivan Rossi", "Operations", False, "WKS-0116"),
    ("f.mensah", "Fatou Mensah", "Finance", False, "WKS-0118"),
    ("o.tanaka", "Omar Tanaka", "Sales", False, "WKS-0119"),
    ("v.silva", "Vera Silva", "Operations", False, "WKS-0120"),
    ("svc-backup", "Backup service", "IT", True, ""),
    ("svc-scanner", "Scan-to-folder service", "IT", False, ""),
]

SERVERS = {
    "SRV-DC01": "10.10.10.5",
    "SRV-FILE01": "10.10.10.15",
    "SRV-RDP01": "10.10.10.30",     # RDP jump host published to the internet
    "SRV-MFP01": "10.10.10.50",     # multifunction printer / scanner
}


def ws_ip(ws: str) -> str:
    """WKS-0117 -> 10.10.20.117"""
    return f"10.10.20.{int(ws[-3:])}"


class Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.events: List[Dict] = []

    def at(self, hour: int, minute: int = 0, second: int = 0) -> datetime:
        return DAY + timedelta(hours=hour, minutes=minute, seconds=second)

    def add(self, ts: datetime, code: int, computer: str, **fields) -> None:
        event = {
            "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventCode": code,
            "Computer": computer,
            "TargetDomainName": DOMAIN,
        }
        event.update(fields)
        self.events.append(event)

    # ---- event helpers (field names follow the Windows Security log) ----
    def logon_ok(self, ts, computer, user, logon_type, ip, ws="-"):
        self.add(ts, 4624, computer, TargetUserName=user, LogonType=logon_type,
                 IpAddress=ip, WorkstationName=ws, Status="0x0", SubStatus="0x0")

    def logon_fail(self, ts, computer, user, logon_type, ip, ws="-", sub="0xC000006A"):
        self.add(ts, 4625, computer, TargetUserName=user, LogonType=logon_type,
                 IpAddress=ip, WorkstationName=ws, Status="0xC000006D", SubStatus=sub,
                 FailureReason=FAILURE_REASONS[sub])

    def special_priv(self, ts, computer, user):
        self.add(ts, 4672, computer, SubjectUserName=user,
                 PrivilegeList="SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege")

    # ---------------------------------------------------------------- noise
    def normal_day(self) -> None:
        r = self.rng
        for user, _, _, _, ws in USERS:
            if not ws:
                continue
            start = self.at(r.randint(7, 9), r.randint(0, 59), r.randint(0, 59))
            # morning interactive logon at own workstation (sometimes a typo first)
            if r.random() < 0.35:
                self.logon_fail(start - timedelta(seconds=r.randint(8, 40)), ws, user, 2, "127.0.0.1", ws)
            self.logon_ok(start, ws, user, 2, "127.0.0.1", ws)
            # mapped drives / file server access during the day
            for _ in range(r.randint(2, 5)):
                t = start + timedelta(minutes=r.randint(5, 9 * 60))
                self.logon_ok(t, "SRV-FILE01", user, 3, ws_ip(ws), ws)
            # unlock after lunch (logon type 7)
            self.logon_ok(start + timedelta(hours=r.randint(4, 5), minutes=r.randint(0, 59)), ws, user, 7, "127.0.0.1", ws)
        # IT admins legitimately use RDP to the jump host from their workstations
        for admin in ("a.morgan", "d.okafor"):
            ws = next(u[4] for u in USERS if u[0] == admin)
            for _ in range(r.randint(1, 3)):
                t = self.at(r.randint(9, 17), r.randint(0, 59), r.randint(0, 59))
                self.logon_ok(t, "SRV-RDP01", admin, 10, ws_ip(ws), ws)
                self.special_priv(t + timedelta(seconds=1), "SRV-RDP01", admin)

    def service_accounts(self) -> None:
        r = self.rng
        for hour in range(24):
            t = self.at(hour, 5, r.randint(0, 59))
            self.logon_ok(t, "SRV-FILE01", "svc-backup", 5, "-", "-")
            self.special_priv(t + timedelta(seconds=1), "SRV-FILE01", "svc-backup")
        # scanner service has a stale password: fails every 30 minutes all day, never succeeds
        t = self.at(0, 2)
        while t < DAY + timedelta(days=1):
            self.logon_fail(t, "SRV-FILE01", "svc-scanner", 3, SERVERS["SRV-MFP01"], "SRV-MFP01")
            t += timedelta(minutes=30, seconds=r.randint(-20, 20))

    def internet_noise(self) -> None:
        """Background scanning of the exposed RDP server: 1-3 guesses per IP, common usernames."""
        r = self.rng
        names = ["administrator", "admin", "user", "test", "guest", "scanner", "backup", "rdp"]
        for _ in range(45):
            ip = f"198.51.100.{r.randint(100, 250)}" if r.random() < 0.5 else f"203.0.113.{r.randint(100, 250)}"
            t = self.at(r.randint(0, 23), r.randint(0, 59), r.randint(0, 59))
            for _ in range(r.randint(1, 3)):
                user = r.choice(names)
                sub = "0xC000006A" if user == "administrator" else "0xC0000064"
                self.logon_fail(t, "SRV-RDP01", user, 3, ip, f"WIN-{r.randint(1000, 9999)}", sub)
                t += timedelta(seconds=r.randint(2, 20))

    # ---------------------------------------------------------------- scenarios
    def scenario_a_malicious(self) -> None:
        """RDP brute force -> success -> privileges -> persistence (new admin account)."""
        r = self.rng
        ip, ws, host = "203.0.113.45", "DESKTOP-7K2Q9P", "SRV-RDP01"
        t = self.at(2, 13, 5)
        # quick username check first (user does not exist), then focus on a real admin
        for name in ("amorgan", "alex.morgan"):
            self.logon_fail(t, host, name, 3, ip, ws, "0xC0000064")
            t += timedelta(seconds=r.randint(6, 14))
        for _ in range(14):
            self.logon_fail(t, host, "a.morgan", 3, ip, ws)
            t += timedelta(seconds=r.randint(18, 35))
        success = t + timedelta(seconds=40)
        self.logon_ok(success, host, "a.morgan", 10, ip, ws)
        self.special_priv(success + timedelta(seconds=1), host, "a.morgan")
        self.add(success + timedelta(minutes=4, seconds=12), 4720, "SRV-DC01",
                 SubjectUserName="a.morgan", TargetUserName="support_tmp", SourceComputer=host)
        self.add(success + timedelta(minutes=4, seconds=50), 4732, "SRV-DC01",
                 SubjectUserName="a.morgan", MemberName="support_tmp", TargetUserName="Administrators",
                 SourceComputer=host)

    def scenario_b_benign(self) -> None:
        """Password change, then a stale saved credential (mapped drive) on the user's own workstation."""
        r = self.rng
        self.add(self.at(8, 52, 31), 4723, "SRV-DC01", SubjectUserName="j.rivera", TargetUserName="j.rivera")
        ws = "WKS-0117"
        t = self.at(9, 1, 10)
        for _ in range(9):
            self.logon_fail(t, "SRV-FILE01", "j.rivera", 3, ws_ip(ws), ws)
            t += timedelta(seconds=r.randint(30, 70))
        self.logon_ok(t + timedelta(minutes=2), "SRV-FILE01", "j.rivera", 3, ws_ip(ws), ws)

    def scenario_c_low_and_slow(self) -> None:
        """3 failures every ~25 minutes for 3.5 hours, then success - stays under 5-in-10-minutes."""
        r = self.rng
        ip, ws, host = "198.51.100.23", "WIN-LPT4471", "SRV-RDP01"
        t = self.at(10, 0, 12)
        for _ in range(9):
            burst = t
            for _ in range(3):
                self.logon_fail(burst, host, "k.chen", 3, ip, ws)
                burst += timedelta(seconds=r.randint(20, 50))
            t += timedelta(minutes=25, seconds=r.randint(-60, 60))
        self.logon_ok(t + timedelta(minutes=3), host, "k.chen", 10, ip, ws)

    def build(self) -> List[Dict]:
        self.normal_day()
        self.service_accounts()
        self.internet_noise()
        self.scenario_a_malicious()
        self.scenario_b_benign()
        self.scenario_c_low_and_slow()
        self.events.sort(key=lambda e: (e["time"], e["EventCode"]))
        for i, e in enumerate(self.events, start=1):
            e["RecordNumber"] = 100000 + i
        return self.events


CSV_FIELDS = ["RecordNumber", "time", "EventCode", "Computer", "TargetUserName", "TargetDomainName",
              "LogonType", "IpAddress", "WorkstationName", "Status", "SubStatus", "FailureReason",
              "SubjectUserName", "MemberName", "PrivilegeList", "SourceComputer"]


def write_outputs(events: List[Dict], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=False) + "\n")
    with open(os.path.join(out_dir, "events.csv"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
    with open(os.path.join(out_dir, "users.csv"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["username", "full_name", "department", "privileged", "assigned_workstation"])
        for row in USERS:
            writer.writerow(row)
    with open(os.path.join(out_dir, "assets.csv"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["hostname", "ip", "role", "internet_exposed", "owner"])
        roles = {"SRV-DC01": "Domain controller", "SRV-FILE01": "File server",
                 "SRV-RDP01": "RDP jump host", "SRV-MFP01": "Printer / scanner"}
        for host, ip in SERVERS.items():
            writer.writerow([host, ip, roles[host], "yes" if host == "SRV-RDP01" else "no", "IT"])
        for user, _, _, _, ws in USERS:
            if ws:
                writer.writerow([ws, ws_ip(ws), "Workstation", "no", user])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic Windows Security events.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    args = parser.parse_args(argv)
    events = Builder(args.seed).build()
    write_outputs(events, args.out)
    counts: Dict[int, int] = {}
    for e in events:
        counts[e["EventCode"]] = counts.get(e["EventCode"], 0) + 1
    print(f"Wrote {len(events)} events to {args.out}")
    print("By EventCode: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
