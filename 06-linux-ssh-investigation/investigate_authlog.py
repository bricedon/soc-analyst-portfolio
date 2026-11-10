#!/usr/bin/env python3
"""
Linux auth.log investigation: SSH brute force, suspicious sudo, persistence.

Parses /var/log/auth.log (Debian/Ubuntu syslog format) and raises findings:

  BRUTE_FORCE_SUCCESS  >= 5 failed SSH logins from one IP within 10 minutes, then an
                       accepted login from that IP
  PASSWORD_LOGIN       SSH login with a password from outside the internal network
                       (policy: key-based logins only)
  SUSPICIOUS_SUDO      sudo running downloads, scripts from /tmp, chmod +x, reverse shells...
  UID0_ACCOUNT         a new account created with UID 0 (a second root)
  CRONTAB_CHANGE       root crontab replaced shortly after suspicious activity
  SCANNING             many invalid usernames from one IP (informational)

Usage:
    python investigate_authlog.py
    python investigate_authlog.py --session deploy     # timeline of one user's activity
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
YEAR = 2026     # syslog lines have no year
INTERNAL = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]

LINE = re.compile(r"^(?P<ts>\w{3}\s+\d+ \d\d:\d\d:\d\d) (?P<host>\S+) (?P<prog>[\w\-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
PATTERNS = {
    "failed": re.compile(r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
    "invalid": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "accepted": re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "sudo": re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.*)$"),
    "useradd": re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)"),
    "crontab": re.compile(r"\((?P<user>\S+)\) (?P<action>REPLACE|EDIT|DELETE) \((?P<target>\S+)\)"),
}
SUSPICIOUS_CMD = [
    (r"\b(wget|curl)\b.*https?://", "downloads a file from the internet"),
    (r"(^|\s)/(tmp|dev/shm|var/tmp)/", "uses a file in a world-writable temp folder"),
    (r"chmod \+x", "makes a file executable"),
    (r"\b(nc|ncat|socat)\b.*-e|/dev/tcp/", "reverse shell pattern"),
    (r"base64 (-d|--decode)", "decodes hidden content"),
    (r"\b(useradd|usermod)\b.*-o|-u 0\b", "creates or changes an account to UID 0"),
    (r"history -c|unset HISTFILE", "clears shell history"),
]


def internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in INTERNAL)


def parse(path: str) -> List[Dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            m = LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            ts = datetime.strptime(f"{YEAR} {m['ts']}", "%Y %b %d %H:%M:%S")
            ev = {"time": ts, "prog": m["prog"], "pid": m["pid"], "msg": m["msg"], "raw": raw.rstrip("\n"), "kind": None}
            for kind, pat in PATTERNS.items():
                pm = pat.search(m["msg"])
                if pm and (kind != "sudo" or m["prog"] == "sudo") and (kind != "crontab" or m["prog"] == "crontab") \
                        and (kind != "useradd" or m["prog"] == "useradd"):
                    ev["kind"] = kind
                    ev.update(pm.groupdict())
                    break
            events.append(ev)
    return events


def analyze(events: List[Dict], threshold: int = 5, window_min: int = 10) -> List[Dict]:
    findings = []
    fails_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    invalid_by_ip: Dict[str, set] = defaultdict(set)
    sudo_seen: Dict[str, int] = defaultdict(int)
    last_suspicious = None

    for e in events:
        k = e["kind"]
        if k == "failed":
            fails_by_ip[e["ip"]].append(e)
        elif k == "invalid":
            invalid_by_ip[e["ip"]].add(e["user"])
        elif k == "accepted":
            recent = [f for f in fails_by_ip.get(e["ip"], []) if e["time"] - f["time"] <= timedelta(minutes=30)]
            burst = max((sum(1 for g in recent if timedelta(0) <= g["time"] - f["time"] <= timedelta(minutes=window_min))
                         for f in recent), default=0)
            if burst >= threshold:
                findings.append(F(e, "BRUTE_FORCE_SUCCESS", "Critical",
                                  f'{len(recent)} failed logins from {e["ip"]} then ACCEPTED {e["method"]} for {e["user"]}'))
            if e["method"] == "password" and not internal(e["ip"]):
                findings.append(F(e, "PASSWORD_LOGIN", "High",
                                  f'password login for {e["user"]} from external IP {e["ip"]} (policy: keys only)'))
        elif k == "sudo":
            sudo_seen[e["user"]] += 1
            reasons = [why for pat, why in SUSPICIOUS_CMD if re.search(pat, e["cmd"])]
            if reasons:
                last_suspicious = e["time"]
                findings.append(F(e, "SUSPICIOUS_SUDO", "High",
                                  f'{e["user"]} ran as {e["as"]}: {e["cmd"]}  ({"; ".join(reasons)})'))
        elif k == "useradd" and e["uid"] == "0":
            findings.append(F(e, "UID0_ACCOUNT", "Critical", f'new account {e["user"]} with UID 0 (second root account)'))
        elif k == "crontab" and last_suspicious and e["time"] - last_suspicious <= timedelta(minutes=30):
            findings.append(F(e, "CRONTAB_CHANGE", "High",
                              f'{e["user"]} crontab {e["action"]} {(e["time"] - last_suspicious).seconds // 60} min after suspicious sudo (persistence?)'))

    for ip, users in invalid_by_ip.items():
        if len(users) >= 3:
            first = min(e["time"] for e in events if e["kind"] == "invalid" and e.get("ip") == ip)
            findings.append({"time": first, "type": "SCANNING", "severity": "Info",
                             "detail": f"{ip} tried {len(users)} non-existent usernames: {', '.join(sorted(users))}",
                             "raw": ""})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Info": 3}
    findings.sort(key=lambda f: (f["time"], order[f["severity"]]))
    return findings


def F(e, ftype, sev, detail):
    return {"time": e["time"], "type": ftype, "severity": sev, "detail": detail, "raw": e["raw"]}


def user_timeline(events: List[Dict], user: str) -> List[str]:
    out, ips = [], set()
    for e in events:
        if e.get("user") == user and e["kind"] == "accepted":
            ips.add(e["ip"])
    # session windows: from "Accepted ... for user" to "session closed for user"
    windows, start = [], None
    for e in events:
        if e["kind"] == "accepted" and e.get("user") == user:
            start = e["time"]
        elif start and e["prog"] == "sshd" and f"session closed for user {user}" in e["msg"]:
            windows.append((start, e["time"]))
            start = None
    if start:
        windows.append((start, events[-1]["time"]))
    for e in events:
        in_session = e["prog"] in ("useradd", "usermod", "passwd", "crontab", "groupadd") and \
            any(a <= e["time"] <= b for a, b in windows)
        rel = e.get("user") == user or user in e["msg"] or (e.get("ip") in ips) or in_session
        if rel and e["prog"] != "CRON":
            out.append(e["raw"])
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Investigate a Linux auth.log.")
    p.add_argument("--log", default=os.path.join(HERE, "data", "auth.log"))
    p.add_argument("--session", metavar="USER", help="timeline for one user (and the IPs they logged in from)")
    a = p.parse_args(argv)
    events = parse(a.log)
    if a.session:
        lines = user_timeline(events, a.session)
        print(f"Timeline for {a.session}: {len(lines)} lines\n")
        print("\n".join(lines))
        return 0
    findings = analyze(events)
    kinds = defaultdict(int)
    for e in events:
        kinds[e["kind"] or "other"] += 1
    print(f"Parsed {len(events)} lines: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"Findings: {len(findings)}\n")
    for f in findings:
        print(f'{f["time"]:%b %d %H:%M:%S}  {f["severity"]:<8} {f["type"]:<20} {f["detail"]}')
    os.makedirs(os.path.join(HERE, "output"), exist_ok=True)
    with open(os.path.join(HERE, "output", "findings.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# auth.log findings\n\n| Time | Severity | Type | Detail |\n|---|---|---|---|\n")
        for f in findings:
            fh.write(f'| {f["time"]:%b %d %H:%M:%S} | {f["severity"]} | {f["type"]} | {f["detail"].replace("|", "/")} |\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
