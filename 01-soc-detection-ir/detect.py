#!/usr/bin/env python3
"""
Detection: brute force followed by a successful logon (Windows Security log).

Rule (default values, all tunable on the command line):
    5 or more failed logons (4625) for the SAME user from the SAME source IP
    within 10 minutes, followed by a successful logon (4624) for that user
    from that IP within 30 minutes after the last failure.

MITRE ATT&CK: T1110.001 Brute Force: Password Guessing -> T1078 Valid Accounts.

Every alert is enriched with context an analyst would look up by hand
(user role, asset exposure, internal vs external IP, recent password change,
activity after the logon) and given a rule-based risk score. The score is a
TRIAGE AID - the analyst still makes the decision.

Usage:
    python detect.py                          # run on data/events.jsonl, write output/
    python detect.py --timeline ALERT-001     # print the timeline of one alert
    python detect.py --threshold 3 --window 60   # tuning experiment
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# --------------------------------------------------------------------------- loading

def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def load_events(path: str) -> List[Dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} line {line_no}: invalid JSON ({exc})") from exc
            e["_t"] = parse_time(e["time"])
            events.append(e)
    events.sort(key=lambda e: e["_t"])
    return events


def load_csv(path: str, key: str) -> Dict[str, Dict]:
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8", newline="") as fh:
        return {row[key].lower(): row for row in csv.DictReader(fh)}


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # "-" or local logons
    return addr.is_loopback or any(addr in net for net in RFC1918)


# --------------------------------------------------------------------------- alert model

@dataclass
class Alert:
    alert_id: str
    rule: str
    user: str
    src_ip: str
    target_host: str
    first_failure: str
    last_failure: str
    failure_count: int
    max_failures_in_window: int
    success_time: str
    success_logon_type: int
    src_workstation_name: str
    context: Dict = field(default_factory=dict)
    score: int = 0
    severity: str = ""
    score_reasons: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- detection

def find_bursts(times: List[datetime], threshold: int, window: timedelta) -> List[tuple]:
    """Group failures that are at most `window` apart; keep groups where some
    `window`-long interval contains >= threshold failures.
    Returns (start_index, end_index, max_in_window)."""
    bursts = []
    i = 0
    while i < len(times):
        j = i
        while j + 1 < len(times) and times[j + 1] - times[j] <= window:
            j += 1
        # max failures inside any sliding window within times[i..j]
        best, left = 0, i
        for right in range(i, j + 1):
            while times[right] - times[left] > window:
                left += 1
            best = max(best, right - left + 1)
        if best >= threshold:
            bursts.append((i, j, best))
        i = j + 1
    return bursts


def detect(events: List[Dict], threshold: int = 5, window_min: int = 10, success_within_min: int = 30) -> List[Alert]:
    window = timedelta(minutes=window_min)
    success_within = timedelta(minutes=success_within_min)

    failures: Dict[tuple, List[Dict]] = defaultdict(list)
    successes: Dict[tuple, List[Dict]] = defaultdict(list)
    for e in events:
        if e["EventCode"] == 4625:
            failures[(e["TargetUserName"].lower(), e["IpAddress"])].append(e)
        elif e["EventCode"] == 4624:
            successes[(e["TargetUserName"].lower(), e["IpAddress"])].append(e)

    alerts: List[Alert] = []
    for key, fails in failures.items():
        times = [f["_t"] for f in fails]
        for start, end, best in find_bursts(times, threshold, window):
            last = times[end]
            success = next((s for s in successes.get(key, [])
                            if last < s["_t"] <= last + success_within), None)
            if success is None:
                continue
            alerts.append(Alert(
                alert_id="",
                rule=f"BruteForceThenSuccess (>= {threshold} fails / {window_min} min, success within {success_within_min} min)",
                user=fails[start]["TargetUserName"],
                src_ip=key[1],
                target_host=success["Computer"],
                first_failure=fails[start]["time"],
                last_failure=fails[end]["time"],
                failure_count=end - start + 1,
                max_failures_in_window=best,
                success_time=success["time"],
                success_logon_type=success.get("LogonType", 0),
                src_workstation_name=success.get("WorkstationName", "-"),
            ))
    alerts.sort(key=lambda a: a.success_time)
    for n, a in enumerate(alerts, start=1):
        a.alert_id = f"ALERT-{n:03d}"
    return alerts


# --------------------------------------------------------------------------- enrichment + scoring

def enrich(alerts: List[Alert], events: List[Dict], users: Dict[str, Dict], assets: Dict[str, Dict]) -> None:
    for a in alerts:
        user_l = a.user.lower()
        success_t = parse_time(a.success_time)
        first_fail_t = parse_time(a.first_failure)
        info = users.get(user_l, {})
        target = assets.get(a.target_host.lower(), {})
        assigned_ws = info.get("assigned_workstation", "")
        assigned_ip = assets.get(assigned_ws.lower(), {}).get("ip", "") if assigned_ws else ""

        after = [e for e in events if success_t <= e["_t"] <= success_t + timedelta(minutes=60)]
        before = [e for e in events if first_fail_t - timedelta(hours=2) <= e["_t"] < first_fail_t]
        same_ip_fails = [e for e in events if e["EventCode"] == 4625 and e.get("IpAddress") == a.src_ip]

        ctx = {
            "src_ip_internal": is_internal(a.src_ip),
            "user_known": bool(info),
            "user_department": info.get("department", "unknown"),
            "user_privileged": info.get("privileged", "False") == "True",
            "user_assigned_workstation": assigned_ws or "-",
            "src_is_users_workstation": bool(assigned_ws) and (
                a.src_workstation_name.upper() == assigned_ws.upper() or a.src_ip == assigned_ip),
            "target_role": target.get("role", "unknown"),
            "target_internet_exposed": target.get("internet_exposed", "no") == "yes",
            "password_changed_2h_before": any(
                e["EventCode"] in (4723, 4724) and e.get("TargetUserName", "").lower() == user_l for e in before),
            "special_privileges_after": any(
                e["EventCode"] == 4672 and e.get("SubjectUserName", "").lower() == user_l
                and e["Computer"] == a.target_host for e in after),
            "account_changes_after": [
                f'{e["EventCode"]} {e.get("TargetUserName", "")} {e.get("MemberName", "")}'.strip()
                for e in after if e["EventCode"] in (4720, 4722, 4724, 4728, 4732, 4756)
                and e.get("SubjectUserName", "").lower() == user_l],
            "other_usernames_tried_from_ip": sorted({
                e["TargetUserName"] for e in same_ip_fails if e["TargetUserName"].lower() != user_l}),
        }
        a.context = ctx

        score, reasons = 40, ["base: brute force followed by success (+40)"]

        def adj(points: int, why: str):
            nonlocal score
            score += points
            reasons.append(f"{why} ({points:+d})")

        if not ctx["src_ip_internal"]:
            adj(20, "source IP is external")
        if ctx["target_internet_exposed"]:
            adj(5, "target host is internet-exposed")
        if ctx["user_privileged"]:
            adj(15, "account is privileged")
        if ctx["special_privileges_after"]:
            adj(5, "special privileges assigned at logon (4672)")
        if ctx["account_changes_after"]:
            adj(20, "account created / group membership changed after logon")
        if ctx["other_usernames_tried_from_ip"]:
            adj(5, "same IP tried other usernames")
        if ctx["password_changed_2h_before"]:
            adj(-20, "user changed own password shortly before (stale credential pattern)")
        if ctx["src_is_users_workstation"]:
            adj(-15, "source is the user's assigned workstation")
        a.score = max(0, min(100, score))
        a.severity = "High" if a.score >= 80 else "Medium" if a.score >= 50 else "Low"
        a.score_reasons = reasons


# --------------------------------------------------------------------------- timeline

def timeline(alert: Alert, events: List[Dict]) -> List[Dict]:
    """Events about the alert's user or source IP, 15 min before the first failure to
    60 min after the success, plus password changes in the 2 hours before."""
    start = parse_time(alert.first_failure) - timedelta(minutes=15)
    end = parse_time(alert.success_time) + timedelta(minutes=60)
    user_l = alert.user.lower()
    rows = []
    for e in events:
        involved = (e.get("TargetUserName", "").lower() == user_l
                    or e.get("SubjectUserName", "").lower() == user_l
                    or e.get("IpAddress") == alert.src_ip)
        if not involved:
            continue
        pw_change = e["EventCode"] in (4723, 4724) and start - timedelta(hours=2) <= e["_t"] < start
        if start <= e["_t"] <= end or pw_change:
            rows.append(e)
    return rows


DESCRIPTIONS = {
    4624: "Logon success", 4625: "Logon FAILED", 4672: "Special privileges assigned",
    4720: "User account CREATED", 4723: "User changed own password", 4724: "Password reset by admin",
    4732: "Member ADDED to local/domain group",
}


def format_event(e: Dict) -> str:
    code = e["EventCode"]
    desc = DESCRIPTIONS.get(code, str(code))
    if code in (4624, 4625):
        detail = f'user={e["TargetUserName"]} src={e["IpAddress"]} ws={e["WorkstationName"]} type={e["LogonType"]}'
        if code == 4625:
            detail += f' sub={e["SubStatus"]}'
    elif code == 4672:
        detail = f'user={e["SubjectUserName"]}'
    elif code == 4732:
        detail = f'by={e["SubjectUserName"]} member={e["MemberName"]} group={e["TargetUserName"]}'
    else:
        detail = f'by={e.get("SubjectUserName", "-")} target={e.get("TargetUserName", "-")}'
    return f'{e["time"]}  {code}  {e["Computer"]:<11} {desc:<32} {detail}'


def compress(lines: List[str]) -> List[str]:
    """Collapse runs of identical 4625 lines (except timestamp) to keep timelines readable."""
    out, i = [], 0
    while i < len(lines):
        j = i
        key = lines[i][21:]
        while j + 1 < len(lines) and lines[j + 1][21:] == key and " 4625 " in lines[i][:30]:
            j += 1
        if j - i >= 2:
            out.append(lines[i])
            out.append(f"{'':21}...  {j - i - 1} more identical failures  ...")
            out.append(lines[j])
        else:
            out.extend(lines[i:j + 1])
        i = j + 1
    return out


# --------------------------------------------------------------------------- output

def write_outputs(alerts: List[Alert], events: List[Dict], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "alerts.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump([asdict(a) for a in alerts], fh, indent=2)
    lines = ["# Detection results", "",
             f"Rule: {alerts[0].rule if alerts else 'n/a'}", "",
             "| Alert | Severity | Score | User | Source IP | Target | Failures | Success at |",
             "|---|---|---|---|---|---|---|---|"]
    for a in alerts:
        lines.append(f"| {a.alert_id} | {a.severity} | {a.score} | {a.user} | {a.src_ip} | {a.target_host} | "
                     f"{a.failure_count} | {a.success_time} |")
    for a in alerts:
        lines += ["", f"## {a.alert_id} - {a.user} from {a.src_ip}", "", "Score breakdown:"]
        lines += [f"- {r}" for r in a.score_reasons]
        lines += ["", "Timeline:", "", "```text"]
        lines += compress([format_event(e) for e in timeline(a, events)])
        lines += ["```"]
    with open(os.path.join(out_dir, "alerts.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def print_summary(alerts: List[Alert], total_events: int, total_failures: int) -> None:
    print(f"Analyzed {total_events} events ({total_failures} failed logons). Alerts: {len(alerts)}\n")
    if not alerts:
        return
    print(f"{'ALERT':<10} {'SEV':<7} {'SCORE':>5}  {'USER':<10} {'SOURCE IP':<15} {'TARGET':<11} {'FAILS':>5}  SUCCESS AT")
    print("-" * 92)
    for a in alerts:
        print(f"{a.alert_id:<10} {a.severity:<7} {a.score:>5}  {a.user:<10} {a.src_ip:<15} {a.target_host:<11} "
              f"{a.failure_count:>5}  {a.success_time}")
    print()
    for a in alerts:
        print(f"{a.alert_id}: " + "; ".join(a.score_reasons[1:]) if len(a.score_reasons) > 1 else f"{a.alert_id}: base score only")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Brute force -> success detection on Windows Security events.")
    p.add_argument("--events", default=os.path.join(HERE, "data", "events.jsonl"))
    p.add_argument("--users", default=os.path.join(HERE, "data", "users.csv"))
    p.add_argument("--assets", default=os.path.join(HERE, "data", "assets.csv"))
    p.add_argument("--out", default=os.path.join(HERE, "output"))
    p.add_argument("--threshold", type=int, default=5, help="failures needed inside the window (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--success-within", type=int, default=30, help="minutes after last failure (default 30)")
    p.add_argument("--timeline", metavar="ALERT_ID", help="print the timeline of one alert")
    args = p.parse_args(argv)

    events = load_events(args.events)
    alerts = detect(events, args.threshold, args.window, args.success_within)
    enrich(alerts, events, load_csv(args.users, "username"), load_csv(args.assets, "hostname"))

    if args.timeline:
        match = next((a for a in alerts if a.alert_id.upper() == args.timeline.upper()), None)
        if not match:
            print(f"{args.timeline} not found. Alerts: {', '.join(a.alert_id for a in alerts) or 'none'}")
            return 1
        print(f"Timeline for {match.alert_id} ({match.user} from {match.src_ip})\n")
        print("\n".join(compress([format_event(e) for e in timeline(match, events)])))
        return 0

    write_outputs(alerts, events, args.out)
    print_summary(alerts, len(events), sum(1 for e in events if e["EventCode"] == 4625))
    print(f"\nWrote {os.path.relpath(os.path.join(args.out, 'alerts.json'))} and alerts.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
