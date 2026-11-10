#!/usr/bin/env python3
"""
Risk-based vulnerability prioritization (local, standard library only).

CVSS tells you how bad a flaw is in theory. This tool ranks findings by how much
risk they create HERE: technical severity + evidence of exploitation + exposure
+ asset criticality - compensating controls. Every score shows its reasons, so a
human can challenge it.

Commands
    python prioritize.py                      # rank findings -> output/remediation_register.csv + .md
    python prioritize.py ticket F02           # remediation ticket for one finding -> output/TICKET-F02.md
    python prioritize.py revalidate data/rescan_2026-11-12.csv   # compare a rescan with the register

Scoring (max 100)
    CVSS base x 4                                   (0-40)
    Exploitation evidence:
        observed against OUR asset                  +30
        in CISA KEV (known exploited)               +30   (not added twice with "observed")
        else public exploit                         +10
        else / and EPSS >= 0.5                      +10   (only if not KEV / observed)
        used by ransomware                          +5
    Exposure: internet +15, internal +5, internal-segmented +2, isolated 0
    Asset criticality (1-5) x 3                     (3-15)
    Compensating control documented                 -10
    Decommission planned                            -5

Priority and remediation SLA (calendar days from detection)
    P1 >= 75  -> 7 days  (and KEV + internet-facing -> 72 hours)
    P2 55-74  -> 30 days
    P3 35-54  -> 90 days
    P4 < 35   -> next maintenance cycle, or documented risk acceptance
"""

from __future__ import annotations

import argparse
import csv
import os
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "output")

EXPOSURE_POINTS = {"internet": 15, "internal": 5, "internal-segmented": 2, "isolated": 0}
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}


def read_csv(path: str) -> List[Dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def yes(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("yes", "true", "1")


def score_finding(f: Dict, asset: Dict, intel: Dict) -> Dict:
    reasons = []
    cvss = float(f["cvss_base"])
    score = cvss * 4
    reasons.append(f"CVSS {cvss} x4 = {score:.1f}")

    observed, kev = yes(intel.get("observed_in_environment")), yes(intel.get("in_kev"))
    epss = float(intel["epss"]) if intel.get("epss") else None
    if observed:
        score += 30
        reasons.append("attack OBSERVED against this asset in our logs +30")
    elif kev:
        score += 30
        reasons.append(f"in CISA KEV since {intel.get('kev_date_added') or '?'} +30")
    else:
        if yes(intel.get("public_exploit")):
            score += 10
            reasons.append("public exploit available +10")
        if epss is not None and epss >= 0.5:
            score += 10
            reasons.append(f"EPSS {epss} >= 0.5 +10")
    if yes(intel.get("ransomware_use")):
        score += 5
        reasons.append("used in ransomware campaigns +5")

    exposure = asset["exposure"]
    pts = EXPOSURE_POINTS.get(exposure, 5)
    score += pts
    reasons.append(f"exposure {exposure} +{pts}")

    crit = int(asset["criticality"])
    score += crit * 3
    reasons.append(f"asset criticality {crit}/5 +{crit * 3}")

    controls = asset.get("compensating_controls", "").strip()
    if controls and controls.lower() != "none":
        score -= 10
        reasons.append(f"compensating control ({controls}) -10")
    if "decommission" in asset.get("notes", "").lower():
        score -= 5
        reasons.append("decommission planned -5")

    score = round(max(0.0, min(100.0, score)), 1)
    priority = "P1" if score >= 75 else "P2" if score >= 55 else "P3" if score >= 35 else "P4"
    detected = datetime.strptime(f["detected"], "%Y-%m-%d").date()
    due = detected + timedelta(days=SLA_DAYS[priority])
    if priority == "P1" and kev and exposure == "internet":
        due = detected + timedelta(days=3)
        reasons.append("KEV + internet-facing: emergency 72h SLA")
    return {
        "finding_id": f["finding_id"], "asset_id": f["asset_id"], "hostname": asset["hostname"],
        "asset_role": asset["role"], "hosts": asset.get("host_count", "1"), "owner": asset["owner"],
        "cve": f["cve"], "title": f["title"], "cvss": cvss, "exposure": exposure, "criticality": crit,
        "kev": "yes" if kev else "no", "epss": "" if epss is None else epss,
        "observed": "yes" if observed else "no", "score": score, "priority": priority,
        "detected": f["detected"], "due": due.isoformat(), "fix": f["fix"], "reasons": reasons,
    }


def build_register(data_dir: str = DATA) -> List[Dict]:
    assets = {a["asset_id"]: a for a in read_csv(os.path.join(data_dir, "assets.csv"))}
    intel = {i["cve"]: i for i in read_csv(os.path.join(data_dir, "threat_intel.csv"))}
    rows = [score_finding(f, assets[f["asset_id"]], intel.get(f["cve"], {}))
            for f in read_csv(os.path.join(data_dir, "scan_results.csv"))]
    rows.sort(key=lambda r: (-r["score"], -r["cvss"]))
    for rank, r in enumerate(rows, start=1):
        r["rank"] = rank
    return rows


# --------------------------------------------------------------------------- outputs

REGISTER_FIELDS = ["rank", "finding_id", "priority", "score", "cvss", "cve", "title", "hostname", "asset_role",
                   "hosts", "exposure", "criticality", "kev", "epss", "observed", "owner", "detected", "due", "fix"]


def write_register(rows: List[Dict], out_dir: str = OUT) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "remediation_register.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REGISTER_FIELDS + ["status"], extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({**r, "status": "Open"})
    lines = ["# Remediation register", "",
             "| # | Finding | Priority | Score | CVSS | Asset | Exposure | KEV | Due | Owner |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f'| {r["rank"]} | {r["finding_id"]} {r["title"]} | **{r["priority"]}** | {r["score"]} | {r["cvss"]} | '
                     f'{r["hostname"]} | {r["exposure"]} | {r["kev"]} | {r["due"]} | {r["owner"]} |')
    lines += ["", "## Why each score"]
    for r in rows:
        lines.append(f'- **{r["finding_id"]}** ({r["priority"]}, {r["score"]}): ' + "; ".join(r["reasons"]))
    with open(os.path.join(out_dir, "remediation_register.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def print_register(rows: List[Dict]) -> None:
    print(f"{'#':>2}  {'ID':<4} {'PRI':<3} {'SCORE':>5} {'CVSS':>4}  {'HOST':<14} {'EXPOSURE':<19} {'KEV':<4} {'DUE':<10}  TITLE")
    print("-" * 120)
    for r in rows:
        print(f'{r["rank"]:>2}  {r["finding_id"]:<4} {r["priority"]:<3} {r["score"]:>5} {r["cvss"]:>4}  '
              f'{r["hostname"]:<14} {r["exposure"]:<19} {r["kev"]:<4} {r["due"]:<10}  {r["title"][:52]}')


def make_ticket(row: Dict) -> str:
    return f"""# {row['priority']} remediation ticket: {row['finding_id']} - {row['title']}

| Field | Value |
|---|---|
| Asset | {row['hostname']} ({row['asset_role']}), {row['hosts']} host(s) |
| Owner / assignee | {row['owner']} |
| Vulnerability | {row['cve']} - CVSS {row['cvss']} |
| Risk score / priority | {row['score']} / **{row['priority']}** (rank #{row['rank']}) |
| Detected | {row['detected']} |
| **Due date (SLA)** | **{row['due']}** |

## Why this priority
{chr(10).join('- ' + r for r in row['reasons'])}

## Required action
{row['fix']}

## Change plan
1. Schedule the change (emergency change if the SLA is 72 hours) and notify users of the expected impact.
2. Take a backup / configuration snapshot of {row['hostname']} before the change.
3. Apply the fix.
4. Test the service works (functional check by {row['owner']}).

## Rollback
Restore the snapshot / previous version if the service fails the functional check, then escalate to the security team the same day. Rolling back reopens the risk.

## Definition of done (validation evidence)
- [ ] Rescan of {row['hostname']} no longer reports {row['cve']} (attach the rescan export)
- [ ] Version / configuration check output attached
- [ ] For credential-related fixes: credentials rotated and old sessions invalidated
- [ ] Register status changed to "Closed - verified"
"""


def revalidate(register: List[Dict], rescan_path: str, today: str) -> List[Dict]:
    rescan = {r["finding_id"]: r for r in read_csv(rescan_path)}
    today_d = date.fromisoformat(today)
    results = []
    for r in register:
        found = rescan.get(r["finding_id"])
        overdue = today_d > date.fromisoformat(r["due"])
        if not found:
            status = "Closed - verified by rescan"
        else:
            remaining = int(found.get("affected_hosts") or 1)
            total = int(r["hosts"] or 1)
            if remaining < total:
                status = f"Partially remediated ({remaining}/{total} hosts still vulnerable)"
            else:
                status = "Still open"
            if overdue:
                status += " - OVERDUE"
        results.append({"finding_id": r["finding_id"], "priority": r["priority"], "hostname": r["hostname"],
                        "title": r["title"], "due": r["due"], "status": status})
    known = {r["finding_id"] for r in register}
    for fid, f in rescan.items():
        if fid not in known:
            results.append({"finding_id": fid, "priority": "?", "hostname": f["asset_id"], "title": f["title"],
                            "due": "-", "status": "NEW finding - triage and score it"})
    return results


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Risk-based vulnerability prioritization.")
    p.add_argument("--data", default=DATA)
    p.add_argument("--out", default=OUT)
    sub = p.add_subparsers(dest="cmd")
    t = sub.add_parser("ticket", help="write a remediation ticket for one finding")
    t.add_argument("finding_id")
    v = sub.add_parser("revalidate", help="compare a rescan CSV with the register")
    v.add_argument("rescan")
    v.add_argument("--today", default=None, help="date of the check (default: rescan date in file name or today)")
    a = p.parse_args(argv)

    rows = build_register(a.data)
    if a.cmd == "ticket":
        row = next((r for r in rows if r["finding_id"].upper() == a.finding_id.upper()), None)
        if not row:
            print(f"Unknown finding {a.finding_id}")
            return 1
        os.makedirs(a.out, exist_ok=True)
        path = os.path.join(a.out, f"TICKET-{row['finding_id']}.md")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(make_ticket(row))
        print(make_ticket(row))
        print(f"Saved {os.path.relpath(path)}")
        return 0
    if a.cmd == "revalidate":
        today = a.today
        if not today:
            base = os.path.basename(a.rescan)
            digits = base.replace("rescan_", "").replace(".csv", "")
            today = digits if len(digits) == 10 else date.today().isoformat()
        results = revalidate(rows, a.rescan, today)
        print(f"Revalidation on {today} against {os.path.basename(a.rescan)}\n")
        print(f"{'ID':<4} {'PRI':<3} {'HOST':<14} {'DUE':<10}  STATUS")
        print("-" * 96)
        for r in results:
            print(f'{r["finding_id"]:<4} {r["priority"]:<3} {r["hostname"]:<14} {r["due"]:<10}  {r["status"]}')
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, f"revalidation_{today}.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(results[0].keys()))
            w.writeheader()
            w.writerows(results)
        return 0

    write_register(rows, a.out)
    print_register(rows)
    print("\nWrote output/remediation_register.csv and .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
