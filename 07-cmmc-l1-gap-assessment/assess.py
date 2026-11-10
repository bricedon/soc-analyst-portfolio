#!/usr/bin/env python3
"""
CMMC Level 1 gap assessment (practice tool, standard library only).

Reads the 15 Level 1 security requirements (FAR 52.204-21) and a company's
assessment results, then produces:
  * readiness summary: Met / Partial / Not Met / Not Assessed
  * affirmation decision: at Level 1 EVERY requirement must be Met
    (Level 1 does not allow a POA&M, so "Partial" counts as Not Met)
  * prioritized remediation plan (risk first, quick wins first) with target dates
  * evidence request list for anything not assessed
  * executive summary in Markdown

Usage:
    python assess.py
    python assess.py --hours-per-week 10     # capacity used to schedule target dates

Reference: 32 CFR Part 170 (CMMC Program) and FAR 52.204-21. This tool is for
practice; an official self-assessment follows the DoD CMMC Level 1 Assessment Guide.
"""

from __future__ import annotations

import argparse
import csv
import os
from datetime import date, timedelta
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def read(path: str) -> List[Dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def load(data_dir: str = DATA):
    reqs = {r["id"]: r for r in read(os.path.join(data_dir, "requirements.csv"))}
    results = read(os.path.join(data_dir, "assessment.csv"))
    profile = {r["field"]: r["value"] for r in read(os.path.join(data_dir, "company_profile.csv"))}
    missing = set(reqs) - {r["id"] for r in results}
    for rid in sorted(missing):
        results.append({"id": rid, "status": "Not Assessed", "evidence": "", "gap": "No assessment row",
                        "risk": "Medium", "effort_hours": "1", "owner": "?", "related_lab": ""})
    for r in results:
        r.update({k: reqs[r["id"]][k] for k in ("family", "short_name", "requirement_summary", "nist_800_171")})
    results.sort(key=lambda r: list(reqs).index(r["id"]))
    return reqs, results, profile


def plan(results: List[Dict], start: date, hours_per_week: int) -> List[Dict]:
    gaps = [r for r in results if r["status"] != "Met"]
    # Not Assessed first (we need the facts), then by risk, then quick wins (low effort) first
    gaps.sort(key=lambda r: (r["status"] != "Not Assessed", RISK_ORDER.get(r["risk"], 1), float(r["effort_hours"] or 0)))
    used, items = 0.0, []
    for n, r in enumerate(gaps, start=1):
        used += float(r["effort_hours"] or 0)
        weeks = max(1, -(-int(used) // hours_per_week))        # ceiling division
        items.append({**r, "order": n, "target": (start + timedelta(weeks=weeks)).isoformat(),
                      "quick_win": float(r["effort_hours"] or 0) <= 3})
    return items


def summary(results: List[Dict]) -> Dict[str, int]:
    out = {"Met": 0, "Partial": 0, "Not Met": 0, "Not Assessed": 0}
    for r in results:
        out[r["status"]] = out.get(r["status"], 0) + 1
    return out


def write_report(profile, results, items, counts, out_dir) -> str:
    total = len(results)
    can_affirm = counts["Met"] == total
    done_by = max((i["target"] for i in items), default=profile["assessment_date"])
    lines = [
        f"# CMMC Level 1 Gap Assessment: {profile['company']}", "",
        f"Assessment date: {profile['assessment_date']} · Assessor: {profile['assessor']} · Scope: {profile['contract_data']}", "",
        "## Executive summary", "",
        f"- **{counts['Met']} of {total}** Level 1 requirements are fully met "
        f"({counts['Partial']} partial, {counts['Not Met']} not met, {counts['Not Assessed']} not assessed).",
        f"- **Annual affirmation: {'READY' if can_affirm else 'NOT READY'}.** Level 1 requires all 15 requirements to be met; "
        "a plan of action (POA&M) is **not** allowed at Level 1, so partial items must be closed before affirming.",
        f"- Highest risks: " + "; ".join(f"{i['short_name']} ({i['id']})" for i in items if i["risk"] == "High") + ".",
        f"- With the planned capacity, all gaps can be closed by **{done_by}**, then re-assessed before affirmation.", "",
        "## Results by requirement", "",
        "| ID | Requirement | NIST 800-171 | Status | Gap | Evidence |", "|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r['id']} | {r['short_name']} | {r['nist_800_171']} | **{r['status']}** | {r['gap'] or '-'} | {r['evidence'] or '-'} |")
    lines += ["", "## Remediation plan (ordered)", "",
              "| # | ID | Action needed | Risk | Effort (h) | Quick win | Owner | Target |", "|---|---|---|---|---|---|---|---|"]
    for i in items:
        lines.append(f"| {i['order']} | {i['id']} | {i['gap']} | {i['risk']} | {i['effort_hours']} | "
                     f"{'yes' if i['quick_win'] else ''} | {i['owner']} | {i['target']} |")
    req = [i for i in items if i["status"] == "Not Assessed"]
    if req:
        lines += ["", "## Evidence requests", ""]
        for i in req:
            lines.append(f"- **{i['id']} {i['short_name']}**: provide {i['gap'][len('No evidence received for '):] if i['gap'].startswith('No evidence received for ') else i['gap']} "
                         f"(owner: {i['owner']}).")
    lines += ["", "## Links to the technical labs", ""]
    for r in results:
        if r.get("related_lab"):
            lines.append(f"- {r['id']}: see lab {r['related_lab']}")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "cmmc_l1_gap_report.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "remediation_plan.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["order", "id", "short_name", "status", "gap", "risk", "effort_hours",
                                           "quick_win", "owner", "target"], extrasaction="ignore")
        w.writeheader()
        w.writerows(items)
    return path


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="CMMC Level 1 gap assessment.")
    p.add_argument("--data", default=DATA)
    p.add_argument("--out", default=os.path.join(HERE, "output"))
    p.add_argument("--hours-per-week", type=int, default=8)
    a = p.parse_args(argv)
    reqs, results, profile = load(a.data)
    counts = summary(results)
    items = plan(results, date.fromisoformat(profile["assessment_date"]), a.hours_per_week)
    path = write_report(profile, results, items, counts, a.out)

    print(f"{profile['company']} - CMMC Level 1 practice assessment ({profile['assessment_date']})")
    print("Status: " + " | ".join(f"{k} {v}" for k, v in counts.items()))
    print(f"Annual affirmation: {'READY' if counts['Met'] == len(results) else 'NOT READY (all 15 must be Met; no POA&M at Level 1)'}\n")
    print(f"{'#':>2}  {'ID':<15} {'STATUS':<13} {'RISK':<7} {'HRS':>4}  {'TARGET':<10}  GAP")
    print("-" * 110)
    for i in items:
        print(f"{i['order']:>2}  {i['id']:<15} {i['status']:<13} {i['risk']:<7} {i['effort_hours']:>4}  {i['target']:<10}  {i['gap'][:58]}")
    print(f"\nReport: {os.path.relpath(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
