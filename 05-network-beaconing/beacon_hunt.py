#!/usr/bin/env python3
"""
C2 beaconing hunt on connection logs (Zeek conn.log style, CSV).

Malware that has infected a computer usually "calls home" to its command-and-control
(C2) server on a schedule: every N seconds, with a little random jitter and small,
similar-sized requests. Humans browsing the web do not look like that.

For every (source, destination, port) pair the tool measures:
    regularity of the time between connections   (coefficient of variation, CV)
    regularity of the bytes sent                  (CV of orig_bytes)
    number of connections and duration covered
    prevalence: how many internal hosts talk to the same destination
                (a destination used by the whole company is rarely C2)
and produces a ranked list of beacon candidates with reasons.

Usage:
    python generate_conn.py            # synthetic 8-hour conn log -> data/conn.csv
    python beacon_hunt.py              # ranked candidates
    python beacon_hunt.py --show 10.10.20.113 203.0.113.99    # inter-arrival detail of one pair
    python beacon_hunt.py --no-allowlist                       # see what the allowlist hides
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import statistics
from collections import defaultdict
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in n for n in RFC1918)


def load_conn(path: str) -> List[Dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["ts"] = float(r["ts"])
        r["orig_bytes"] = int(r["orig_bytes"])
        r["resp_bytes"] = int(r["resp_bytes"])
    rows.sort(key=lambda r: r["ts"])
    return rows


def load_allowlist(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def allowed(dst: str, port: str, allow: List[Dict]) -> str:
    for a in allow:
        if ipaddress.ip_address(dst) in ipaddress.ip_network(a["destination"], strict=False) and a["port"] in ("*", port):
            return a["reason"]
    return ""


def cv(values: List[float]) -> float:
    if len(values) < 2:
        return 9.99
    mean = statistics.mean(values)
    return statistics.pstdev(values) / mean if mean else 9.99


def hunt(rows: List[Dict], allow: List[Dict], min_conns: int = 8) -> List[Dict]:
    pairs: Dict[tuple, List[Dict]] = defaultdict(list)
    prevalence: Dict[tuple, set] = defaultdict(set)
    for r in rows:
        pairs[(r["src"], r["dst"], r["dst_port"])].append(r)
        prevalence[(r["dst"], r["dst_port"])].add(r["src"])

    out = []
    for (src, dst, port), conns in pairs.items():
        if len(conns) < min_conns:
            continue
        times = [c["ts"] for c in conns]
        gaps = [b - a for a, b in zip(times, times[1:])]
        interval_cv = cv(gaps)
        bytes_cv = cv([c["orig_bytes"] for c in conns])
        span_h = (times[-1] - times[0]) / 3600
        prev = len(prevalence[(dst, port)])
        reasons, score = [], 0.0

        regularity = max(0.0, 1 - min(interval_cv, 1.0))
        score += regularity * 45
        reasons.append(f"interval CV {interval_cv:.2f} (+{regularity * 45:.0f})")
        size_reg = max(0.0, 1 - min(bytes_cv, 1.0))
        score += size_reg * 15
        reasons.append(f"bytes CV {bytes_cv:.2f} (+{size_reg * 15:.0f})")
        if span_h >= 4:
            score += 10
            reasons.append(f"active over {span_h:.1f} h (+10)")
        if not internal(dst):
            score += 20
            reasons.append("external destination (+20)")
        if prev >= 5:
            score -= 35
            reasons.append(f"{prev} internal hosts use this destination (-35)")
        elif prev == 1:
            score += 10
            reasons.append("only this host talks to it (+10)")
        out_b = sum(c["orig_bytes"] for c in conns)
        in_b = sum(c["resp_bytes"] for c in conns) or 1
        if out_b / in_b >= 10:
            score += 5
            reasons.append(f"upload-heavy: {out_b // 1024} KB out vs {in_b // 1024} KB in (+5, possible exfiltration)")
        why_allowed = allowed(dst, port, allow)
        if why_allowed:
            reasons.append(f"ALLOWLISTED: {why_allowed}")
        score = round(max(0.0, min(100.0, score)), 1)
        out.append({
            "src": src, "dst": dst, "port": port, "connections": len(conns),
            "median_interval_s": round(statistics.median(gaps), 1), "interval_cv": round(interval_cv, 3),
            "avg_bytes_out": round(statistics.mean(c["orig_bytes"] for c in conns)),
            "total_bytes_in": sum(c["resp_bytes"] for c in conns),
            "span_hours": round(span_h, 1), "prevalence": prev, "score": score,
            "verdict": ("allowlisted" if why_allowed else
                        "LIKELY BEACON" if score >= 70 else "investigate" if score >= 45 else "low"),
            "reasons": reasons,
        })
    out.sort(key=lambda x: -x["score"])
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Hunt for C2 beaconing in conn logs.")
    p.add_argument("--conn", default=os.path.join(HERE, "data", "conn.csv"))
    p.add_argument("--allowlist", default=os.path.join(HERE, "data", "allowlist.csv"))
    p.add_argument("--no-allowlist", action="store_true")
    p.add_argument("--min-conns", type=int, default=8)
    p.add_argument("--top", type=int, default=8)
    p.add_argument("--show", nargs=2, metavar=("SRC", "DST"))
    a = p.parse_args(argv)

    rows = load_conn(a.conn)
    if a.show:
        sel = [r for r in rows if r["src"] == a.show[0] and r["dst"] == a.show[1]]
        print(f"{len(sel)} connections {a.show[0]} -> {a.show[1]}\n")
        prev = None
        for r in sel[:25]:
            gap = "" if prev is None else f"+{r['ts'] - prev:7.1f}s"
            print(f"ts={r['ts']:.1f}  {gap:>10}  port={r['dst_port']}  out={r['orig_bytes']:>6}  in={r['resp_bytes']:>7}")
            prev = r["ts"]
        if len(sel) > 25:
            print(f"... {len(sel) - 25} more")
        return 0

    allow = [] if a.no_allowlist else load_allowlist(a.allowlist)
    results = hunt(rows, allow, a.min_conns)
    print(f"{len(rows)} connections, {len({r['src'] for r in rows})} internal hosts, "
          f"{len(results)} pairs with >= {a.min_conns} connections\n")
    print(f"{'SCORE':>5}  {'VERDICT':<13} {'SRC':<14} {'DST':<15} {'PORT':<5} {'CONNS':>5} {'MEDIAN GAP':>10} {'CV':>5} {'HOSTS':>5}")
    print("-" * 92)
    for r in results[:a.top]:
        print(f"{r['score']:>5}  {r['verdict']:<13} {r['src']:<14} {r['dst']:<15} {r['port']:<5} {r['connections']:>5} "
              f"{r['median_interval_s']:>9}s {r['interval_cv']:>5} {r['prevalence']:>5}")
    print()
    for r in results[:3]:
        print(f"{r['src']} -> {r['dst']}:{r['port']}  " + "; ".join(r["reasons"]))
    os.makedirs(os.path.join(HERE, "output"), exist_ok=True)
    with open(os.path.join(HERE, "output", "beacon_candidates.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[k for k in results[0] if k != "reasons"] + ["reasons"])
        w.writeheader()
        for r in results:
            w.writerow({**r, "reasons": " | ".join(r["reasons"])})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
