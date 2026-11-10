#!/usr/bin/env python3
"""
Synthetic Zeek-style conn log (8 hours, 30 workstations) for the beaconing lab.

Planted patterns
  BEACON   10.10.20.113 -> 203.0.113.99:443   every 60 s (+/- 3 s jitter), ~310 bytes out
  BENIGN   every workstation -> 10.10.10.40:8443   every 300 s (endpoint agent check-in)
  BENIGN   every workstation -> 10.10.10.5:123/udp every 1024 s (NTP time sync)
  EDGE     10.10.20.108 -> 198.51.100.200:443  every ~45 min with 30% jitter, large uploads
Noise: random web browsing to many external destinations during the day.

Usage: python generate_conn.py [--seed 11]
"""

from __future__ import annotations

import argparse
import csv
import os
import random

START = 1792400400.0      # 2026-10-19 08:00:00 UTC (epoch seconds)
HOURS = 8
FIELDS = ["ts", "uid", "src", "src_port", "dst", "dst_port", "proto", "service", "duration", "orig_bytes",
          "resp_bytes", "conn_state"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = p.parse_args(argv)
    r = random.Random(a.seed)
    rows = []
    end = START + HOURS * 3600
    hosts = [f"10.10.20.{n}" for n in range(101, 131)]

    def add(ts, src, dst, port, proto, service, out_b, in_b, dur):
        rows.append({"ts": f"{ts:.3f}", "uid": "C" + "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(15)),
                     "src": src, "src_port": r.randint(49152, 65535), "dst": dst, "dst_port": port, "proto": proto,
                     "service": service, "duration": f"{dur:.3f}", "orig_bytes": out_b, "resp_bytes": in_b,
                     "conn_state": "SF"})

    web = [f"192.0.2.{n}" for n in range(10, 60)] + [f"198.51.100.{n}" for n in range(30, 60)]
    for h in hosts:
        # browsing: bursts of activity at random times
        t = START + r.uniform(0, 1800)
        while t < end:
            for _ in range(r.randint(3, 12)):
                add(t, h, r.choice(web), 443, "tcp", "ssl", r.randint(400, 4000), r.randint(2000, 900000), r.uniform(0.1, 30))
                t += r.uniform(0.5, 40)
            t += r.expovariate(1 / 900)
        # endpoint agent every 300 s
        t = START + r.uniform(0, 300)
        while t < end:
            add(t, h, "10.10.10.40", 8443, "tcp", "ssl", r.randint(900, 1100), r.randint(1500, 2500), r.uniform(0.2, 1))
            t += 300 + r.uniform(-1, 1)
        # NTP every 1024 s
        t = START + r.uniform(0, 1024)
        while t < end:
            add(t, h, "10.10.10.5", 123, "udp", "ntp", 48, 48, 0.01)
            t += 1024

    # BEACON
    t = START + 1200
    while t < end:
        add(t, "10.10.20.113", "203.0.113.99", 443, "tcp", "ssl", r.randint(295, 325), r.randint(160, 200), r.uniform(0.2, 0.6))
        t += 60 + r.uniform(-3, 3)
    # EDGE: slow, jittery, bigger uploads
    t = START + 600
    while t < end:
        add(t, "10.10.20.108", "198.51.100.200", 443, "tcp", "ssl", r.randint(40000, 260000), r.randint(800, 1500), r.uniform(2, 9))
        t += 2700 * r.uniform(0.7, 1.3)

    rows.sort(key=lambda x: float(x["ts"]))
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "conn.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(a.out, "allowlist.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["destination", "port", "reason", "approved_by", "review_date"])
        w.writerow(["10.10.10.40/32", "8443", "Endpoint management agent check-in (every 5 min)", "IT Ops", "2027-04-01"])
        w.writerow(["10.10.10.5/32", "123", "NTP time sync to domain controller", "IT Ops", "2027-04-01"])
    print(f"Wrote {len(rows)} connections to {a.out}/conn.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
