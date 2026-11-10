#!/usr/bin/env python3
"""
Endpoint detection on process creation events (Sysmon Event ID 1), local and tested.

Rules
  OFFICE_SPAWNS_SHELL   Word / Excel / PowerPoint / Outlook starts cmd, PowerShell, wscript, mshta...
  ENCODED_POWERSHELL    powershell.exe / pwsh.exe with -enc / -EncodedCommand (the command is DECODED for the analyst)
  LOLBIN_DOWNLOAD       certutil -urlcache, bitsadmin /transfer, regsvr32 /i:http, mshta http...
  RUN_FROM_USER_PATH    a program started from Users\\Public, AppData\\Local\\Temp or Downloads
  SCHEDULED_TASK        schtasks /create (persistence)
  RENAMED_BINARY        OriginalFileName is a known Windows tool but the file name is different

Allowlist (data/allowlist.json): narrow exceptions (rule + parent + user + decoded content),
each with an owner and a review date. Suppressed alerts are still shown as "suppressed".

Usage:
    python detect_process.py
    python detect_process.py --tree WKS-0113     # process tree for one host
    python detect_process.py --no-allowlist
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))

OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe")
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
KNOWN_TOOLS = {"powershell.exe": "powershell.exe", "cmd.exe": "cmd.exe", "certutil.exe": "certutil.exe",
               "rundll32.exe": "rundll32.exe", "mshta.exe": "mshta.exe", "regsvr32.exe": "regsvr32.exe",
               "psexec.c": "psexec.exe", "wscript.exe": "wscript.exe"}
LOLBIN = [(r"certutil(\.exe)?\"?\s.*-urlcache.*https?://", "certutil downloads a file"),
          (r"bitsadmin(\.exe)?\s.*/transfer", "bitsadmin downloads a file"),
          (r"regsvr32(\.exe)?\s.*/i:https?://", "regsvr32 loads a remote scriptlet"),
          (r"mshta(\.exe)?\s+https?://", "mshta runs a remote HTA")]
USER_PATHS = re.compile(r"\\users\\(public|[^\\]+\\(appdata\\local\\temp|downloads))\\", re.IGNORECASE)
ENC_FLAG = re.compile(r"\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


def base(path: str) -> str:
    return path.replace('"', "").split("\\")[-1].lower()


def decode_ps(cmdline: str) -> Optional[str]:
    m = ENC_FLAG.search(cmdline)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(2)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return "<could not decode>"


def load(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def suppressed(alert: Dict, ev: Dict, allow: List[Dict]) -> Optional[str]:
    for a in allow:
        if (a["rule"] == alert["rule"] and ev["ParentImage"].lower() == a["parent_image"].lower()
                and ev["User"].lower() == a["user"].lower()
                and a["decoded_must_contain"].lower() in (alert.get("decoded") or "").lower()):
            return f'{a["reason"]} (owner {a["owner"]}, review {a["review_date"]})'
    return None


def detect(events: List[Dict], allow: List[Dict]) -> List[Dict]:
    alerts = []

    def raise_(rule, sev, ev, why, decoded=None):
        a = {"time": ev["UtcTime"], "host": ev["Computer"].split(".")[0], "user": ev["User"], "rule": rule,
             "severity": sev, "process": ev["Image"], "parent": ev["ParentImage"], "why": why,
             "command_line": ev["CommandLine"], "decoded": decoded, "guid": ev["ProcessGuid"]}
        a["suppressed"] = suppressed(a, ev, allow)
        alerts.append(a)

    for ev in events:
        img, parent, cmd = base(ev["Image"]), base(ev["ParentImage"]), ev["CommandLine"]
        original = (ev.get("OriginalFileName") or "").lower()
        if parent in OFFICE and img in SHELLS:
            raise_("OFFICE_SPAWNS_SHELL", "High", ev, f"{parent} started {img}")
        if img in ("powershell.exe", "pwsh.exe"):
            decoded = decode_ps(cmd)
            if decoded:
                raise_("ENCODED_POWERSHELL", "High", ev, "encoded PowerShell command", decoded)
        for pat, why in LOLBIN:
            if re.search(pat, cmd, re.IGNORECASE):
                raise_("LOLBIN_DOWNLOAD", "High", ev, why)
        if USER_PATHS.search(ev["Image"]):
            raise_("RUN_FROM_USER_PATH", "Medium", ev, f"executable started from a user-writable folder: {ev['Image']}")
        if img == "schtasks.exe" and re.search(r"/create", cmd, re.IGNORECASE):
            raise_("SCHEDULED_TASK", "Medium", ev, "scheduled task created (persistence)")
        if original in KNOWN_TOOLS and img != KNOWN_TOOLS[original]:
            raise_("RENAMED_BINARY", "High", ev, f"file is {img} but OriginalFileName is {ev['OriginalFileName']}",
                   decode_ps(cmd) if original == "powershell.exe" else None)
    return alerts


def tree(events: List[Dict], host: str) -> List[str]:
    evs = [e for e in events if e["Computer"].split(".")[0].upper() == host.upper()]
    by_parent = defaultdict(list)
    guids = {e["ProcessGuid"] for e in evs}
    for e in evs:
        by_parent[e["ParentProcessGuid"]].append(e)
    lines = []

    def walk(e, depth):
        cmd = e["CommandLine"]
        lines.append(f'{"   " * depth}{"\\_ " if depth else ""}{e["UtcTime"][11:19]}  {base(e["Image"])}  '
                     f'[{e["User"]}]  {cmd[:90] + ("..." if len(cmd) > 90 else "")}')
        for child in by_parent.get(e["ProcessGuid"], []):
            walk(child, depth + 1)

    for e in evs:
        if e["ParentProcessGuid"] not in guids:
            walk(e, 0)
    return lines


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Detect suspicious process creation (Sysmon EID 1).")
    p.add_argument("--events", default=os.path.join(HERE, "data", "sysmon_process_creation.jsonl"))
    p.add_argument("--allowlist", default=os.path.join(HERE, "data", "allowlist.json"))
    p.add_argument("--no-allowlist", action="store_true")
    p.add_argument("--tree", metavar="HOST")
    a = p.parse_args(argv)
    events = load(a.events)
    if a.tree:
        print(f"Process tree for {a.tree}\n")
        print("\n".join(tree(events, a.tree)))
        return 0
    allow = [] if a.no_allowlist else json.load(open(a.allowlist, encoding="utf-8"))
    alerts = detect(events, allow)
    active = [x for x in alerts if not x["suppressed"]]
    print(f"{len(events)} process events | {len(alerts)} rule hits | {len(active)} active alerts | "
          f"{len(alerts) - len(active)} suppressed by allowlist\n")
    print(f"{'TIME (UTC)':<23} {'HOST':<9} {'SEV':<7} {'RULE':<20} DETAIL")
    print("-" * 110)
    for x in alerts:
        tag = "  [suppressed]" if x["suppressed"] else ""
        print(f'{x["time"]:<23} {x["host"]:<9} {x["severity"]:<7} {x["rule"]:<20} {x["why"]}{tag}')
        if x["decoded"] and not x["suppressed"]:
            print(f'{"":>41}decoded: {x["decoded"]}')
    os.makedirs(os.path.join(HERE, "output"), exist_ok=True)
    with open(os.path.join(HERE, "output", "alerts.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(alerts, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
