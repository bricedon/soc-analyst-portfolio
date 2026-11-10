# Detection results

Rule: BruteForceThenSuccess (>= 5 fails / 10 min, success within 30 min)

| Alert | Severity | Score | User | Source IP | Target | Failures | Success at |
|---|---|---|---|---|---|---|---|
| ALERT-001 | High | 100 | a.morgan | 203.0.113.45 | SRV-RDP01 | 14 | 2026-10-14T02:19:58Z |
| ALERT-002 | Low | 5 | j.rivera | 10.10.20.117 | SRV-FILE01 | 9 | 2026-10-14T09:11:22Z |

## ALERT-001 - a.morgan from 203.0.113.45

Score breakdown:
- base: brute force followed by success (+40)
- source IP is external (+20)
- target host is internet-exposed (+5)
- account is privileged (+15)
- special privileges assigned at logon (4672) (+5)
- account created / group membership changed after logon (+20)
- same IP tried other usernames (+5)

Timeline:

```text
2026-10-14T02:13:05Z  4625  SRV-RDP01   Logon FAILED                     user=amorgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC0000064
2026-10-14T02:13:14Z  4625  SRV-RDP01   Logon FAILED                     user=alex.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC0000064
2026-10-14T02:13:24Z  4625  SRV-RDP01   Logon FAILED                     user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC000006A
                     ...  12 more identical failures  ...
2026-10-14T02:18:46Z  4625  SRV-RDP01   Logon FAILED                     user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=3 sub=0xC000006A
2026-10-14T02:19:58Z  4624  SRV-RDP01   Logon success                    user=a.morgan src=203.0.113.45 ws=DESKTOP-7K2Q9P type=10
2026-10-14T02:19:59Z  4672  SRV-RDP01   Special privileges assigned      user=a.morgan
2026-10-14T02:24:10Z  4720  SRV-DC01    User account CREATED             by=a.morgan target=support_tmp
2026-10-14T02:24:48Z  4732  SRV-DC01    Member ADDED to local/domain group by=a.morgan member=support_tmp group=Administrators
```

## ALERT-002 - j.rivera from 10.10.20.117

Score breakdown:
- base: brute force followed by success (+40)
- user changed own password shortly before (stale credential pattern) (-20)
- source is the user's assigned workstation (-15)

Timeline:

```text
2026-10-14T08:52:31Z  4723  SRV-DC01    User changed own password        by=j.rivera target=j.rivera
2026-10-14T09:01:10Z  4625  SRV-FILE01  Logon FAILED                     user=j.rivera src=10.10.20.117 ws=WKS-0117 type=3 sub=0xC000006A
                     ...  7 more identical failures  ...
2026-10-14T09:08:24Z  4625  SRV-FILE01  Logon FAILED                     user=j.rivera src=10.10.20.117 ws=WKS-0117 type=3 sub=0xC000006A
2026-10-14T09:11:22Z  4624  SRV-FILE01  Logon success                    user=j.rivera src=10.10.20.117 ws=WKS-0117 type=3
```
