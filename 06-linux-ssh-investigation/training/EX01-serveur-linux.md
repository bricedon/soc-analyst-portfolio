# Exercice : un serveur Linux compromis

⏱️ **35 minutes** · Rôles : SOC, IR, sécurité Linux

## Scénario
Le serveur web `web01` a un comportement étrange depuis cette nuit. L'équipe te donne `data/auth.log` et te demande : « Est-ce qu'on a été piratés ? Si oui, comment, et qu'est-ce qu'on fait ? »

## À faire
1. **À la main d'abord** (PowerShell `Select-String`, ou `grep` si tu as WSL ou Git Bash) :
   ```powershell
   Select-String -Path .\data\auth.log -Pattern "Accepted"
   Select-String -Path .\data\auth.log -Pattern "COMMAND="
   Select-String -Path .\data\auth.log -Pattern "new user|crontab"
   ```
   Quelles connexions ont réussi ? Laquelle est anormale, et pourquoi (méthode, IP, heure) ?
2. Reconstitue la **chronologie** de l'attaque en 6 à 8 lignes (heure + action + ce que ça signifie).
3. La ligne `ansible ... /tmp/ansible-tmp/nginx.conf` est signalée. Vrai ou faux positif ? Comment ajusterais-tu la règle **sans la rendre aveugle** ?
4. **Nettoyer ou reconstruire** le serveur ? Défends ton choix en 3 phrases.
5. Explique en anglais simple à un manager ce qui s'est passé (4 phrases).

## Critères de réussite
- [ ] Tu repères : connexion par **mot de passe**, depuis une IP **externe**, après **26 échecs**, sur un compte de service.
- [ ] Tu identifies la persistance : le compte UID 0 **et** la crontab de root.
- [ ] Tu proposes une exception étroite pour Ansible (utilisateur + IP source + chemin précis), pas « ignorer /tmp ».
