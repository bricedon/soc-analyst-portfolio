# Corrigé : exercice S5-J1

## Les 3 de la semaine
1. **F02, VPN (7.5) → P1, 72 h.** Dans le KEV depuis le 28/10, EPSS 0.94, utilisée par des ransomwares, exposée à internet, porte d'entrée de tout le personnel à distance. Après le patch : **invalider les sessions VPN et changer les identifiants admin**, car des jetons ont pu être volés avant le patch.
2. **F03, RDP exposé sans MFA (5.3) → P1.** Ce n'est pas une CVE, c'est une erreur de configuration. Mais elle a été **exploitée chez nous** (lab 01, INC-0001 : force brute puis connexion réussie). Correction rapide et peu risquée : supprimer la règle RDP publique et passer par le VPN avec MFA.
3. **F06, navigateur sur 150 postes (8.8) → P1.** Dans le KEV, exploitée par de la publicité malveillante, sur 150 postes qui naviguent tous les jours. Le déploiement est automatisable.

**Ensuite :** F07 SMBv1 (P2, à 74.4 donc juste sous P1). Il faut d'abord vérifier les vieux clients qui en dépendent. Puis F05 (base ERP) : critique, mais segmentée et exige une connexion valide.

## Défendre F02 avant F01
> F01 a le CVSS le plus élevé, mais aucun exploit n'est connu, l'EPSS est de 0.004, le serveur est sur un VLAN isolé et il sera retiré en décembre. F02 est exploitée **aujourd'hui**, n'importe qui sur internet peut l'atteindre, et elle ouvre l'accès à tout le réseau. Le risque, c'est la probabilité multipliée par l'impact : F02 gagne sur les deux. Je garde F01 dans le registre et je **vérifie l'isolation** (revue des règles du pare-feu), parce que tout mon raisonnement repose dessus.

## Ce qui manque au ticket F02
Une fenêtre de maintenance précise et le contact d'astreinte. L'impact pour les utilisateurs : le VPN coupé pendant X minutes, donc prévenir le télétravail. Le numéro exact de version firmware attendu après le patch. L'action « invalider les sessions » écrite comme une étape à part. Et qui valide le rescan.

## Message au responsable (12/11)
> F02 (VPN) and F07 (SMBv1) are fixed and confirmed by the Nov 12 rescan. Two P1 items are overdue: the browser update is on 141 of 150 workstations, with 9 still vulnerable, and the public RDP rule on jump-rdp01 is still open even though we saw an attack through it. I suggest forcing the update on the 9 machines today and removing the RDP rule in tomorrow's change window. The rescan also found a new VPN finding (F11, CVSS 5.9), which I will score and ticket today.

## Points d'excellence
- Tu remarques que l'**isolation** et le **WAF** ne valent que s'ils sont vérifiés.
- Tu proposes une **acceptation du risque** documentée pour F01 si le retrait en décembre est confirmé.
- Tu relies F03 au lab 01 : la gestion des vulnérabilités se nourrit de ce que voit le SOC.
