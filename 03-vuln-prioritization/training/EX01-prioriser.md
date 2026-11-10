# Exercice S5-J1 : prioriser 10 vulnérabilités et défendre ton choix

⏱️ **40 minutes** · Rôles : Vulnerability Management, Security Analyst, GRC

## Scénario
Lundi 2 novembre 2026. Le scan hebdomadaire a trouvé 10 vulnérabilités. L'équipe IT ne peut en traiter que **3 cette semaine**. Ton responsable te demande lesquelles, dans quel ordre, et pourquoi.

## Avant de lancer l'outil (15 min, sans l'outil)
Ouvre seulement `data/assets.csv`, `data/scan_results.csv` et `data/threat_intel.csv` (dans Excel par exemple).
1. Classe **tes** 3 premières vulnérabilités et la dernière, avec une phrase de justification pour chacune.
2. Défends par écrit, en 5 lignes, pourquoi **F02 (CVSS 7.5)** passe avant **F01 (CVSS 9.8)**, ou pourquoi tu n'es pas d'accord.

## Ensuite, avec l'outil (25 min)
```powershell
cd 03-vuln-prioritization
python prioritize.py
python prioritize.py ticket F02
python prioritize.py revalidate data\rescan_2026-11-12.csv
```
3. Compare ton classement à celui de l'outil. Où es-tu en désaccord ? Qui a raison, et pourquoi ?
4. **F03** a un CVSS de 5.3 mais passe en P1 : quelle preuve justifie ça ? (Indice : lab 01.)
5. Lis le ticket F02 : que manque-t-il pour que l'équipe réseau puisse agir sans te rappeler ?
6. Revalidation du 12 novembre : écris le message de 4 lignes à ton responsable (en anglais) sur ce qui est vraiment corrigé, ce qui est en retard et ce qui est nouveau.

## Critères de réussite
- [ ] Ton ordre repose sur l'exploitation, l'exposition et la criticité, pas seulement sur le CVSS.
- [ ] Tu notes que l'isolation de lab-test07 est une **hypothèse à vérifier**.
- [ ] Tu sais que « corrigé » se prouve par un rescan propre.
- [ ] Ton message au responsable chiffre le résiduel (9/150 postes) et propose une action pour chaque retard.

<details><summary>Indice 1</summary>Pour chaque ligne, demande-toi : un attaquant peut-il l'atteindre aujourd'hui ? Est-ce qu'on sait que c'est exploité ? Qu'est-ce qu'on perd si ça tombe ?</details>
<details><summary>Indice 2</summary>KEV = « exploitée dans la nature ». EPSS 0.94 = 94 % de probabilité d'exploitation dans les 30 jours. Un VPN est la porte d'entrée de tout le réseau.</details>

**Envoie ton analyse avec « Entraînement du jour » avant d'ouvrir le corrigé.**
