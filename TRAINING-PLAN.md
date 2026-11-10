# Parcours d'entraînement : 6 semaines, 30 à 45 minutes par jour

Chaque jour : un exercice, une **preuve** à produire (fichier, capture ou commit), puis l'entraînement à l'oral en anglais.
Progression sur chaque bloc de 2 semaines : **reproduire** → **enquêter sans indices** → **améliorer la détection ou le process**.

Quand tu reviens, écris **« Entraînement du jour »**. Je pars du dernier exercice validé, je te donne le scénario et les critères, j'attends ton analyse, puis je note sur 5 critères (preuves, raisonnement, priorisation, remédiation, communication) et je termine par une question d'entretien en anglais.

| Jour | Exercice | Rôle visé | Preuve à produire |
|---|---|---|---|
| **Semaine 1 : SOC Lab, reproduire et trier** | | | |
| S1-J1 | Trier ALERT-001 et ALERT-002, escalader ou clôturer ([EX01](01-soc-detection-ir/training/EX01-triage-alertes.md)) | SOC | Rapport `INC-0001-brice.md` |
| S1-J2 | Refaire la démo sur Windows, puis expliquer à voix haute chaque Event ID et chaque LogonType | SOC | Capture + enregistrement vocal de 2 min en anglais |
| S1-J3 | Lire `detect.py` et expliquer la fenêtre glissante (`find_bursts`) avec tes mots | Detection Eng | 10 lignes de commentaires en français |
| S1-J4 | Changer le seuil (3, 5, 8) et la fenêtre : combien d'alertes ? Quel compromis ? | Detection Eng | Tableau des résultats + recommandation |
| S1-J5 | Installer Splunk Free, importer `events.jsonl`, valider les requêtes Q1 à Q6 | SOC | Captures Splunk + corrections dans `queries.spl` |
| **Semaine 2 : SOC Lab, enquêter et améliorer** | | | |
| S2-J1 | Nouvelle journée générée (seed secret) : enquête **sans indices** | SOC / IR | Rapport d'incident complet |
| S2-J2 | Chasse : trouver `k.chen` et écrire une règle « low and slow » | Threat Hunting | Nouvelle règle + test unitaire |
| S2-J3 | Réduire le faux positif ALERT-002 sans perdre ALERT-001 | Detection Eng | PR / commit + tests verts |
| S2-J4 | Écrire le plan de confinement d'ALERT-001 avec les étapes de vérification | IR | Checklist confinement |
| S2-J5 | Simulation d'entretien : présenter le lab en 3 min, puis 5 questions | Tous | Note /10 + points à travailler |
| **Semaine 3 : CloudTrail & IAM, reproduire** | | | |
| S3-J1 | Lire des événements CloudTrail : qui, quoi, où, résultat (`errorCode`) | Cloud Security | Fiche « champs CloudTrail » |
| S3-J2 | Distinguer le changement autorisé, la tentative refusée et l'escalade réussie | Cloud / IAM | Tableau des 3 cas |
| S3-J3 | Identifier l'auteur réel derrière un rôle assumé (`AssumeRole`, `sourceIdentity`) | IAM | Chaîne d'identité dessinée |
| S3-J4 | Évaluer l'impact d'une politique IAM ajoutée (actions, ressources) | IAM | Analyse de la politique |
| S3-J5 | Requêtes locales en Python ou PowerShell, plus l'équivalent CloudTrail Lake / Athena (SQL) | Cloud Security | Requêtes + résultats |
| **Semaine 4 : CloudTrail & IAM, enquêter et décider** | | | |
| S4-J1 | Enquête sans indices sur un nouveau jeu de données | Cloud IR | Rapport d'incident |
| S4-J2 | Vérifications avant confinement : que casse-t-on si on révoque ? | Cloud IR | Liste des vérifications + décision |
| S4-J3 | Écrire une détection : `AttachUserPolicy` / `PutUserPolicy` hors processus de changement | Detection Eng | Règle + test |
| S4-J4 | Revue des accès IAM (moindre privilège) sur un inventaire fictif | IAM / GRC | Rapport de revue des accès |
| S4-J5 | Simulation d'entretien Cloud Security / IAM | Cloud / IAM | Note /10 |
| **Semaine 5 : Vulnérabilités, prioriser** | | | |
| S5-J1 | Lire un résultat de scan : CVSS, vecteur, actif touché | Vuln Mgmt | Fiche par vulnérabilité |
| S5-J2 | Ajouter l'exposition, la criticité de l'actif et les indices d'exploitation (KEV, EPSS) | Vuln Mgmt | Score de priorité justifié |
| S5-J3 | Défendre le cas où un CVSS plus bas passe en premier | Security Analyst | Argument écrit + oral (2 min) |
| S5-J4 | Écrire un ticket de remédiation exploitable pour l'équipe IT | Vuln Mgmt | Ticket complet |
| S5-J5 | Prouver la correction : revalidation avant / après | Vuln Mgmt | Preuve de revalidation |
| **Semaine 6 : Vulnérabilités, GRC et synthèse** | | | |
| S6-J1 | Enquête sans indices : nouveau scan, nouvel inventaire | Vuln Mgmt | Registre de remédiation |
| S6-J2 | Exception et risque accepté : quand on ne peut pas corriger | GRC | Formulaire d'acceptation du risque |
| S6-J3 | Relier les résultats à un contrôle (NIST 800-53 / CMMC) | GRC / Compliance | Mapping contrôle → preuve |
| S6-J4 | Préparer les lignes de CV et les STAR avec **tes** résultats réels | Tous | `CAREER.md` complété |
| S6-J5 | Simulation d'entretien finale : les 3 labs en 10 minutes | Tous | Note finale + plan de suite |
