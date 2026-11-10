# Exercice S3-J1 : enquête IAM dans CloudTrail

⏱️ **40 minutes** · Rôles : Cloud Security, IAM, IR

## Scénario
Le **mardi 21 octobre 2026 à 08:00 UTC**, l'équipe sécurité remarque que le trail `org-trail` est **arrêté**. Tu as reçu l'export CloudTrail de la veille (`data/cloudtrail.json`), les tickets de changement, les réseaux connus et la liste des identités.

## Ce que tu dois produire
Pour **chacune** des 3 situations (le changement autorisé, la tentative refusée, l'action suspecte réussie) :
1. **L'auteur** : l'identité qui appelle ET l'identité d'origine. Explique comment tu remontes la chaîne.
2. **L'identité ciblée**, **l'action**, le **résultat** (succès ou refus).
3. **L'impact** : qu'est-ce que l'attaquant peut faire maintenant ?
4. Ton **verdict** et ta **décision**.

Ensuite :
5. **5 vérifications à faire AVANT de confiner** l'incident critique, ordonnées, avec la raison de chacune.
6. **Le piège** : la tentative refusée de `ci-deploy` est-elle sans danger ? Justifie avec `identities.csv`.
7. Un **résumé manager** de 4 phrases, en anglais.

## Critères de réussite
- [ ] La chaîne complète : ConsoleLogin sans MFA → AssumeRole → CreateUser / AttachUserPolicy / CreateAccessKey → utilisation de la nouvelle clé → StopLogging, avec les heures.
- [ ] Tu distingues « identifiants de mlee » et « Min Lee la personne ». Cite la preuve de 14:05.
- [ ] Tu sais que désactiver le rôle `DevOpsAutomation` peut casser la production, et tu dis comment le vérifier.
- [ ] Tu proposes de rétablir la journalisation **en premier**.

## Commandes
```powershell
cd 02-cloudtrail-iam-investigation
python investigate.py
python investigate.py --actor mlee
python investigate.py --actor ci-deploy
$ct = (Get-Content .\data\cloudtrail.json -Raw | ConvertFrom-Json).Records
$ct | Where-Object eventName -eq 'ConsoleLogin' | Select-Object eventTime, sourceIPAddress, @{n='user';e={$_.userIdentity.userName}}, @{n='mfa';e={$_.additionalEventData.MFAUsed}}
Import-Csv .\data\identities.csv | Format-Table
```

<details><summary>Indice 1</summary>Un appel fait par `assumed-role/DevOpsAutomation/mlee` : cherche l'événement <code>AssumeRole</code> dont la clé temporaire (<code>responseElements.credentials.accessKeyId</code>) est la même que celle de l'appel.</details>
<details><summary>Indice 2</summary>La nouvelle clé de <code>backup-svc2</code> apparaît dans la réponse de <code>CreateAccessKey</code>. Qui a créé cette clé ?</details>
<details><summary>Indice 3</summary>Dans <code>identities.csv</code>, d'où <code>ci-deploy</code> est-il censé fonctionner ? D'où vient l'appel refusé ?</details>

**N'ouvre pas `solutions/` avant d'avoir envoyé ton analyse avec « Entraînement du jour ».**
