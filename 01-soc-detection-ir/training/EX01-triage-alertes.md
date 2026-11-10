# Exercice S1-J1 : trier deux alertes et décider de l'escalade

⏱️ **35 à 45 minutes** · Niveau : reproduction guidée → premier jugement d'analyste

## Le scénario
Nous sommes le **mercredi 15 octobre 2026, à 09 h 30 UTC**. Tu es **analyste SOC Tier 1** chez CORP. La règle `BruteForceThenSuccess` a créé deux alertes pendant la nuit et la matinée : **ALERT-001** et **ALERT-002**. Ton responsable veut une décision pour chacune avant 10 h 15.

Tu disposes uniquement de ce qui est dans `data/` :
- `events.jsonl` : journal de sécurité Windows du 14 octobre
- `users.csv` : utilisateurs, service, comptes privilégiés, poste attribué
- `assets.csv` : serveurs, postes, exposition à internet

## Ce que tu dois produire
1. **Pour chaque alerte**, en 5 lignes maximum :
   - Ton verdict : *True positive / Benign true positive / False positive / Undetermined*
   - **Escalader ou clôturer ?** Et pourquoi maintenant.
   - **3 preuves** qui soutiennent ta décision. Chaque preuve doit avoir une heure UTC et un Event ID.
   - **2 preuves qui MANQUENT** : ce que les logs ne te disent pas, et où tu irais les chercher.
2. **Pour ALERT-001**, remplis le modèle `reports/incident-report-template.md`. Enregistre-le sous `reports/INC-0001-<ton-prénom>.md`, en **anglais simple**.
3. **Une phrase** : y a-t-il autre chose de suspect dans ces logs, que la règle n'a pas vu ?

## Critères de réussite
- [ ] Les deux verdicts sont justifiés par des preuves vérifiées par toi-même. Le score de l'outil n'est pas une preuve : c'est un indice.
- [ ] Chaque preuve cite une heure, un Event ID et un champ (IP, LogonType, SubStatus…).
- [ ] Au moins 2 preuves manquantes réalistes par alerte.
- [ ] Des actions de confinement ordonnées par priorité, chacune avec un moyen de **vérifier** qu'elle a marché.
- [ ] Le rapport ALERT-001 est lisible par un manager en 1 minute (section 1).

## Commandes de départ
```powershell
cd 01-soc-detection-ir
python detect.py
python detect.py --timeline ALERT-001
python detect.py --timeline ALERT-002

# Enquête libre dans PowerShell
$ev = Get-Content .\data\events.jsonl | ConvertFrom-Json
$ev | Where-Object IpAddress -eq '203.0.113.45' | Format-Table time, EventCode, TargetUserName, LogonType, SubStatus
$ev | Where-Object { $_.SubjectUserName -eq 'a.morgan' -or $_.TargetUserName -eq 'a.morgan' } | Format-Table time, EventCode, Computer, IpAddress, LogonType
Import-Csv .\data\users.csv | Where-Object username -in 'a.morgan','j.rivera'
```

---

## Indices progressifs (ouvre-les un par un, seulement si tu bloques)

<details><summary>Indice 1 : par où commencer</summary>

Pose-toi trois questions pour chaque alerte : **D'où** vient la connexion (IP interne ou externe ? poste attendu pour cet utilisateur ?) **Qui** est le compte (privilégié ?) **Qu'est-ce qui s'est passé APRÈS** la connexion réussie ?
</details>

<details><summary>Indice 2 : les Event IDs qui comptent</summary>

4625 = échec · 4624 = succès (regarde **LogonType** : 2 = clavier, 3 = réseau, 10 = RDP) · 4672 = privilèges admin à l'ouverture de session · 4720 = compte créé · 4732 = ajout à un groupe · 4723 = l'utilisateur a changé **son propre** mot de passe. Pour `SubStatus` : `0xC000006A` = mauvais mot de passe, `0xC0000064` = l'utilisateur n'existe pas.
</details>

<details><summary>Indice 3 : la vraie Alex Morgan</summary>

Regarde à quelle heure `a.morgan` s'est connectée **depuis son propre poste** ce jour-là, et compare avec 02:19. Qu'est-ce que ça t'apprend, et qu'est-ce que ça ne prouve pas ?
</details>

<details><summary>Indice 4 : ce que la règle ne voit pas</summary>

Groupe tous les 4625 par utilisateur et IP, puis trie-les par nombre :
`$ev | Where-Object EventCode -eq 4625 | Group-Object TargetUserName, IpAddress | Sort-Object Count -Descending | Select-Object -First 6 Count, Name`
Une ligne devrait t'inquiéter. Laquelle, et pourquoi la règle l'a-t-elle ratée ?
</details>

---

**Quand tu as fini :** envoie-moi ton analyse en écrivant **« Entraînement du jour »**, avec ton texte ou ton fichier. Je te noterai sur 5 critères (preuves, raisonnement, priorisation, remédiation, communication). **N'ouvre pas `solutions/` avant.**
