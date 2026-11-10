# Exercice : chasser le C2 dans 10 000 connexions

⏱️ **40 minutes** · Rôles : Threat Hunting, SOC, Network Security

## Scénario
Une alerte threat intel dit qu'un groupe criminel utilise des malwares qui « appellent la maison » toutes les minutes. Aucune alerte n'a sonné chez nous. Tu as 8 heures de logs de connexions (`data/conn.csv`).

## À faire
1. **Sans l'outil :** dans PowerShell, compte les connexions par destination externe, puis repère une destination contactée par **un seul** poste mais très souvent.
   ```powershell
   $c = Import-Csv .\data\conn.csv
   $c | Where-Object { $_.dst -notlike '10.*' } | Group-Object src, dst | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
   ```
2. Lance `python beacon_hunt.py` et explique **avec tes mots** ce qu'est le coefficient de variation et pourquoi il est bas pour un beacon.
3. Pourquoi l'agent `10.10.10.40:8443` n'est-il **pas** un C2, alors qu'il est encore plus régulier ? Donne 2 raisons.
4. Le cas `10.10.20.108 → 198.51.100.200` : beacon, exfiltration, ou sauvegarde cloud légitime ? Quelles **3 preuves supplémentaires** demandes-tu avant de décider ?
5. Rédige l'escalade (5 lignes, en anglais) pour `10.10.20.113`.

## Critères de réussite
- [ ] Tu cites les chiffres (462 connexions, ~60 s, CV 0.03, 1 hôte, IP externe).
- [ ] Tu sais qu'une régularité parfaite n'est pas une preuve : il faut la combiner avec la prévalence, le propriétaire et la liste blanche.
- [ ] Pour 10.10.20.108, tu demandes le processus (EDR), le domaine (DNS / certificat TLS) et l'avis du propriétaire du poste avant de décider.
