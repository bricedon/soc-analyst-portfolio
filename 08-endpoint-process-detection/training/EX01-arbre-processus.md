# Exercice : lire un arbre de processus et régler une règle

⏱️ **40 minutes** · Rôles : Detection Engineering, SOC, IR

## Scénario
L'EDR de CORP remonte 12 détections ce matin. Ton responsable : « Dis-moi ce qui est réel, ce qui est du bruit, et si nos règles ont des trous. »

## À faire
1. `python detect_process.py --tree WKS-0113` : raconte l'attaque en 6 étapes, avec heure, processus parent → enfant, et ce que ça signifie. Décode toi-même la commande PowerShell :
   ```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<colle la chaîne après -enc>"))
   ```
2. Les 5 alertes SCCM : pourquoi sont-elles **supprimées** et pas **effacées** ? Qu'est-ce qui empêche un attaquant de profiter de l'exception ?
3. WKS-0119 : pourquoi la règle `ENCODED_POWERSHELL` ne voit rien ? Quelle **unique** modification de la règle Python la ferait réagir ? Écris-la et ajoute un test.
4. Lis `sigma/encoded_powershell.yml` : le filtre SCCM est-il **aussi étroit** que celui de la version Python ? Sinon, quel risque cela crée-t-il ?
5. Priorise : quelles actions sur WKS-0113 dans les 15 premières minutes ?

## Critères de réussite
- [ ] Une chronologie exacte : Outlook 10:14 → Word 10:17:19 → cmd → PowerShell → certutil → p.exe → schtasks.
- [ ] Tu expliques `OriginalFileName` (le nom inscrit dans l'exécutable lui-même, que renommer le fichier ne change pas).
- [ ] Tu vois que le filtre Sigma n'impose pas le contenu décodé : un attaquant qui lance du PowerShell encodé via le client SCCM, en SYSTEM, passerait.
- [ ] Ton confinement : isoler le poste, tuer `p.exe`, supprimer la tâche planifiée, bloquer 203.0.113.99, chercher le même hash ou la même IP ailleurs, réinitialiser les identifiants de l'utilisateur.
