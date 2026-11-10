# Exercice : traiter la file « Report phishing »

⏱️ **35 minutes** · Rôles : SOC, Email Security, IR

## Scénario
Lundi matin, 5 emails signalés t'attendent. Rachel (Finance) a déjà répondu à E3 : « OK, je vais acheter les cartes ce midi ». Devon (IT) dit avoir cliqué sur le lien d'E2, mais « sans rien taper ».

## À faire **avant** de lancer l'outil
Ouvre chaque `.eml` dans le Bloc-notes (ce sont des fichiers texte) et, pour chacun, note :
1. Ton verdict, et les **2 preuves les plus fortes** (en-tête + valeur exacte).
2. Les IOCs à bloquer, et ceux qu'il ne **faut surtout pas** bloquer.
3. L'action **urgente** pour Rachel (E3) et pour Devon (E2). Dans quel ordre, et pourquoi ?

## Ensuite
```powershell
python triage_email.py
```
4. Compare tes réponses avec l'outil. Où t'es-tu trompé, et où l'outil se trompe-t-il ?
5. Écris en anglais le message de 3 phrases à Sana (E5), qui a signalé une newsletter légitime. Elle doit avoir envie de **continuer** à signaler.

## Critères de réussite
- [ ] Tu expliques pourquoi E3 passe SPF/DKIM/DMARC et reste malveillant.
- [ ] Pour Devon : un clic sans saisie demande quand même une vérification (logs proxy et DNS, version du navigateur, connexions récentes).
- [ ] Tu ne bloques ni `corp.example`, ni `gmail.com`, ni l'IP du serveur Gmail.
- [ ] Rachel passe en premier : de l'argent est sur le point de partir.

<details><summary>Indice</summary>Pour E3, compare le nom affiché avec <code>directory.csv</code>. Pour E4, décode la pièce jointe base64 (ou laisse l'outil le faire) et cherche <code>&lt;form action=</code>.</details>

**Envoie ton analyse avec « Entraînement du jour » avant d'ouvrir le corrigé.**
