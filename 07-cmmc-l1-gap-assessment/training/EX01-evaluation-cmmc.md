# Exercice : la PME peut-elle signer son affirmation CMMC ?

⏱️ **40 minutes** · Rôles : GRC, conformité, consultant

## Scénario
Le dirigeant de Northwind Precision Parts te dit : « Notre client (le prime) veut notre affirmation CMMC niveau 1 pour **le 31 décembre**. On a un antivirus et un pare-feu, donc ça va, non ? »

## À faire
1. Lis `data/assessment.csv`. Pour 3 exigences de ton choix, explique avec tes mots **pourquoi** le statut est correct, ou pourquoi tu le changerais.
2. Lance `python assess.py`. Peut-il signer le 31 décembre avec 8 h d'IT par semaine ? Et avec 4 h ? Que proposes-tu ?
3. « Partial » sur AC.L1-B.1.I : quelle **preuve** demandes-tu pour passer à « Met » ? (Pas « on l'a fait », une preuve vérifiable.)
4. Rédige la réponse au dirigeant en anglais (6 lignes max) : honnête, sans jargon, avec une date réaliste.
5. **Question éthique :** le dirigeant demande « Est-ce qu'on peut affirmer maintenant et corriger après ? » Que réponds-tu, et pourquoi ?

## Critères de réussite
- [ ] Tu sais qu'au niveau 1, **les 15 exigences** doivent être satisfaites et qu'un POA&M n'est **pas** permis.
- [ ] Chaque « Met » repose sur une **preuve** (capture, export, procédure signée), pas sur une déclaration orale.
- [ ] Ta réponse au dirigeant donne une date réaliste et les 3 actions qui débloquent le plus.
- [ ] À la question éthique, tu expliques qu'une affirmation fausse expose l'entreprise (False Claims Act) et proposes une solution honnête.
