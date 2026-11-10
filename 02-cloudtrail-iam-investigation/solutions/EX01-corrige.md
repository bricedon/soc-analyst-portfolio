# Corrigé : exercice S3-J1

## 1. Changement autorisé → clôturer
`devon.admin` (session console **avec MFA**, IP 198.51.100.10 = bureau) attache **ReadOnlyAccess** à `intern.qa` à 15:12:40. Le ticket **CHG-2041** correspond sur tous les points : acteur, action, cible, politique et fenêtre 14:00–18:00. Impact : le stagiaire peut tout **lire**, y compris des données sensibles. C'est autorisé, mais tu peux recommander une politique plus étroite (moindre privilège).

## 2. Tentative refusée → ce n'est PAS « sans danger »
La clé longue durée de `ci-deploy` (AKIA…), depuis **203.0.113.77** (internet), fait d'abord `GetCallerIdentity` (« qui suis-je ? », une reconnaissance typique). Ensuite, elle tente `AttachUserPolicy AdministratorAccess` sur elle-même, puis `CreateAccessKey` : deux **AccessDenied**. Or `identities.csv` dit que `ci-deploy` déploie **uniquement depuis les serveurs de build (10.0.0.0/8)**. Conclusion : **la clé a fuité** (code source, logs de pipeline, poste d'un développeur). Décision : la tourner et la désactiver, chercher toutes ses utilisations depuis des IP externes, et trouver la source de la fuite. Le refus prouve que le moindre privilège a fonctionné. Il ne prouve pas que la clé est sûre.

## 3. Escalade réussie → incident critique
| Heure UTC | Appelant | Action | Ce que ça signifie |
|---|---|---|---|
| 03:41:17 | mlee | ConsoleLogin **MFAUsed=No**, IP 203.0.113.200 | Mot de passe seul, IP inconnue, hors des horaires de mlee (13–23) |
| 03:43:22 | mlee | ListAttachedUserPolicies | Reconnaissance : « quels droits ai-je ? » |
| 03:44:34 | mlee | AssumeRole DevOpsAutomation | Passe sur un rôle qui peut gérer IAM |
| 03:47:14 | DevOpsAutomation/mlee | CreateUser **backup-svc2** | Persistance (nom qui imite un compte de service) |
| 03:48:02 | DevOpsAutomation/mlee | AttachUserPolicy **AdministratorAccess** | Contrôle total du compte |
| 03:48:38 | DevOpsAutomation/mlee | CreateAccessKey backup-svc2 | Identifiant longue durée, qui survit à un reset du mot de passe de mlee |
| 03:54:41–03:55:03 | backup-svc2 | GetCallerIdentity, ListBuckets | La nouvelle clé est utilisée, avec la même IP |
| 03:56:13 | backup-svc2 | **StopLogging** org-trail | On efface ses traces : tout ce qui suit est **invisible** |

**Identifiants de mlee ≠ Min Lee :** à 14:05:36, mlee se connecte **avec MFA** depuis le bureau (198.51.100.11) et fait des actions normales. Le plus probable : un mot de passe volé, sur un compte où la MFA n'est **pas imposée**. Il faut le confirmer **hors bande**.

**Impact :** l'attaquant a un administrateur complet (`backup-svc2` et sa clé) et la journalisation est coupée depuis 03:56. On ne sait pas ce qui s'est passé après : exfiltration S3, création de ressources, autres portes dérobées.

## Vérifications avant confinement (dans l'ordre)
1. **Redémarrer la journalisation** et chercher d'autres sources (trail d'organisation, GuardDuty, logs d'accès S3), puisque le trail est aveugle depuis 03:56.
2. **Inventorier les identifiants** : toutes les clés de backup-svc2 et de mlee, les sessions actives du rôle, d'autres utilisateurs créés.
3. **Chercher d'autres formes de persistance** : relations de confiance des rôles modifiées, nouvelles versions de politiques, Lambda / EC2 / profils de connexion créés, dans **toutes les régions**.
4. **Évaluer l'impact métier** : `DevOpsAutomation` sert-il aux pipelines de production ? Si oui, on révoque les **sessions** actives sans supprimer le rôle.
5. **Confirmer avec Min Lee hors bande**, puis **préserver les preuves** (export CloudTrail) avant de supprimer quoi que ce soit.

Ensuite, confinement : désactiver la clé de backup-svc2 → lui retirer AdministratorAccess → révoquer les sessions de DevOpsAutomation → réinitialiser le mot de passe de mlee et **imposer la MFA**. Chaque action se vérifie (voir le guide, section 3).

## Exemple de résumé manager
> On Oct 20 at 03:41 UTC, someone signed in to AWS as developer mlee with a password only (no MFA) from an unknown internet IP. Using the DevOpsAutomation role, they created a new user, backup-svc2, gave it full administrator access, created an access key for it, and at 03:56 stopped our CloudTrail logging. The real Min Lee signed in normally with MFA at 14:05, so we believe her password was stolen. We need to restore logging and disable the backdoor user now, and we cannot yet see what happened after 03:56.
