# Corrigé : exercice S1-J1

> ⚠️ Ouvre ce fichier seulement après avoir envoyé ton analyse.

## ALERT-001 : `a.morgan` depuis 203.0.113.45 → **True positive, escalade immédiate**

**Preuves qui soutiennent le verdict**
| Heure UTC | Event | Preuve |
|---|---|---|
| 02:13:05–02:13:14 | 4625 `0xC0000064` | La même IP essaie d'abord `amorgan` puis `alex.morgan`, deux comptes qui **n'existent pas**. L'attaquant devine le format des noms d'utilisateur : ce n'est pas une employée qui se trompe de mot de passe. |
| 02:13:24–02:18:46 | 14 × 4625 `0xC000006A` | 14 mauvais mots de passe en 5 min 22 s, depuis une IP **externe** (203.0.113.45), sur `SRV-RDP01`, **exposé à internet** (assets.csv). |
| 02:19:58 | 4624 LogonType **10** | Connexion RDP réussie, depuis un poste nommé `DESKTOP-7K2Q9P` : ce n'est pas le poste d'Alex (`WKS-0101`). |
| 02:19:59 | 4672 | Session avec privilèges administrateur : le compte est **privilégié** (IT). |
| 02:24:10 / 02:24:48 | 4720 + 4732 | Moins de 5 minutes après la connexion, création de `support_tmp`, ajouté aux **Administrators**. C'est de la **persistance** (T1136, T1098). |
| 09:07:01 | 4624 type 2 sur WKS-0101 | La vraie Alex commence sa journée à 09:07 sur son poste. Ça **suggère** qu'elle n'était pas active à 02:19, mais ça **ne le prouve pas** : il faut lui demander. |

**Preuves manquantes**
| Ce qu'on ne sait pas | Où chercher |
|---|---|
| Ce que l'attaquant a fait sur SRV-RDP01 entre 02:19 et 02:24 (outils, commandes, fichiers) | EDR / Sysmon / 4688 (création de processus) sur SRV-RDP01 |
| Si Alex reconnaît cette activité | Appel **hors bande** (téléphone ou responsable, pas l'email du compte compromis) |
| Si `support_tmp` a été utilisé après 02:24, ailleurs que dans ces logs | Logs du DC et des autres serveurs, au-delà du 14/10. Dans nos données, aucun 4624 pour `support_tmp`, mais la couverture est limitée |
| Réputation et géolocalisation de 203.0.113.45, autres connexions vers nous | Threat intel, logs pare-feu ou VPN |
| Pourquoi personne n'a vu l'alerte entre 02:20 et 09:30 | Process SOC (couverture de nuit), point d'amélioration |

**Pourquoi escalader maintenant :** compte privilégié, accès réussi depuis l'extérieur et persistance créée. Chaque minute compte, et 7 heures se sont déjà écoulées. On escalade **avant** d'avoir toutes les réponses : les preuves manquantes justifient l'enquête Tier 2, elles ne justifient pas d'attendre.

**Confinement, par priorité** (actions à proposer et coordonner avec Tier 2 ou IT, pas à faire seul sans autorisation)
| # | Action | Comment vérifier que ça a marché |
|---|---|---|
| 1 | Désactiver `support_tmp` et le retirer d'Administrators | 4725 (désactivé) / 4733 (retiré du groupe), `Get-ADUser support_tmp` → Enabled False |
| 2 | Réinitialiser le mot de passe de `a.morgan` (2 fois si Kerberos), fermer ses sessions RDP | Nouveau 4724, plus de session active de 203.0.113.45 |
| 3 | Bloquer 203.0.113.45 et retirer l'exposition de RDP à internet (passer par VPN + MFA) | Plus aucun 4625/4624 depuis des IP externes sur SRV-RDP01 |
| 4 | Isoler ou analyser SRV-RDP01 (EDR) avant de le remettre en service | Rapport d'analyse, aucun outil malveillant trouvé |
| 5 | Chercher d'autres comptes compromis par la même méthode | Voir « Ce que la règle n'a pas vu » plus bas |

---

## ALERT-002 : `j.rivera` depuis 10.10.20.117 → **Benign true positive** (comportement réel, cause non malveillante), à clôturer

**Preuves**
| Heure UTC | Event | Preuve |
|---|---|---|
| 08:52:31 | 4723 | j.rivera a changé **lui-même** son mot de passe, 9 minutes avant les échecs. |
| 09:01:10–09:08:24 | 9 × 4625 type 3 | Échecs **réseau** vers SRV-FILE01, depuis **10.10.20.117 = WKS-0117, son propre poste** (users.csv + assets.csv). C'est un lecteur réseau qui garde l'ancien mot de passe. |
| 09:11:22 | 4624 type 3 | Succès depuis le même poste, sans 4672 ni changement de compte ensuite. Compte non privilégié (Finance). |

**Preuves manquantes :** la confirmation de l'utilisateur (ticket ou appel : « as-tu changé ton mot de passe ce matin ? »), et les logs du poste WKS-0117 pour confirmer quel processus utilisait l'ancien identifiant.

**Décision :** clôturer en *benign true positive* avec ces preuves dans la note, après confirmation rapide de l'utilisateur. **Amélioration :** ce cas se répète après chaque changement de mot de passe. On peut baisser la priorité quand on voit à la fois un 4723 de moins de 2 h, une source interne et le poste attribué, mais **sans supprimer l'alerte**.

---

## Ce que la règle n'a pas vu : `k.chen` depuis 198.51.100.23 ⚠️
La commande de l'indice 4 montre **27 échecs** de `k.chen` depuis 198.51.100.23 (IP **externe**), entre 10:00 et 13:45, par groupes de 3 toutes les ~25 minutes. Ensuite vient une **connexion RDP réussie à 13:48:39** (4624 type 10). Jamais 5 échecs en 10 minutes, donc la règle ne s'est pas déclenchée : c'est une attaque **low and slow**. Si tu l'as trouvée, c'est le réflexe d'un analyste expérimenté : **ne pas faire confiance seulement aux alertes**. Ce cas devient l'exercice de la semaine 2 : écrire une règle de chasse qui la trouve sans exploser le nombre de faux positifs.

---

## Exemple de résumé (section 1 du rapport, en anglais)
> On Oct 14 at 02:19 UTC, an external IP (203.0.113.45) logged in over RDP to the internet-exposed jump host SRV-RDP01 as **a.morgan**, a privileged IT account, after 14 failed password attempts in 5 minutes. Within 5 minutes, the session created a new account, **support_tmp**, and added it to Administrators. This is a confirmed account compromise with persistence (high confidence). I escalated to Tier 2 at 09:35 and recommend disabling support_tmp, resetting a.morgan's password, and removing internet RDP exposure immediately.

## Barème (sur 10 par critère)
| Critère | 9–10 | 5–6 |
|---|---|---|
| Preuves | Heures, IDs et champs exacts, y compris 0xC0000064 et le nom du poste de l'attaquant | « Beaucoup d'échecs puis un succès » |
| Raisonnement | Distingue « suggère » et « prouve » (la connexion à 09:07) | Reprend le score de l'outil comme preuve |
| Priorisation | ALERT-001 d'abord, escalade immédiate, mentionne le délai de 7 h | Traite les deux alertes de la même façon |
| Remédiation | Actions ordonnées, chacune avec sa vérification | « Changer le mot de passe » seulement |
| Communication | Résumé manager clair en 4 phrases, en anglais simple | Jargon ou texte trop long |
