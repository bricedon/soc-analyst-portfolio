# Corrigé : file « Report phishing »

| Email | Verdict | Preuves clés |
|---|---|---|
| E1 | Légitime | SPF/DKIM/DMARC `pass` pour acme-supplies.example (fournisseur approuvé), lien vers son vrai portail, PDF attendu |
| E2 | Phishing d'identifiants | Domaine `micros0ft-account.example` (un zéro à la place du o), le texte affiche `login.microsoftonline.com` mais le lien va ailleurs en **http**, Reply-To différent, urgence + menace |
| E3 | BEC (fraude au président) | Nom « Kiran Patel » = le PDG dans l'annuaire, mais adresse **gmail**, Reply-To vers un autre domaine, cartes cadeaux + « confidentiel » + « can't talk ». L'authentification passe parce que c'est **vraiment** Gmail |
| E4 | Usurpation de notre domaine + formulaire | `From: helpdesk@corp.example` mais **SPF/DKIM/DMARC fail**, envoyé depuis 203.0.113.66, pièce jointe HTML avec un champ mot de passe qui poste vers `http://203.0.113.66/collect.php` |
| E5 | Légitime (bon réflexe de l'utilisatrice) | Authentification `pass`, liens de suivi du même domaine, lien de désinscription, l'utilisatrice a un compte CloudNotes |

## Ordre d'urgence
1. **Rachel (E3) en premier :** de l'argent va partir ce midi. L'appeler tout de suite, prévenir la Finance, et vérifier avec le PDG par un numéro connu.
2. **Devon (E2) :** même sans saisie, vérifier les logs proxy et DNS (a-t-il seulement chargé la page ? une redirection ?), la version de son navigateur, et ses connexions Microsoft 365 récentes. S'il a saisi quoi que ce soit : réinitialiser son mot de passe, révoquer ses sessions, vérifier ses règles de boîte mail.
3. Purger E2, E3 et E4 de toutes les boîtes, puis bloquer les IOCs.

## Les IOCs à ne pas bloquer
`corp.example` : c'est nous ; la vraie solution est un DMARC en `p=reject`. `gmail.com` : des millions d'utilisateurs légitimes. `192.0.2.41` : un serveur d'envoi Gmail partagé. On bloque **l'adresse précise**, les URL et l'IP 203.0.113.66.

## Message à Sana (E5)
> Thanks for reporting this, Sana. Reporting is exactly the right reflex! We checked it: this newsletter really comes from CloudNotes, the service you signed up for, so it's safe and you can keep it or unsubscribe. Please keep sending us anything that looks odd.
