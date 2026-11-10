# Corrigé : chasse au beacon

**Coefficient de variation (CV)** = écart-type ÷ moyenne des intervalles entre connexions. Un humain clique de façon irrégulière : son CV est proche de 1 ou plus. Un programme réglé sur 60 s ± 3 s donne un CV d'environ 0.03.

**Pourquoi 10.10.10.40:8443 n'est pas un C2 :** (1) **les 30 postes** lui parlent : c'est un service de l'entreprise, pas une infection isolée. (2) La destination est **interne**, connue, avec un propriétaire (IT Ops) et une ligne dans la liste blanche, avec une date de revue. Une liste blanche sans propriétaire ni date de revue est elle-même un risque.

**10.10.20.108 → 198.51.100.200 :** ~11 connexions sur 7,4 h, intervalle ~48 min à ±30 %, **40 à 260 Ko envoyés** à chaque fois pour ~1 Ko reçu. Ça peut être de l'exfiltration, ou un client de sauvegarde ou de synchronisation non déclaré. Preuves à demander : **le processus** qui ouvre ces connexions (EDR / Sysmon EID 3), **le domaine** (logs DNS, certificat TLS dans `ssl.log`), et **l'utilisateur ou le propriétaire** du poste (« utilisez-vous un outil de sauvegarde ? »). Et la question de la donnée : *quels fichiers* ont été lus juste avant ?

**Escalade pour 10.10.20.113 :**
> Host 10.10.20.113 has connected to external IP 203.0.113.99 on port 443 every 60 seconds (462 times, ±3 s) for almost 8 hours, with near-identical request sizes. No other host talks to this IP, and it is not a known service. This matches command-and-control beaconing. I recommend isolating the host through EDR now, collecting the process that opens these connections, and blocking 203.0.113.99 at the firewall and proxy. I will check whether any other host contacted this IP in the last 30 days.
