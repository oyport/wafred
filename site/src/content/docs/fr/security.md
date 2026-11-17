---
title: Sécurité
description: Comment signaler une vulnérabilité en privé, quelles versions reçoivent des correctifs et comment durcir l'instance avant d'exposer WAFred à Internet.
minutes: 8
---

## Signaler une vulnérabilité

WAFred se trouve dans le chemin des requêtes des applications qu'il protège :
une vulnérabilité dans WAFred compte autant qu'une dans les sites derrière lui.
Signalez-la toujours en privé — jamais dans une issue, une discussion ou une
pull request publique.

- **GitHub private vulnerability reporting (recommandé) :**
  [Signaler une vulnérabilité](https://github.com/shuaiZend/WAFred/security/advisories/new)
  — privé, suivi, et le chemin le plus rapide vers un correctif.
- **E-mail :** `security@waf.red`, surveillé par au moins deux mainteneurs.
  Une clé PGP est en cours de publication ; tant que son empreinte n'est pas
  listée ici, envoyez d'abord un résumé en texte clair et nous répondrons avec
  la clé.

Indiquez la version affectée, le mode d'exécution (`all-in-one`, `server`,
`agent`), le backend TLS, les étapes de reproduction et les prérequis d'attaque ;
masquez jetons et mots de passe. Nous accusons réception sous trois jours ouvrés,
donnons des nouvelles chaque semaine pendant la préparation du correctif et
coordonnons la divulgation après sa publication (ou à 90 jours, au plus tôt). La
politique complète se trouve dans
[SECURITY.md](https://github.com/shuaiZend/WAFred/blob/main/SECURITY.md).

## Versions supportées

| Version | Statut | Correctifs de sécurité |
| --- | --- | --- |
| `0.32.x` (ligne actuelle) | Supportée | Oui |
| `0.31.x` | Correctifs critiques uniquement | Sur demande, best effort |
| `0.30.x` et antérieures | Fin de vie | Non |

Seule la ligne actuelle reçoit des correctifs garantis ; les correctifs de
sécurité sortent en versions de patch et sont listés sous `### Security` dans le
[changelog](https://github.com/shuaiZend/WAFred/blob/main/CHANGELOG.md).

## Durcissement avant exposition

La console embarque des valeurs par défaut pensées pour le développement. Avant
d'exposer une instance à un réseau que vous ne contrôlez pas :

1. **Identifiants** — changez le mot de passe administrateur initial, définissez
   `WAFRED_JWT_SECRET` et `WAFRED_SECRET_KEY` avec 32 octets aléatoires
   chacun, fermez l'inscription (`WAFRED_ALLOW_REGISTRATION=false`) et changez
   le mot de passe PostgreSQL.
2. **Réseau** — liez la console (`9080`) à loopback ou à une interface privée et
   passez par un VPN ou un reverse proxy ; n'exposez le port gRPC (`9090`)
   qu'aux hôtes agents ; n'exposez jamais PostgreSQL (`5432`).
3. **TLS** — importez un vrai certificat pour la console ou terminez TLS devant
   elle ; activez HTTPS et HSTS sur chaque site ; gardez TLS sur gRPC.
4. **Secrets au repos** — `WAFRED_SECRET_KEY` chiffre les secrets des canaux de
   notification, la clé du fournisseur d'IA et les identifiants des cibles de
   sauvegarde. Sans elle, ils sont stockés en clair. Sauvegardez la clé
   séparément ; il n'y a pas encore de rotation en ligne.
5. **Journaux** — les logs d'accès conservent les en-têtes complets (dont
   `Authorization`, `Cookie` et `Set-Cookie`) et jusqu'à 8 Kio de chaque corps,
   pendant 180 jours par défaut. Traitez PostgreSQL et Elasticsearch comme des
   coffres d'identifiants et réduisez la rétention quand c'est possible.
6. **MCP et IA** — une clé MCP `write` est un identifiant administrateur global ;
   une clé `read` ne voit que les sites de son propriétaire. L'assistant IA envoie
   les résultats d'outils (sites, logs, événements WAF, audit) au fournisseur
   configuré : activez-le uniquement là où ces données peuvent sortir du
   déploiement.

La liste complète, avec les variables exactes, les étapes de sauvegarde et les
avertissements de rotation, se trouve dans
[SECURITY.md](https://github.com/shuaiZend/WAFred/blob/main/SECURITY.md#hardening-checklist)
et [docs/deployment.md](https://github.com/shuaiZend/WAFred/blob/main/docs/deployment.md).
