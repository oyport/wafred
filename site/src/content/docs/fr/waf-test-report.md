---
title: Rapport de tests WAFred 1.0.4
description: Résultats corrigés du corpus complet, corrections des faux négatifs, vérification HTTPS avec certificat autosigné et références historiques d'autres WAF.
minutes: 5
---

## Résultats en bref

Test du 2026-11-22 avec une version candidate WAFred 1.0.4 compilée localement et le corpus public chaitin/blazehttp : 33 877 requêtes HTTP (658 malveillantes, 33 219 bénignes). Les blocages et les défis comptent comme interceptions et comme trafic bénin affecté.

| Niveau | Attaques interceptées | Trafic bénin affecté | Replay p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658 (60,33 %) | 4/33 219 (0,012 %) | 43 / 48 ms | 0 |
| Normal + inspection du corps | 494/658 (75,08 %) | 12/33 219 (0,036 %) | 43 / 48 ms | 0 |
| Strict | 501/658 (76,14 % ; 491 blocages, 10 défis) | 4/33 219 (0,012 %) | 43 / 48 ms | 0 |
| Strict + inspection du corps | **632/658 (96,05 % ; 622 blocages, 10 défis)** | **19/33 219 (0,057 %)** | 43 / 48 ms | 0 |

## Corrections des faux négatifs

Le replayer initial envoyait les échantillons sans adaptation. Les requêtes avec un corps mais sans `Content-Length` ni `Transfer-Encoding` arrivaient donc sans corps, ce qui sous-estimait l'inspection. Le replayer ajoute maintenant une longueur exacte et retire les octets au-delà d'une longueur déclarée valide. Cela corrige aussi 15 échantillons bénins mal formés qui renvoyaient HTTP 500 lors du transfert ; les quatre profils finaux n'ont plus de HTTP 500.

WAFred analyse désormais les corps URL-encoded et multipart sans `Content-Type` lorsqu'ils ont une structure de formulaire claire, inspecte les segments de chemin Base64 et ajoute deux signatures réservées à Strict pour `alert.call` et `prompt.call`. Strict + body a intercepté 632/658 attaques. Dix-neuf requêtes bénignes ont été bloquées ou défiées (17 blocages, 2 défis) : vérifiez ces échantillons avant d'activer ce niveau.

## Référence historique inter-produits

Le graphique compare la mesure actuelle de WAFred 1.0.4 au dernier test de la période PingWAF (P13), tout en conservant les références historiques SafeLine, ModSecurity et Cloudflare. Le test précédent utilisait le même corpus nominal, mais un framing du body plus ancien ; le harnais actuel a corrigé 15 réponses HTTP 500 liées au framing. Ces valeurs sont des résultats par version, pas une expérience avant/après contrôlée. Les autres produits n'ont pas été retestés et leurs dénominateurs et chemins réseau diffèrent. Le p95 WAFred inclut la VM, le proxy et l'origine simulée ; les latences ne sont pas directement comparables.

## Corps compressés et HTTPS

La suite gzip a intercepté 0/8 attaques sans inspection du corps, 7/8 avec Normal + inspection et 8/8 avec Strict + inspection. Les deux requêtes bénignes ont été acceptées dans tous les niveaux.

Un listener HTTPS isolé a utilisé un certificat autosigné pour `wafred-test.local` et `127.0.0.1`. La validation explicite avec `curl --cacert` a réussi ; le magasin de certificats par défaut de curl l'a refusé comme prévu. Les handshakes SNI OpenSSL ont réussi en TLS 1.2 et TLS 1.3. Les requêtes bénignes HTTP/HTTPS ont renvoyé 200 ; les attaques de formulaire et de chemin Base64 en HTTPS ont renvoyé 403. TLS s'est terminé sur WAFred ; l'origine simulée utilisait HTTP.

## Capacité et portée

Le test de trois minutes à 256 connexions et les résultats de limite de descripteurs à 512 proviennent du binaire déployé d'origine, pas du candidat corrigé. À 512 connexions, le processus d'origine avec `nofile=1 024` a produit 30 réponses 502 en GET et 68 en POST ; une copie isolée avec 65 536 n'en a produit aucune. Le processus all-in-one actif n'a pas été modifié.

La matrice de sécurité utilise un proxy HTTP/1.1 isolé et une origine simulée. Une origine réelle, HTTP/2/HTTP/3, le routage de production, rate limiting/CC et un test de forte concurrence du candidat restent à couvrir. Rapport complet : [WAFred 1.0.4](https://github.com/oyport/wafred/blob/main/docs/wafred-baseline-test-report-2026-11-22.md).
