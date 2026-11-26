---
title: Tunnels
description: Exposez un service d'un réseau privé via le plan de données du WAF, sans port entrant ni IP publique sur cet hôte. Appairage, listener d'edge, rattachement du pool d'origines, sortie SOCKS5, exploitation et dépannage.
minutes: 12
---

Un tunnel expose un service situé dans un réseau privé (NAS, application interne, page d'administration de base de données) **sans ouvrir de port entrant et sans IP publique sur cet hôte**. Le connecteur se connecte en sortie vers l'edge ; l'edge termine le côté public. Toutes les protections du WAF (règles, limitation de débit, challenges, cache, contrôle d'accès, journaux, certificats, TLS vers l'origine) s'appliquent telles quelles : pour l'edge, un tunnel est une origine ordinaire.

## Les pièces

| Pièce | Où elle tourne | Rôle |
| --- | --- | --- |
| **Connecteur** (`wafred-tunnel`) | dans le réseau privé | se connecte **en sortie** au plan de contrôle et aux edges ; relaie chaque connexion vers la cible interne |
| **Listener d'edge** | sur l'edge (`tunnel_addr`, port `9443`) | accepte la session TLS du connecteur et ouvre un pont loopback par cible |
| **Pont** | sur l'edge, `127.0.0.1:<port éphémère>` | fait passer le tunnel pour une origine ordinaire |
| **Rattachement du pool** | plan de contrôle | indique quels `host:port` internes le trafic du site peut atteindre par ce tunnel |

Un tunnel n'est **pas** un VPN : il ne transporte que le trafic des pools d'origines qui lui sont rattachés. Un tunnel = un domaine de confiance.

## Trois états distincts

| État | Signification |
| --- | --- |
| **Appairé** | les identifiants existent ; le tunnel est utilisable |
| **Activé** | l'interrupteur par tunnel de l'opérateur |
| **Connecteur en ligne** | un connecteur détient actuellement un flux de contrôle |

Un tunnel peut être appairé et activé avec un connecteur hors ligne : c'est une configuration valide, pas une panne.

## Mise en place en cinq étapes

### 1. Créer le tunnel

**Agents → Tunnels → Create tunnel.** La console affiche une commande d'appairage à usage unique. Le jeton n'est affiché **qu'une fois** et expire après 30 minutes par défaut ; en générer un autre fait tourner les identifiants et déconnecte le connecteur en cours.

### 2. Lancer le connecteur dans le réseau privé

```bash
sudo wafred-tunnel pair \
  --config /etc/wafred/tunnel.toml \
  --server-url https://control-plane:9090 \
  --server-ca-cert /etc/wafred/tunnel-ca.pem \
  --token <pairing-token>
sudo wafred-tunnel run --config /etc/wafred/tunnel.toml
```

`pair` échange le jeton contre des identifiants durables et écrit `/etc/wafred/tunnel.toml` (`0600`). `run` maintient un flux de contrôle vers le plan de contrôle et une session par ingress d'edge. Les échecs de connexion sont journalisés en `warn`.

### 3. Activer le listener d'un edge et lui donner une adresse publique

```toml
[agent]
tunnel_addr = "0.0.0.0:9443"
```

Ouvrez `9443` dans le pare-feu, puis renseignez l'adresse **Tunnel ingress** dans **Agents → [nœud]**. L'edge génère son certificat auto-signé au premier démarrage (persisté), en publie le SHA-256 et le connecteur l'épingle. Le listener se lie au démarrage : changer `tunnel_addr` exige un redémarrage. L'adresse d'ingress et la politique sont appliquées à chaud (≤5 s sur un edge connecté).

### 4. Rattacher un pool d'origines

**Sites → [site] → Origin pools → [pool] → Tunnel.** Les adresses des nœuds du pool sont les cibles internes que le connecteur contacte. Sans session, le pool n'a pas d'origine en amont et les routes répondent `503` au lieu de basculer vers l'origine par défaut.

### 5. Vérifier

1. **Connecteur en ligne** : badge de la liste et panneau de détail ; `wafred-tunnel status` donne le même état localement.
2. **Un edge propose un ingress** : le panneau affiche l'edge et les cibles.
3. **Le site répond** : `curl -H 'Host: app.example.com' --resolve …` doit renvoyer `200`.

## Trajet d'une requête

Client → edge `:443` → pipeline WAF → pool rattaché au tunnel → pont loopback → session TLS multiplexée → connecteur → cible interne. Le journal d'accès affiche l'origine comme `tunnel://<nom>/<cible>`.

## Sans sortie directe : SOCKS5

```toml
socks5_proxy    = "10.0.0.1:1080"
socks5_username = "connector"
socks5_password = "…"
```

Les deux canaux — flux de contrôle et sessions d'edge — passent par le proxy. Les noms de cibles sont résolus par le proxy (ATYP 3) et il n'y a aucun repli silencieux vers une connexion directe.

## Exploitation

| Action | Effet |
| --- | --- |
| **Ré-appairer** | tourne les identifiants, déconnecte le connecteur |
| **Révoquer** | supprime les identifiants ; les edges refusent au bundle suivant (≤5 s) |
| **Désactiver** | interrupteur par tunnel ; les sessions se ferment au prochain rechargement |
| **Supprimer** | refusé (`409`) tant que des pools le référencent ; `?force=true` détache les pools, qui repassent en origines **directes** |
| **Réglages** | interrupteur global, durée du jeton, flux par session, cibles par tunnel |

## Modèle de sécurité

L'edge ne voit jamais les identifiants du connecteur : il vérifie un **jeton de session Ed25519 de courte durée** émis par le plan de contrôle (clé dérivée de `jwt_secret`). Un jeton capturé expire (une heure par défaut) et ne vaut que pour un tunnel. Le connecteur épingle le certificat de l'edge. La révocation converge tant que l'edge peut joindre le plan de contrôle.

## Dépannage

| Symptôme | À vérifier |
| --- | --- |
| `cannot reach the control plane` | `server_url`, accès au `9090`, CA, proxy SOCKS5 |
| En ligne mais « 0 edge » | `tunnel_addr` ou adresse d'ingress non renseignés |
| Identifiants refusés | jeton expiré ou révoqué, ou edge sans la nouvelle clé publique |
| `502/503` | aucune session, ou connecteur incapable d'atteindre la cible |
| Suppression `409` | des pools le référencent encore |

## Limites de cette version

HTTP, HTTPS et WebSocket via un site ; TCP brut non exposé. Un tunnel = un domaine de confiance. Les cibles et les flux par session sont plafonnés par les réglages.