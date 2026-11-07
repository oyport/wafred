---
title: Déploiement
description: Docker Compose et compilation, ports, précédence de configuration, systemd et agents distribués.
minutes: 10
---

## Formes de déploiement

**All-in-one** exécute le plan de contrôle et un plan de données dans un seul processus : idéal pour un nœud unique, une évaluation ou un petit déploiement.

**Distribué** exécute un `wafred server` et autant de `wafred agent` que nécessaire. L'état reste dans le plan de contrôle et les agents ne conservent que leur cache de règles : ajouter une périphérie ne touche pas la base.

## Ports

| Port | Usage | Remarques |
| --- | --- | --- |
| `9080` | API REST + console | HTTPS auto-signé jusqu'au remplacement ; à garder privé |
| `9090` | Plan gRPC | Les agents s'y connectent ; TLS par défaut, `grpc_tls_mode = "off"` dégrade |
| `80` | Trafic relayé | Lié dès le premier site créé |
| `443` | Trafic relayé | Ouvert après émission ou import d'un certificat |

`GET /healthz` répond en HTTP et HTTPS : c'est ce que doivent sonder le healthcheck compose et votre répartiteur.

## Docker Compose

```bash
git clone https://github.com/oyport/wafred.git
cd wafred
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

Le compose démarre `ghcr.io/oyport/wafred:latest` en all-in-one à côté de `postgres:16-alpine` et publie `80`, `443`, `9080` et `9090`. Le port de la base est lié à `127.0.0.1`.

> Gardez `hostname` stable : le plan de contrôle apparie les réenregistrements par hostname et API key ; un ID de conteneur changeant laisse des agents fantômes hors ligne.

## Compilation

| Outil | Version | Raison |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | Le binaire |
| Node.js | 26.12.1+ | Compile la console embarquée (`engine-strict`) |
| `protoc` | récent | Génération gRPC, **obligatoire** |
| `cmake` | récent | Backend TLS |
| PostgreSQL | 14+ (16 recommandé) | Stockage du plan de contrôle |

Sans `protoc`, `pingwaf-proto` écrit des fichiers factices et les crates suivants ne compilent pas.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin wafred --features full
./target/release/wafred all-in-one \
  --db-url "postgres://wafred:wafred@localhost:5432/wafred"
```

Sur Linux, `install.sh` télécharge l'archive, installe dans `/usr/local/bin`, écrit `/etc/wafred/wafred.toml` et l'unité systemd, puis démarre le service. Lancez-le dans un terminal sans argument pour l'assistant interactif (mode, identifiants administrateur, URL PostgreSQL, SANs du certificat, version), ou via un pipe pour une installation non interactive en une ligne.

```bash
# assistant interactif, avec plan d'installation et confirmation
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh -o install.sh && bash install.sh

# une ligne, non interactive (aucune question — un pipe n'a pas de terminal)
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash -s -- --mode all-in-one
```

Options : `--mode all-in-one|server|agent`, `--no-systemd` pour éviter l'unité, `--admin-email` / `--admin-password` / `--tls-sans` (ou les variables `WAFRED_*` correspondantes) pour définir les valeurs sans questions, et `--dry-run` pour prévisualiser le plan sans installer.

## Précédence de configuration

Lecture du TOML, puis des variables `WAFRED_*`, puis des options CLI ; le dernier canal gagne. Les clés inconnues sont signalées puis ignorées.

```bash
wafred all-in-one --config /etc/wafred/wafred.toml
WAFRED_CONFIG=/etc/wafred/wafred.toml wafred all-in-one
```

`[server]` couvre `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` et `serve_frontend`. `[agent]` couvre `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, les lots de journaux, `fail_open` et l'envoi de métriques.

## Agents distribués

```bash
WAFRED_SERVER_URL="https://control.example.com:9090" \
WAFRED_API_KEY="<enrollment key>" \
WAFRED_CACHE_DIR="/var/lib/wafred/cache" \
wafred agent
```

Les clés d'enrôlement se créent depuis la console (`POST /api/v1/agents/enroll` renvoie la commande d'installation). Un `WAFRED_API_KEY` vide ne vaut que pour l'auto-enregistrement en boucle locale en all-in-one.

## systemd et TLS

L'unité fournie s'exécute sous l'utilisateur `wafred` avec `Restart=always`, `LimitNOFILE=65536` et `ProtectSystem=strict`, avec écriture limitée à `/var/lib/wafred` et `/etc/wafred`. Aucun signal de reload : les changements viennent du plan de contrôle, et un changement de binaire ou d'unité demande `systemctl restart wafred`.

La console sert du HTTPS dès le premier démarrage avec un certificat auto-signé. Renseignez `WAFRED_TLS_SANS` avec le hostname réel avant génération, importez votre certificat via **Réglages → HTTPS du plan de contrôle**, ou passez `WAFRED_TLS_ENABLED=false` derrière un proxy terminant TLS.
