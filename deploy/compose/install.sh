#!/usr/bin/env bash
# WAFred Docker Compose installer.
#
#   curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh | bash
#
# Downloads the official compose file into ./wafred, writes a private .env with
# the values below, then runs `docker compose up -d`. It never needs root and
# never overwrites an existing .env: a second run is an upgrade, not a reset.
set -euo pipefail

REPO="${WAFRED_REPO:-oyport/wafred}"
REF="${WAFRED_REF:-}"
TAG="${WAFRED_TAG:-latest}"
DIR="${WAFRED_COMPOSE_DIR:-wafred}"
ADMIN_EMAIL="${WAFRED_ADMIN_EMAIL:-admin@wafred.local}"
ADMIN_PASSWORD="${WAFRED_ADMIN_PASSWORD:-wafred123}"
TLS_SANS="${WAFRED_TLS_SANS:-}"
HTTP_PORT="${WAFRED_HTTP_PORT:-80}"
HTTPS_PORT="${WAFRED_HTTPS_PORT:-443}"
ADMIN_PORT="${WAFRED_ADMIN_PORT:-9080}"
GRPC_PORT="${WAFRED_GRPC_PORT:-9090}"
FORCE=false
DRY_RUN=false

usage() {
    cat <<'EOF'
WAFred Docker Compose installer

Usage:
  install.sh [options]

Options:
  --tag <tag>              Image tag (default: latest; pin a release in production)
  --ref <git-ref>          Git ref the compose file is downloaded from
                           (default: v<tag> for a release tag, otherwise main)
  --dir <path>             Directory to create/use (default: ./wafred)
  --admin-email <email>    Initial administrator e-mail
  --admin-password <pw>    Initial administrator password (default: wafred123)
  --tls-sans <list>        Comma-separated SANs for the self-signed dashboard cert
  --http-port <port>       Host port for HTTP (default: 80)
  --https-port <port>      Host port for HTTPS (default: 443)
  --admin-port <port>      Host port for the console/API (default: 9080)
  --grpc-port <port>       Host port for the agent gRPC endpoint (default: 9090)
  --force                  Overwrite an existing .env (keeps the data volumes)
  --dry-run                Print the resolved plan and exit
  -h, --help               Show this help

Every option also has a WAFRED_* environment variable (WAFRED_TAG,
WAFRED_COMPOSE_DIR, WAFRED_ADMIN_EMAIL, ...).
EOF
}

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

warn() {
    printf 'warning: %s\n' "$1" >&2
}

require_value() { # $1 option, $2 next argument
    if [[ -z "${2:-}" ]]; then
        die "option $1 requires a value (use --help)"
    fi
    case "$2" in
        --*) die "option $1 requires a value, but got another option: $2" ;;
    esac
}

validate_port() { # $1 option, $2 value
    [[ "$2" =~ ^[0-9]+$ ]] || die "$1 must be a number"
    (( 10#$2 >= 1 && 10#$2 <= 65535 )) || die "$1 must be between 1 and 65535"
}

reject_control_chars() { # $1 label, $2 value
    if [[ "$2" == *[[:cntrl:]]* ]]; then
        die "$1 must not contain control characters"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag) require_value "$1" "${2:-}"; TAG="$2"; shift 2 ;;
        --ref) require_value "$1" "${2:-}"; REF="$2"; shift 2 ;;
        --dir) require_value "$1" "${2:-}"; DIR="$2"; shift 2 ;;
        --admin-email) require_value "$1" "${2:-}"; ADMIN_EMAIL="$2"; shift 2 ;;
        --admin-password) require_value "$1" "${2:-}"; ADMIN_PASSWORD="$2"; shift 2 ;;
        --tls-sans) require_value "$1" "${2:-}"; TLS_SANS="$2"; shift 2 ;;
        --http-port) require_value "$1" "${2:-}"; HTTP_PORT="$2"; shift 2 ;;
        --https-port) require_value "$1" "${2:-}"; HTTPS_PORT="$2"; shift 2 ;;
        --admin-port) require_value "$1" "${2:-}"; ADMIN_PORT="$2"; shift 2 ;;
        --grpc-port) require_value "$1" "${2:-}"; GRPC_PORT="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option '$1' (use --help)" ;;
    esac
done

reject_control_chars "tag" "$TAG"
reject_control_chars "admin e-mail" "$ADMIN_EMAIL"
reject_control_chars "admin password" "$ADMIN_PASSWORD"
reject_control_chars "TLS SANs" "$TLS_SANS"
validate_port "--http-port" "$HTTP_PORT"
validate_port "--https-port" "$HTTPS_PORT"
validate_port "--admin-port" "$ADMIN_PORT"
validate_port "--grpc-port" "$GRPC_PORT"

if [[ -z "$REF" ]]; then
    if [[ "$TAG" == "latest" ]]; then
        REF="main"
    else
        REF="v${TAG#v}"
    fi
fi
COMPOSE_URL="https://raw.githubusercontent.com/${REPO}/${REF}/docker-compose.yml"

# .env values are read by compose, so the same newline/quote rules apply as in
# any shell assignment. Ports and e-mail are validated above; these three can
# contain arbitrary text.
env_value() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\$}"
    printf '%s' "$value"
}

if [[ "$DRY_RUN" == "true" ]]; then
    cat <<EOF
WAFred Docker Compose install plan
  compose file : ${COMPOSE_URL}
  directory    : $(cd "$(dirname "$DIR")" 2>/dev/null && pwd || pwd)/$(basename "$DIR")
  image tag    : ${TAG}
  admin e-mail : ${ADMIN_EMAIL}
  admin passwd : $([[ "$ADMIN_PASSWORD" == "wafred123" ]] && echo "default (forced change on first login)" || echo "custom")
  tls sans     : ${TLS_SANS:-none (covers the hostname used to reach the console)}
  ports        : http ${HTTP_PORT}, https ${HTTPS_PORT}, admin ${ADMIN_PORT}, grpc ${GRPC_PORT}
EOF
    exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (the 'docker compose' plugin, not docker-compose)"

mkdir -p "$DIR"
cd "$DIR"

if [[ -f .env && "$FORCE" != "true" ]]; then
    die "$(pwd)/.env already exists; re-run with --force to rewrite it (data volumes are kept)"
fi

printf 'Downloading %s\n' "$COMPOSE_URL"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$COMPOSE_URL" -o docker-compose.yml
else
    die "curl is required to download the compose file"
fi

umask 077
{
    printf 'WAFRED_TAG=%s\n' "$(env_value "$TAG")"
    printf 'WAFRED_ADMIN_EMAIL=%s\n' "$(env_value "$ADMIN_EMAIL")"
    printf 'WAFRED_ADMIN_PASSWORD=%s\n' "$(env_value "$ADMIN_PASSWORD")"
    [[ -n "$TLS_SANS" ]] && printf 'WAFRED_TLS_SANS=%s\n' "$(env_value "$TLS_SANS")"
    [[ "$HTTP_PORT" != "80" ]] && printf 'WAFRED_HTTP_PORT=%s\n' "$HTTP_PORT"
    [[ "$HTTPS_PORT" != "443" ]] && printf 'WAFRED_HTTPS_PORT=%s\n' "$HTTPS_PORT"
    [[ "$ADMIN_PORT" != "9080" ]] && printf 'WAFRED_ADMIN_PORT=%s\n' "$ADMIN_PORT"
    [[ "$GRPC_PORT" != "9090" ]] && printf 'WAFRED_GRPC_PORT=%s\n' "$GRPC_PORT"
} > .env
chmod 600 .env

printf 'Starting WAFred (image tag %s)\n' "$TAG"
docker compose up -d

cat <<EOF

WAFred is starting.

  Console : https://localhost:${ADMIN_PORT}  (self-signed certificate)
  Account : ${ADMIN_EMAIL}
  Password: $([[ "$ADMIN_PASSWORD" == "wafred123" ]] && echo "wafred123 (forced change at first sign-in)" || echo "the value you supplied (stored in $(pwd)/.env)")

The first boot pulls the image and initialises PostgreSQL; the console can take
a minute to answer. Follow it with:

  cd $(pwd) && docker compose logs -f wafred

Upgrade later with:

  cd $(pwd) && docker compose pull && docker compose up -d
EOF
