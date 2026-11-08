#!/usr/bin/env bash
# WAFred Docker Compose installer.
#
#   curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh | bash
#
# Downloads the official compose file into ./wafred, writes a private .env with
# the values below, then runs `docker compose up -d`. It never needs root and
# preserves an existing .env: a second run is an upgrade, not a reset.
set -euo pipefail

REPO="${WAFRED_REPO:-oyport/wafred}"
MIRROR="${WAFRED_MIRROR:-}"
MIRROR_MODE="${WAFRED_MIRROR_MODE:-host-path}"
IMAGE_MIRROR="${WAFRED_IMAGE_MIRROR:-}"
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
  --mirror <https://host>  HTTPS prefix for GitHub downloads
  --mirror-mode <mode>    host-path (default) or full-url
  --image-mirror <url>    OCI proxy prefix (default: --mirror in host-path mode)
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
  --force                  Rewrite an existing .env (keeps the data volumes)
  --dry-run                Print the resolved plan and exit
  -h, --help               Show this help

Every option also has a WAFRED_* environment variable (WAFRED_MIRROR,
WAFRED_MIRROR_MODE, WAFRED_IMAGE_MIRROR, WAFRED_TAG, ...).
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

normalize_mirror() {
    while [[ "$MIRROR" == */ ]]; do MIRROR="${MIRROR%/}"; done
    while [[ "$IMAGE_MIRROR" == */ ]]; do IMAGE_MIRROR="${IMAGE_MIRROR%/}"; done
    [[ "$MIRROR_MODE" == "host-path" || "$MIRROR_MODE" == "full-url" ]] ||
        die "--mirror-mode must be host-path or full-url"
    if [[ -n "$MIRROR" ]]; then
        valid_mirror_url "$MIRROR" "--mirror"
    elif [[ "$MIRROR_MODE" != "host-path" ]]; then
        die "--mirror-mode requires --mirror"
    fi
    if [[ -n "$IMAGE_MIRROR" ]]; then
        valid_mirror_url "$IMAGE_MIRROR" "--image-mirror"
    fi
}

valid_mirror_url() { # $1 URL, $2 option
    # Docker repository paths are lowercase. Disallow credentials, query
    # strings, fragments and shell syntax before writing a URL to .env.
    [[ "$1" =~ ^https://[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9._-]+)*$ ]] ||
        die "$2 must be an HTTPS URL with a lowercase host and optional lowercase path (for example https://mirror.example.com)"
}

mirror_url() { # $1 official HTTPS URL
    if [[ -n "$MIRROR" ]]; then
        if [[ "$MIRROR_MODE" == "full-url" ]]; then
            printf '%s/%s' "$MIRROR" "$1"
        else
            printf '%s/%s' "$MIRROR" "${1#https://}"
        fi
    else
        printf '%s' "$1"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag) require_value "$1" "${2:-}"; TAG="$2"; shift 2 ;;
        --mirror) require_value "$1" "${2:-}"; MIRROR="$2"; shift 2 ;;
        --mirror-mode) require_value "$1" "${2:-}"; MIRROR_MODE="$2"; shift 2 ;;
        --image-mirror) require_value "$1" "${2:-}"; IMAGE_MIRROR="$2"; shift 2 ;;
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

normalize_mirror
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
COMPOSE_URL="$(mirror_url "https://raw.githubusercontent.com/${REPO}/${REF}/docker-compose.yml")"
IMAGE_REPO="ghcr.io/${REPO}"
IMAGE_PROXY_ENABLED=false
if [[ -n "$IMAGE_MIRROR" ]]; then
    IMAGE_REPO="${IMAGE_MIRROR#https://}/ghcr.io/${REPO}"
    IMAGE_PROXY_ENABLED=true
elif [[ -n "$MIRROR" && "$MIRROR_MODE" == "host-path" ]]; then
    IMAGE_REPO="${MIRROR#https://}/ghcr.io/${REPO}"
    IMAGE_PROXY_ENABLED=true
fi

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
  image        : ${IMAGE_REPO}:${TAG}
  directory    : $(cd "$(dirname "$DIR")" 2>/dev/null && pwd || pwd)/$(basename "$DIR")
  image tag    : ${TAG}
  admin e-mail : ${ADMIN_EMAIL}
  admin passwd : $([[ "$ADMIN_PASSWORD" == "wafred123" ]] && echo "default (forced change on first login)" || echo "custom")
  tls sans     : ${TLS_SANS:-none (covers the hostname used to reach the console)}
  ports        : http ${HTTP_PORT}, https ${HTTPS_PORT}, admin ${ADMIN_PORT}, grpc ${GRPC_PORT}
EOF
    if [[ -f "$DIR/.env" && "$FORCE" != "true" ]]; then
        echo "  existing .env: kept (only WAFRED_IMAGE changes when an image proxy is configured)"
    fi
    exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (the 'docker compose' plugin, not docker-compose)"

mkdir -p "$DIR"
cd "$DIR"

printf 'Downloading %s\n' "$COMPOSE_URL"
if command -v curl >/dev/null 2>&1; then
    compose_tmp="$(mktemp ./docker-compose.yml.XXXXXX)"
    if ! curl -fsSL "$COMPOSE_URL" -o "$compose_tmp"; then
        rm -f "$compose_tmp"
        die "failed to download the compose file from $COMPOSE_URL"
    fi
    mv "$compose_tmp" docker-compose.yml
else
    die "curl is required to download the compose file"
fi

ENV_PRESERVED=false
if [[ -f .env && "$FORCE" != "true" ]]; then
    ENV_PRESERVED=true
    printf 'Keeping existing %s/.env\n' "$(pwd)"
    if [[ "$IMAGE_PROXY_ENABLED" == "true" ]]; then
        # Change only the image source; preserve passwords and other settings.
        umask 077
        env_tmp="$(mktemp ./.env.XXXXXX)"
        awk -v image="$IMAGE_REPO" '
            /^WAFRED_IMAGE=/ { if (!seen) print "WAFRED_IMAGE=" image; seen=1; next }
            { print }
            END { if (!seen) print "WAFRED_IMAGE=" image }
        ' .env > "$env_tmp"
        chmod 600 "$env_tmp"
        mv "$env_tmp" .env
    fi
else
    umask 077
    {
        printf 'WAFRED_TAG=%s\n' "$(env_value "$TAG")"
        if [[ "$IMAGE_PROXY_ENABLED" == "true" ]]; then printf 'WAFRED_IMAGE=%s\n' "$IMAGE_REPO"; fi
        printf 'WAFRED_ADMIN_EMAIL=%s\n' "$(env_value "$ADMIN_EMAIL")"
        printf 'WAFRED_ADMIN_PASSWORD=%s\n' "$(env_value "$ADMIN_PASSWORD")"
        if [[ -n "$TLS_SANS" ]]; then printf 'WAFRED_TLS_SANS=%s\n' "$(env_value "$TLS_SANS")"; fi
        if [[ "$HTTP_PORT" != "80" ]]; then printf 'WAFRED_HTTP_PORT=%s\n' "$HTTP_PORT"; fi
        if [[ "$HTTPS_PORT" != "443" ]]; then printf 'WAFRED_HTTPS_PORT=%s\n' "$HTTPS_PORT"; fi
        if [[ "$ADMIN_PORT" != "9080" ]]; then printf 'WAFRED_ADMIN_PORT=%s\n' "$ADMIN_PORT"; fi
        if [[ "$GRPC_PORT" != "9090" ]]; then printf 'WAFRED_GRPC_PORT=%s\n' "$GRPC_PORT"; fi
    } > .env
    chmod 600 .env
fi

docker compose config -q || die "downloaded compose file or .env is invalid"

printf 'Starting WAFred with the image settings in .env\n'
if ! docker compose up -d; then
    die "docker compose failed; if using an image proxy, check its OCI registry path: ${IMAGE_REPO}"
fi

cat <<EOF

WAFred is starting.

  Console : https://localhost:${ADMIN_PORT}  (self-signed certificate)
  Account : $([[ "$ENV_PRESERVED" == "true" ]] && echo "see $(pwd)/.env" || echo "$ADMIN_EMAIL")
  Password: $([[ "$ENV_PRESERVED" == "true" ]] && echo "see $(pwd)/.env" || { [[ "$ADMIN_PASSWORD" == "wafred123" ]] && echo "wafred123 (forced change at first sign-in)" || echo "the value you supplied (stored in $(pwd)/.env)"; })

The first boot pulls the image and initialises PostgreSQL; the console can take
a minute to answer. Follow it with:

  cd $(pwd) && docker compose logs -f wafred

Upgrade later with:

  cd $(pwd) && docker compose pull && docker compose up -d
EOF
