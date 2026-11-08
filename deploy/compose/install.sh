#!/usr/bin/env bash
# WAFred Docker Compose installer.
#
#   curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh | bash
#
# Downloads the official compose file into ./wafred, writes a private .env with
# the values below, then runs `docker compose up -d`. A missing Docker Engine
# requires root or passwordless sudo for package installation. Existing .env
# settings are preserved on a second run.
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
AUTO_INSTALL_DOCKER=true

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
  --no-install-docker      Do not install missing Docker/Compose packages
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

compose_package() {
    local package version
    for package in docker-compose-plugin docker-compose-v2; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            printf '%s' "$package"
            return 0
        fi
    done
    version="$(apt-cache show docker-compose 2>/dev/null | sed -n 's/^Version: //p' | head -n1 || true)"
    if [[ "$version" == 2.* ]]; then
        printf 'docker-compose'
        return 0
    fi
    return 1
}

ensure_docker() {
    local -a admin=() packages=()
    local distro compose_pkg

    if ! command -v docker >/dev/null 2>&1 ||
       ! command -v dockerd >/dev/null 2>&1 ||
       ! docker compose version >/dev/null 2>&1; then
        [[ "$AUTO_INSTALL_DOCKER" == "true" ]] ||
            die "Docker Engine and Compose v2 are required; install them or remove --no-install-docker"
        [[ -r /etc/os-release ]] || die "cannot identify this OS; install Docker Engine and Compose v2 manually"
        # shellcheck disable=SC1091
        . /etc/os-release
        distro="${ID:-}"
        [[ "$distro" == debian || "$distro" == ubuntu ]] ||
            die "automatic Docker installation supports Debian/Ubuntu; install Docker Engine and Compose v2 manually on ${distro:-this OS}"
        command -v apt-get >/dev/null 2>&1 || die "apt-get is required to install Docker automatically"
        if (( EUID != 0 )); then
            command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 ||
                die "Docker is missing; run this installer as root or with passwordless sudo, or install Docker first"
            admin=(sudo -n)
        fi

        printf 'Installing Docker Engine and Compose v2 from the %s package repository...\n' "$distro"
        "${admin[@]}" apt-get update || die "apt-get update failed; check your package mirror"
        if ! command -v dockerd >/dev/null 2>&1; then packages+=(docker.io); fi
        if ! command -v docker >/dev/null 2>&1; then
            # Debian 13 splits the CLI out of docker.io. On releases where
            # docker.io still owns /usr/bin/docker, docker-cli is unavailable.
            if apt-cache show docker-cli >/dev/null 2>&1; then packages+=(docker-cli); fi
        fi
        if ! docker compose version >/dev/null 2>&1; then
            compose_pkg="$(compose_package)" ||
                die "this package repository has no Compose v2 plugin; install it using https://docs.docker.com/compose/install/linux/"
            packages+=("$compose_pkg")
        fi
        "${admin[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" ||
            die "Docker package installation failed; check the apt output above"
    fi

    command -v docker >/dev/null 2>&1 || die "Docker CLI is still unavailable after installation"
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is still unavailable after installation"
    if ! docker info >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1 && ! systemctl is-active --quiet docker; then
            if (( EUID == 0 )); then
                systemctl enable --now docker || die "could not start the Docker service"
            elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
                sudo -n systemctl enable --now docker || die "could not start the Docker service"
            fi
        fi
    fi
    DOCKER=(docker)
    if ! docker info >/dev/null 2>&1; then
        if (( EUID != 0 )) && command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
            DOCKER=(sudo -n docker)
        else
            die "cannot access the Docker daemon; start docker.service and run as root or with passwordless sudo"
        fi
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
        --no-install-docker) AUTO_INSTALL_DOCKER=false; shift ;;
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
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        echo "  Docker      : already installed"
    else
        echo "  Docker      : $([[ "$AUTO_INSTALL_DOCKER" == "true" ]] && echo 'install on Debian/Ubuntu (needs root or passwordless sudo)' || echo 'required before running')"
    fi
    if [[ -f "$DIR/.env" && "$FORCE" != "true" ]]; then
        echo "  existing .env: kept (only WAFRED_IMAGE changes when an image proxy is configured)"
    fi
    exit 0
fi

ensure_docker

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

"${DOCKER[@]}" compose config -q || die "downloaded compose file or .env is invalid"

printf 'Starting WAFred with the image settings in .env\n'
if ! "${DOCKER[@]}" compose up -d; then
    die "docker compose failed. For 'address already in use', choose free host ports in .env (WAFRED_HTTP_PORT, WAFRED_HTTPS_PORT, WAFRED_ADMIN_PORT, WAFRED_GRPC_PORT); for pull errors, check the image source: ${IMAGE_REPO}"
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
