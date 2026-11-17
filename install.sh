#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# WAFred Installation Script
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash -s -- --mode agent --server-url https://... --api-key pwk_...
#   ./install.sh                     # interactive prompts (needs a terminal)
#   ./install.sh [--version X.Y.Z] [--mode all-in-one|server|agent]
#
# Options:
#   --version         Install a specific version (default: latest)
#   --mirror          HTTPS prefix for GitHub API and release downloads
#   --mirror-mode     host-path (default) or full-url
#   --mode            Operating mode: all-in-one, server, agent (default: all-in-one)
#   --server-url      Control plane gRPC URL (agent mode)
#   --api-key         Agent enrollment token (agent mode)
#   --admin-email     Seed administrator e-mail (server / all-in-one)
#   --admin-password  Seed administrator password (omit to generate a random one)
#   --tls-sans        Comma separated names of the dashboard certificate
#   --listen-public   Bind the admin API and gRPC on 0.0.0.0 instead of 127.0.0.1
#   --no-systemd      Skip systemd service creation
#   --interactive     Prompt even when the flags would normally skip the questions
#   --non-interactive Run with the given values and defaults, never prompt
#   --dry-run         Print the resolved plan, then exit without installing
#   --help            Show this help message
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Colors & Helpers ─────────────────────────────────────────────────────────
BOLD="$(tput bold 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

info()    { printf '%s\n' "${BLUE}>${NO_COLOR} $*"; }
success() { printf '%s\n' "${GREEN}✓${NO_COLOR} $*"; }
warn()    { printf '%s\n' "${YELLOW}! $*${NO_COLOR}"; }
error()   { printf '%s\n' "${RED}✗ $*${NO_COLOR}" >&2; }
fatal()   { error "$@"; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

# Host part of a URL, without scheme, credentials, port or path. Handles both
# `host:port` and `[IPv6]:port`, so the warning below can print a usable
# `openssl s_client -connect host:9090` line.
server_host() {
    local rest="${1#*://}"
    rest="${rest%%/*}"
    rest="${rest##*@}"
    if [[ "$rest" == \[* ]]; then
        rest="${rest#[}"
        printf '%s' "${rest%%]*}"
    else
        printf '%s' "${rest%%:*}"
    fi
}

# Loopback control planes are the one place plaintext gRPC is expected.
# `127.*` is deliberately a dotted-quad match, not a prefix: a host like
# `127.evil.com` resolves over DNS and is not loopback.
is_loopback_host() {
    [[ "$1" == "localhost" || "$1" == "::1" ]] && return 0
    [[ "$1" =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# ─── Constants ────────────────────────────────────────────────────────────────
REPO="oyport/wafred"
BINARY_NAME="wafred"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/wafred"
DATA_DIR="/var/lib/wafred"
SERVICE_NAME="wafred"
SUPPORTED_PLATFORMS="linux/amd64 linux/arm64"

normalize_mirror() {
    while [[ "$MIRROR" == */ ]]; do MIRROR="${MIRROR%/}"; done
    [[ "$MIRROR_MODE" == "host-path" || "$MIRROR_MODE" == "full-url" ]] ||
        fatal "--mirror-mode must be host-path or full-url"
    if [[ -z "$MIRROR" ]]; then
        [[ "$MIRROR_MODE" == "host-path" ]] || fatal "--mirror-mode requires --mirror"
        return 0
    fi
    [[ "$MIRROR" =~ ^https://[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9._-]+)*$ ]] ||
        fatal "--mirror must be an HTTPS URL with a lowercase host and optional lowercase path (for example https://mirror.example.com)"
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

# ─── Default Configuration ────────────────────────────────────────────────────
# Empty on purpose: WAFRED_* environment fallbacks are applied after prompts,
# so explicit command-line options take precedence.
VERSION=""
MIRROR=""
MIRROR_MODE=""
MODE=""
SKIP_SYSTEMD=false
DB_URL=""
SERVER_URL=""
SERVER_CA_CERT=""
SERVER_TLS_NAME=""
API_KEY=""
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
TLS_SANS=""
# Bind the admin API / gRPC on all interfaces. Off by default: a fresh install
# with the seeded administrator account must not be reachable from the network
# until the operator has changed its password (or put it behind a proxy).
LISTEN_PUBLIC=false
# Instance key for the at-rest sealing of notification/AI/backup credentials.
# Taken from the environment when set; otherwise generated once and persisted
# in ${CONFIG_DIR}/pingwaf.env (0600). Never rotate it silently: previously
# sealed credentials cannot be opened with a new key.
PINGWAF_SECRET_KEY="${PINGWAF_SECRET_KEY:-}"
ADMIN_PASSWORD_GENERATED=false
DRY_RUN=false
# "" decides from the command line, "true"/"false" are explicit opt-ins.
INTERACTIVE=""
# Any value handed in (flag or WAFRED_* variable) means the caller already made a
# choice, so an unattended run must not start asking questions.
PARAMS_GIVEN=false

# ─── Argument Parsing ─────────────────────────────────────────────────────────
show_help() {
    cat <<EOF
WAFred Installation Script

Usage: $(basename "$0") [OPTIONS]

Running it with no options on a terminal starts the interactive installer;
piping it (curl ... | bash) installs non-interactively with the defaults.
Pass options through the pipe with: bash -s -- <options>

Options:
  --version VERSION        Install a specific version (default: latest release)
  --mirror HTTPS_URL       Prefix GitHub API and release downloads
  --mirror-mode MODE       host-path (default) or full-url
  --mode MODE              Operating mode: all-in-one, server, agent
  --server-url URL         Control plane gRPC URL (agent mode)
  --server-ca-cert PATH    PEM file with the CA that signed the control plane's
                           gRPC certificate (agent mode, https)
  --server-tls-name NAME   Name used for SNI and certificate verification when
                           the certificate has no SAN for the URL host (agent
                           mode, requires a release that knows the flag)
  --api-key KEY            Agent enrollment token (agent mode)
  --db-url URL             PostgreSQL connection string
  --admin-email EMAIL      Seed administrator e-mail (server / all-in-one)
  --admin-password PASS    Seed administrator password. When omitted (and no
                           PINGWAF_ADMIN_PASSWORD) a random password is
                           generated and printed exactly once at the end.
  --tls-sans NAMES         Comma separated dashboard certificate names
  --listen-public          Bind the dashboard/REST API (9080) and the agent
                           gRPC endpoint (9090) on 0.0.0.0. The default is
                           127.0.0.1: expose them only through a reverse proxy
                           or after changing the administrator password.
  --no-systemd             Skip systemd service file creation
  --interactive            Ask the questions even when options were given
  --non-interactive, --yes Never prompt; use the given values and defaults
  --dry-run                Print the resolved plan, then exit without changes
  --help                   Show this help message

Environment Variables:
  WAFRED_VERSION       Same as --version
  WAFRED_MIRROR        Same as --mirror
  WAFRED_MIRROR_MODE   Same as --mirror-mode
  WAFRED_MODE          Same as --mode
  WAFRED_SERVER_URL    Same as --server-url
  WAFRED_SERVER_CA_CERT Same as --server-ca-cert
  WAFRED_SERVER_TLS_NAME Same as --server-tls-name
  WAFRED_API_KEY       Same as --api-key
  WAFRED_DB_URL        Same as --db-url
  WAFRED_ADMIN_EMAIL   Same as --admin-email
  WAFRED_ADMIN_PASSWORD Same as --admin-password
  WAFRED_TLS_SANS      Same as --tls-sans

Examples:
  # Interactive: answer the questions, defaults in brackets
  curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh -o install.sh
  bash install.sh

  # One line, unattended: all-in-one with the defaults
  curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash

  # One line, unattended: a node as an agent pointing at the control plane
  # (the control plane serves gRPC over TLS by default — use https:// and
  # download its CA from Settings -> Control plane HTTPS, then set it in
  # /etc/wafred/wafred.toml as agent.server_ca_cert)
  curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
    | bash -s -- --mode agent --server-url https://10.0.0.1:9090 --api-key pwk_xxx

  # Latest release, custom database and administrator
  ./install.sh --db-url "postgres://user:pass@db:5432/wafred" \
    --admin-email ops@example.com --tls-sans waf.example.com

After installation:
  Config: /etc/wafred/wafred.toml   (edit it, then: systemctl restart wafred)
  Data:   /var/lib/wafred
EOF
}

require_value() { # $1 option name, $2 next argument
    if [[ -z "${2:-}" ]]; then fatal "Option $1 requires a value (use --help for usage)"; fi
    # `--mode --dry-run` would otherwise swallow the next flag as the value.
    case "$2" in
        --*) fatal "Option $1 requires a value, but got another option: $2" ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)        require_value "$1" "${2:-}"; VERSION="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --mirror)         require_value "$1" "${2:-}"; MIRROR="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --mirror-mode)    require_value "$1" "${2:-}"; MIRROR_MODE="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --mode)           require_value "$1" "${2:-}"; MODE="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --db-url)         require_value "$1" "${2:-}"; DB_URL="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --server-url)     require_value "$1" "${2:-}"; SERVER_URL="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --server-ca-cert) require_value "$1" "${2:-}"; SERVER_CA_CERT="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --server-tls-name) require_value "$1" "${2:-}"; SERVER_TLS_NAME="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --api-key)        require_value "$1" "${2:-}"; API_KEY="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --admin-email)    require_value "$1" "${2:-}"; ADMIN_EMAIL="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --admin-password) require_value "$1" "${2:-}"; ADMIN_PASSWORD="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --tls-sans)       require_value "$1" "${2:-}"; TLS_SANS="$2"; PARAMS_GIVEN=true; shift 2 ;;
        --listen-public)  LISTEN_PUBLIC=true; PARAMS_GIVEN=true; shift ;;
        --no-systemd)     SKIP_SYSTEMD=true; shift ;;
        --interactive)    INTERACTIVE=true; shift ;;
        --non-interactive|--yes) INTERACTIVE=false; PARAMS_GIVEN=true; shift ;;
        --dry-run)        DRY_RUN=true; shift ;;
        --help|-h)        show_help; exit 0 ;;
        *)                fatal "Unknown option: $1 (use --help for usage)" ;;
    esac
done

# Environment variable fallbacks. The defaults are applied *after* the prompts,
# so an unanswered question can fall back to them while an explicit flag wins.
VERSION="${VERSION:-${WAFRED_VERSION:-}}"
MIRROR="${MIRROR:-${WAFRED_MIRROR:-}}"
MIRROR_MODE="${MIRROR_MODE:-${WAFRED_MIRROR_MODE:-host-path}}"
normalize_mirror
MODE="${MODE:-${WAFRED_MODE:-}}"
DB_URL="${DB_URL:-${WAFRED_DB_URL:-}}"
# Agent mode reads its settings from the command line or the environment, so
# these are what the systemd unit is built from.
SERVER_URL="${SERVER_URL:-${WAFRED_SERVER_URL:-}}"
SERVER_CA_CERT="${SERVER_CA_CERT:-${WAFRED_SERVER_CA_CERT:-}}"
SERVER_TLS_NAME="${SERVER_TLS_NAME:-${WAFRED_SERVER_TLS_NAME:-}}"
API_KEY="${API_KEY:-${WAFRED_API_KEY:-}}"
ADMIN_EMAIL="${ADMIN_EMAIL:-${WAFRED_ADMIN_EMAIL:-}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${WAFRED_ADMIN_PASSWORD:-}}"
TLS_SANS="${TLS_SANS:-${WAFRED_TLS_SANS:-}}"

# `--version latest` is the documented spelling for "no pin"; the interactive
# prompt already normalises it, the flag path has to do the same or the download
# URL becomes .../download/vlatest/...
if [[ "$VERSION" == "latest" ]]; then VERSION=""; fi

if [[ -n "$VERSION$MIRROR$MODE$DB_URL$SERVER_URL$SERVER_CA_CERT$SERVER_TLS_NAME$API_KEY$ADMIN_EMAIL$ADMIN_PASSWORD$TLS_SANS" ]]; then
    PARAMS_GIVEN=true
fi

# An existing configuration is never rewritten, so the values collected here
# will not be applied — both summaries must say so instead of claiming otherwise.
CONFIG_PRESENT=false
if [[ -f "${CONFIG_DIR}/wafred.toml" ]]; then CONFIG_PRESENT=true; fi

# ─── Interactive Prompts ──────────────────────────────────────────────────────
# Every prompt reads fd 3, never stdin: under `curl | bash` fd 0 is the script
# itself, and consuming it would truncate the run with a syntax error.
PROMPT_FD=3
PROMPT_ON=false

prompt_open_tty() {
    # The braces matter: `exec 3<>/dev/tty 2>/dev/null` would also apply the
    # stderr redirect to the shell permanently, swallowing every prompt and
    # error for the rest of the run.
    if ! { exec 3<>/dev/tty; } 2>/dev/null; then
        return 1
    fi
    return 0
}

prompt_line() { # $1 label, $2 default ("" for none), $3 secret (true/false)
    local label="$1" default_value="$2" secret="${3:-false}"
    local suffix=""
    [[ -n "$default_value" ]] && suffix=" [${default_value}]"

    printf '? %s%s: ' "$label" "$suffix" >&2
    if [[ "$secret" == "true" ]]; then
        if ! IFS= read -r -s -u "$PROMPT_FD" REPLY; then
            printf '\n' >&2
            fatal "Input interrupted while reading: ${label}"
        fi
        printf '\n' >&2
    else
        if ! IFS= read -r -u "$PROMPT_FD" REPLY; then
            fatal "Input interrupted while reading: ${label}"
        fi
    fi

    # Trim surrounding whitespace before applying the default.
    REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
    REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
    [[ -z "$REPLY" ]] && REPLY="$default_value"
    return 0
}

prompt_until() { # $1 label, $2 default, $3 secret, $4 validator
    local label="$1" default_value="$2" secret="${3:-false}" validator="$4"
    local tries=0
    while :; do
        prompt_line "$label" "$default_value" "$secret"
        if "$validator" "$REPLY"; then return 0; fi
        tries=$((tries + 1))
        if (( tries >= 3 )); then
            fatal "Too many invalid answers for: ${label}"
        fi
        warn "That value is not accepted — please try again."
    done
}

validate_mode_input() {
    case "$1" in
        1) REPLY="all-in-one" ;;
        2) REPLY="server" ;;
        3) REPLY="agent" ;;
        all-in-one|server|agent) ;;
        *) return 1 ;;
    esac
    return 0
}

validate_email() { [[ "$1" == *@*.* ]]; }
validate_db_url() { [[ "$1" == postgres://* || "$1" == postgresql://* ]]; }
validate_server_url() { [[ "$1" == http://* || "$1" == https://* ]] && [[ "$1" == *:* ]]; }
validate_required() { [[ -n "$1" ]]; }

validate_yes_no() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        y|yes) REPLY="y" ;;
        n|no)  REPLY="n" ;;
        *)     return 1 ;;
    esac
    return 0
}

# Values below end up inside a TOML basic string and inside systemd
# `Environment=` lines. A stray newline or quote would break the generated file
# at best and inject a unit directive at worst, so control characters are
# rejected outright and the remaining specials are escaped per format.
reject_control_chars() { # $1 label, $2 value
    if [[ "$2" == *[[:cntrl:]]* ]]; then
        fatal "$1 must not contain control characters (newline, tab, ...)"
    fi
}

toml_string() { # $1 raw value -> escaped TOML basic-string body
    local value="${1//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

systemd_env() { # $1 variable name, $2 value -> Environment="NAME=value"
    local value="${2//\\/\\\\}"
    value="${value//\"/\\\"}"
    # Unit files expand % specifiers, so a literal percent must be doubled.
    value="${value//%/%%}"
    printf 'Environment="%s=%s"' "$1" "$value"
}

validate_install_values() {
    reject_control_chars "mode" "$MODE"
    reject_control_chars "--version" "$VERSION"
    reject_control_chars "--db-url" "$DB_URL"
    reject_control_chars "--server-url" "$SERVER_URL"
    reject_control_chars "--server-ca-cert" "$SERVER_CA_CERT"
    reject_control_chars "--server-tls-name" "$SERVER_TLS_NAME"
    reject_control_chars "--api-key" "$API_KEY"
    reject_control_chars "--admin-email" "$ADMIN_EMAIL"
    reject_control_chars "--admin-password" "$ADMIN_PASSWORD"
    reject_control_chars "--tls-sans" "$TLS_SANS"
}

prompt_admin_password() {
    local first second
    for _ in 1 2 3; do
        prompt_line "Administrator password (empty generates a random one, printed once)" "" true
        first="$REPLY"
        if [[ -z "$first" ]]; then
            ADMIN_PASSWORD="wafred123"
            warn "Keeping the documented default password; the console forces a change at first sign-in."
            return 0
        fi
        prompt_line "Repeat administrator password" "" true
        second="$REPLY"
        if [[ "$first" != "$second" ]]; then
            warn "The passwords do not match."
            continue
        fi
        if (( ${#first} < 8 )); then
            warn "Use at least 8 characters."
            continue
        fi
        ADMIN_PASSWORD="$first"
        return 0
    done
    fatal "Too many invalid password attempts."
}

mask_db_url() {
    # Drop the whole userinfo block: a password may itself contain `@` or `:`,
    # which a naive `[^@]*` pattern would leave half-visible.
    printf '%s' "$1" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/]*@#\1***@#'
}

print_plan_summary() {
    local systemd_state="no"
    local password_state="default (wafred123)"
    local api_key_state="unset"

    if [[ "$SKIP_SYSTEMD" != "true" && "${OS:-}" == "linux" ]]; then
        systemd_state="yes (User=wafred, CAP_NET_BIND_SERVICE for 80/443)"
    fi
    if [[ -n "$ADMIN_PASSWORD" && "$ADMIN_PASSWORD" != "wafred123" ]]; then
        password_state="custom"
    fi
    if [[ -n "$API_KEY" ]]; then
        # Never echo key material, not even a prefix: the summary often ends up
        # pasted into an issue or a chat.
        api_key_state="set (${#API_KEY} chars)"
    fi

    echo ""
    echo "${BOLD}Installation plan${NO_COLOR}"
    echo "  mode:        ${MODE:-all-in-one}"
    echo "  version:     ${VERSION:-latest release}"
    echo "  mirror:      ${MIRROR:-none (official GitHub URLs)}"
    if [[ -n "$MIRROR" ]]; then echo "  mirror mode: ${MIRROR_MODE}"; fi
    if [[ -n "${PLATFORM:-}" ]]; then
        echo "  platform:    ${PLATFORM}"
    fi
    echo "  binary:      ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  config:      ${CONFIG_DIR}/wafred.toml"
    echo "  data:        ${DATA_DIR}"
    echo "  systemd:     ${systemd_state}"
    if [[ "${MODE:-all-in-one}" == "agent" ]]; then
        echo "  control:     ${SERVER_URL}"
        echo "  control CA:  ${SERVER_CA_CERT:-none (bundled webpki roots)}"
        echo "  tls name:    ${SERVER_TLS_NAME:-URL host}"
        echo "  api key:     ${api_key_state}"
    else
        echo "  database:    $(mask_db_url "${DB_URL:-postgres://wafred:wafred@localhost:5432/wafred}")"
        echo "  admin:       ${ADMIN_EMAIL:-admin@wafred.local} (password: ${password_state})"
        echo "  tls sans:    ${TLS_SANS:-none (the generated certificate covers the hostname used to reach it)}"
    fi
    if [[ "$CONFIG_PRESENT" == "true" ]]; then
        echo "  ${YELLOW}!${NO_COLOR} ${CONFIG_DIR}/wafred.toml already exists: the admin, TLS and database values above will NOT be written."
    fi
    echo ""
}

run_interactive_prompts() {
    echo ""
    echo "${BOLD}WAFred interactive installer${NO_COLOR}"
    echo "Press Enter to accept the value in brackets."
    echo ""
    echo "Deployment mode:"
    echo "  1) all-in-one  control plane and agent in one process (needs PostgreSQL)"
    echo "  2) server      control plane only"
    echo "  3) agent       data-plane node, connects to a control plane"
    echo ""
    prompt_until "Mode [1-3 or name]" "all-in-one" false validate_mode_input
    MODE="$REPLY"

    if [[ "$MODE" == "agent" ]]; then
        prompt_until "Control plane gRPC URL (https://host:9090)" "$SERVER_URL" false validate_server_url
        SERVER_URL="$REPLY"
        prompt_until "Agent enrollment API key" "" true validate_required
        API_KEY="$REPLY"
    else
        prompt_until "Administrator e-mail" "${ADMIN_EMAIL:-admin@wafred.local}" false validate_email
        ADMIN_EMAIL="$REPLY"
        prompt_admin_password
        prompt_until "PostgreSQL URL" "${DB_URL:-postgres://wafred:wafred@localhost:5432/wafred}" false validate_db_url
        DB_URL="$REPLY"
        prompt_line "Dashboard certificate names (comma separated, empty for none)" "$TLS_SANS" false
        TLS_SANS="${REPLY// /}"
    fi

    prompt_line "Version (empty or 'latest' = latest release)" "${VERSION:-latest}" false
    VERSION="$REPLY"
    if [[ "$VERSION" == "latest" ]]; then VERSION=""; fi

    print_plan_summary
    prompt_until "Continue? [Y/n]" "y" false validate_yes_no
    if [[ "$REPLY" != "y" ]]; then
        info "Aborted — nothing was changed."
        exit 0
    fi
}

decide_interaction() {
    if [[ "$INTERACTIVE" == "true" ]]; then
        if ! prompt_open_tty; then
            fatal "Interactive mode needs a terminal, but /dev/tty is unavailable."
        fi
        PROMPT_ON=true
        return 0
    fi
    if [[ "$INTERACTIVE" == "false" ]]; then return 0; fi
    if [[ "$PARAMS_GIVEN" == "true" ]]; then return 0; fi
    if [[ ! -t 0 ]]; then
        info "No terminal on stdin (curl | bash): installing non-interactively with the defaults."
        info "Pass options through the pipe with: bash -s -- --mode server --db-url ..."
        return 0
    fi
    if ! prompt_open_tty; then return 0; fi
    PROMPT_ON=true
    return 0
}

decide_interaction
if [[ "$PROMPT_ON" == "true" ]]; then
    run_interactive_prompts
fi

MODE="${MODE:-all-in-one}"
DB_URL="${DB_URL:-postgres://wafred:wafred@localhost:5432/wafred}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@wafred.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-wafred123}"
TLS_SANS="${TLS_SANS// /}"

# Validate mode
case "$MODE" in
    all-in-one|server|agent) ;;
    *) fatal "Invalid mode: $MODE (must be: all-in-one, server, agent)" ;;
esac

validate_install_values

# Agents talk to the control plane, never to PostgreSQL.
if [[ "$MODE" == "agent" ]]; then
    SERVER_URL="${SERVER_URL:-http://127.0.0.1:9090}"
    if [[ -z "$API_KEY" ]]; then
        warn "No --api-key given: set WAFRED_API_KEY or pass --api-key, or the agent cannot register."
    fi
    # Schemes are case-insensitive; `HTTP://` must not slip past the warning.
    # `tr` rather than `${var,,}`: macOS ships bash 3.2, which lacks it.
    _cp_scheme="$(printf '%s' "$SERVER_URL" | tr '[:upper:]' '[:lower:]')"
    if [[ "$_cp_scheme" == http:* && -n "$_cp_scheme" ]]; then
        _cp_host="$(server_host "$SERVER_URL")"
        if [[ -z "$_cp_host" ]]; then
            warn "Could not parse a host out of --server-url '${SERVER_URL}'; expected http://host:9090."
        elif is_loopback_host "$_cp_host"; then
            warn "Plain http:// is accepted only because ${_cp_host} is loopback: a control plane on another host serves gRPC over TLS by default."
        else
            warn "Plain http:// to ${_cp_host} fails against a default control plane: the gRPC port serves TLS, so the agent only reports an opaque h2 protocol error."
            warn "  Symptom: journalctl -u wafred shows 'Connection to control plane failed' with FRAME_SIZE_ERROR."
            warn "  Fix:     reinstall with --server-url https://${_cp_host}:9090 --server-ca-cert <control-plane.pem> (add --server-tls-name <SAN> when the certificate does not name ${_cp_host})."
            warn "  Verify:  openssl s_client -connect ${_cp_host}:9090 -servername ${_cp_host} -alpn h2"
        fi
    fi
    if [[ -n "$SERVER_CA_CERT" && ! -r "$SERVER_CA_CERT" ]]; then
        fatal "--server-ca-cert ${SERVER_CA_CERT} is not readable. Download the control plane certificate (Settings -> Control plane HTTPS) and point this option at the PEM file."
    fi
    if [[ -n "$SERVER_TLS_NAME" && -z "$SERVER_CA_CERT" ]]; then
        warn "--server-tls-name only changes certificate verification; the control plane's CA still has to be trusted (use --server-ca-cert)."
    fi
    if [[ -n "$SERVER_TLS_NAME" && "$_cp_scheme" == http:* ]]; then
        warn "--server-tls-name has no effect while --server-url is http:// (TLS is not in use)."
    fi
fi

# ─── Platform Detection ───────────────────────────────────────────────────────
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       fatal "Unsupported operating system: $os" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             fatal "Unsupported architecture: $arch" ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
PLATFORM="${OS}/${ARCH}"

info "Detected platform: ${PLATFORM}"

if [[ "$DRY_RUN" == "true" ]]; then
    print_plan_summary
    info "Dry run: nothing was downloaded, installed or written."
    exit 0
fi

# Secrets used by the generated configuration. The administrator password is
# printed exactly once at the end of a successful install; the instance key is
# written to a 0600 environment file the unit reads (never printed).
if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(random_password)"
    ADMIN_PASSWORD_GENERATED=true
fi
if [[ -z "$PINGWAF_SECRET_KEY" ]]; then
    PINGWAF_SECRET_KEY="$(random_hex 32)"
fi

if [[ "$OS" == "darwin" ]]; then
    fatal "Prebuilt binaries are published for Linux only. On macOS, build from source (see README.md)."
fi

if ! echo "$SUPPORTED_PLATFORMS" | grep -q "$PLATFORM"; then
    fatal "Platform $PLATFORM is not supported. Supported: $SUPPORTED_PLATFORMS"
fi

# ─── Version Resolution ───────────────────────────────────────────────────────
get_latest_version() {
    local url response
    url="$(mirror_url "https://api.github.com/repos/${REPO}/releases/latest")"
    if has curl; then
        response="$(curl -fsSL "$url")" || fatal "Could not fetch the latest release via ${url}. Use --version to bypass the GitHub API."
    elif has wget; then
        response="$(wget -qO- "$url")" || fatal "Could not fetch the latest release via ${url}. Use --version to bypass the GitHub API."
    else
        fatal "Neither curl nor wget found. Please install one of them."
    fi
    printf '%s\n' "$response" |
        sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1
}

if [[ -z "$VERSION" ]]; then
    info "Fetching latest release version..."
    VERSION="$(get_latest_version)"
    if [[ -z "$VERSION" ]]; then
        fatal "Failed to determine latest version. Use --version to specify manually."
    fi
fi

# Strip leading 'v' if present
VERSION="${VERSION#v}"
info "Installing WAFred v${VERSION}"

# ─── Download ─────────────────────────────────────────────────────────────────
# Releases ship both .tar.xz (primary, smaller) and .tar.gz (compatibility
# fallback). Prefer xz; skip straight to .tar.gz when xz(1) is not installed,
# and fall back on a failed download (e.g. releases that predate .tar.xz).

# Verifies one downloaded asset against the published sidecar with
# `sha256sum -c` (or `shasum -a 256 -c` where coreutils is absent).
verify_checksum() {
    local file="$1" sidecar="$2" dir base
    dir="$(dirname "$file")"
    base="$(basename "$sidecar")"
    if has sha256sum; then
        ( cd "$dir" && sha256sum -c "$base" ) >/dev/null 2>&1
    elif has shasum; then
        ( cd "$dir" && shasum -a 256 -c "$base" ) >/dev/null 2>&1
    else
        fatal "Neither sha256sum nor shasum is available; cannot verify the release asset."
    fi
}

# Rejects an archive that would write outside the temp directory (absolute
# paths, `..` components) or that is not the expected single release directory.
verify_archive_members() {
    local archive="$1" list="${TMPDIR}/members.txt" prefix="pingwaf-${OS}-${ARCH}/"
    case "$archive" in
        *.tar.xz) tar -tJf "$archive" > "$list" ;;
        *.tar.gz) tar -tzf "$archive" > "$list" ;;
        *) fatal "Unexpected archive type: ${archive}" ;;
    esac
    if [[ ! -s "$list" ]]; then
        fatal "The archive is empty: $(basename "$archive")"
    fi
    if grep -Eq '(^/|(^|/)\.\.(/|$))' "$list"; then
        fatal "The archive contains an unsafe path (absolute or '..'); refusing to extract it."
    fi
    if grep -v "^${prefix}" "$list" | grep -q .; then
        fatal "The archive contains entries outside '${prefix}'; refusing to extract it."
    fi
}

fetch_asset() {
    local ext url checksum_url expected downloaded
    for ext in tar.xz tar.gz; do
        if [[ "$ext" == "tar.xz" ]] && ! has xz; then
            info "xz(1) not found — falling back to the .tar.gz asset."
            continue
        fi
        ASSET_NAME="wafred-${OS}-${ARCH}.${ext}"
        url="$(mirror_url "https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET_NAME}")"
        info "Downloading ${ASSET_NAME}..."
        info "URL: ${url}"
        downloaded=false
        if has curl; then
            if curl -fsSL --proto '=https' "$url" -o "${TMPDIR}/${ASSET_NAME}" \
                && curl -fsSL --proto '=https' "$checksum_url" -o "${TMPDIR}/${ASSET_NAME}.sha256"; then
                downloaded=true
            fi
        elif has wget; then
            if wget -q "$url" -O "${TMPDIR}/${ASSET_NAME}" \
                && wget -q "$checksum_url" -O "${TMPDIR}/${ASSET_NAME}.sha256"; then
                downloaded=true
            fi
        else
            fatal "Neither curl nor wget found. Please install one of them."
        fi
        if [[ "$downloaded" != "true" ]]; then
            warn "Download failed for ${ASSET_NAME} (asset or its .sha256) — trying the next format."
            continue
        fi
        # Every release ships a .sha256 sidecar; a missing, malformed or
        # mismatching one is fatal. Nothing is extracted or executed before
        # this check passes.
        expected="$(awk 'NR == 1 { print $1 }' "${TMPDIR}/${ASSET_NAME}.sha256")"
        if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
            fatal "The .sha256 sidecar for ${ASSET_NAME} is missing or malformed; refusing to install."
        fi
        if ! verify_checksum "${TMPDIR}/${ASSET_NAME}" "${TMPDIR}/${ASSET_NAME}.sha256"; then
            fatal "Checksum mismatch for ${ASSET_NAME} (published: ${expected}). Refusing to install."
        fi
        success "Verified the sha256 of ${ASSET_NAME}."
        return 0
    done
    fatal "Download failed. Check that version v${VERSION} exists and has a wafred-${OS}-${ARCH} asset."
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ASSET_NAME=""
fetch_asset

# ─── Extract & Install Binary ─────────────────────────────────────────────────
# The checksum has already been verified; still refuse archives whose member
# paths could escape the temp directory before tar touches the filesystem.
verify_archive_members "${TMPDIR}/${ASSET_NAME}"

info "Extracting..."
case "$ASSET_NAME" in
    *.tar.xz) tar -xJf "${TMPDIR}/${ASSET_NAME}" -C "$TMPDIR" ;;
    *.tar.gz) tar -xzf "${TMPDIR}/${ASSET_NAME}" -C "$TMPDIR" ;;
    *)        fatal "Unexpected asset name: ${ASSET_NAME}" ;;
esac

# The release archive contains exactly one binary with this name. There is no
# "first executable" fallback: an unexpected archive layout is an error, not an
# invitation to install an arbitrary file.
BINARY_PATH="$(find "${TMPDIR}/pingwaf-${OS}-${ARCH}" -name "$BINARY_NAME" -type f | head -n1)"
if [[ -z "$BINARY_PATH" ]]; then
    fatal "Binary '${BINARY_NAME}' not found in the verified archive."
fi

chmod +x "$BINARY_PATH"

# The release binaries are linked against the glibc of the runner that built
# them (Ubuntu 24.04 today), so an older distro gets as far as systemd before
# failing with a versioned-symbol error. Catch that here instead, while the
# message can still name the cause.
if ! "$BINARY_PATH" --version >/dev/null 2>&1; then
    smoke_error="$("$BINARY_PATH" --version 2>&1 | head -n1 || true)"
    fatal "The downloaded binary cannot run on this system: ${smoke_error}
       Release assets are built on Ubuntu 24.04 and need glibc 2.39 or newer.
       On older distributions (CentOS/RHEL, Debian 11, Ubuntu 20.04, Alpine,
       ...) build from source instead: https://github.com/${REPO}/blob/main/docs/quick-start.md#path-2-build-from-source"
fi

info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
# The binary must be root-owned: it is executed by the systemd unit (as the
# unprivileged pingwaf user) and may be run by an operator. `mv` preserves the
# installing user's ownership, so the owner/mode are normalised afterwards.
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
    if [[ "$(id -u)" -eq 0 ]]; then
        chown root:root "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    else
        warn "Installed as the current user; run: sudo chown root:root ${INSTALL_DIR}/${BINARY_NAME} && sudo chmod 0755 ${INSTALL_DIR}/${BINARY_NAME}"
    fi
    chmod 0755 "${INSTALL_DIR}/${BINARY_NAME}"
elif has sudo; then
    sudo mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chown root:root "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod 0755 "${INSTALL_DIR}/${BINARY_NAME}"
else
    fatal "No write permission to ${INSTALL_DIR} and sudo not available."
fi

success "Binary installed: ${INSTALL_DIR}/${BINARY_NAME}"

# ─── Create Directories ───────────────────────────────────────────────────────
create_dirs() {
    local cmd=""
    if [[ -w "/" ]]; then
        cmd=""
    elif has sudo; then
        cmd="sudo"
    else
        warn "Cannot create system directories without sudo."
        return
    fi

    $cmd mkdir -p "$CONFIG_DIR" "$DATA_DIR" "${DATA_DIR}/cache" "${DATA_DIR}/certs"

    # Create the service account if on Linux.
    if [[ "$OS" == "linux" ]]; then
        if ! id -u wafred >/dev/null 2>&1; then
            $cmd useradd -r -m -d "$DATA_DIR" -s /usr/sbin/nologin wafred 2>/dev/null || \
            $cmd adduser -r -d "$DATA_DIR" -s /sbin/nologin wafred 2>/dev/null || true
        fi
        $cmd chown -R wafred:wafred "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || true
    fi
}

if [[ "$OS" == "linux" ]]; then
    info "Creating directories..."
    create_dirs
    success "Created ${CONFIG_DIR} and ${DATA_DIR}"
fi

# ─── Write Default Configuration ─────────────────────────────────────────────
write_config() {
    local config_file="${CONFIG_DIR}/wafred.toml"
    if [[ -f "$config_file" ]]; then
        warn "Config file already exists at ${config_file}, leaving it untouched."
        if grep -q '^admin_password = "pingwaf123"' "$config_file" 2>/dev/null; then
            warn "WARNING: ${config_file} still uses the public default administrator password."
            warn "Change it now: pingwaf user reset-password --email ${ADMIN_EMAIL} (or via the dashboard)."
        fi
        warn "Values from this run (control-plane URL, API key, admin account, TLS names,"
        warn "database) were not applied. In agent mode this file is authoritative:"
        warn "edit ${config_file} and run: sudo systemctl restart ${SERVICE_NAME}"
        if [[ "$MODE" == "agent" ]]; then
            local key_state="unset"
            if [[ -n "$API_KEY" ]]; then key_state="set"; fi
            warn "Requested agent settings that were NOT applied: server_url=${SERVER_URL:-unset} api_key=${key_state} server_ca_cert=${SERVER_CA_CERT:-unset} server_tls_name=${SERVER_TLS_NAME:-unset}"
            warn "Put them under [agent] in ${config_file} instead."
        fi
        return
    fi

    local cmd=""
    [[ -w "$CONFIG_DIR" ]] || cmd="sudo"

    # Keys are the command-line flags with dashes replaced by underscores, and
    # the file only fills in what the environment and the command line leave
    # alone (see docs/deployment.md). Settings without a flag — registration,
    # CORS, Elasticsearch, passkeys — stay in the environment.
    local agent_server_url="# agent mode only; all-in-one talks to its own loopback gRPC"
    local agent_api_key="# api_key = \"pwk_...\""
    local agent_ca_cert="# server_ca_cert = \"/etc/wafred/grpc-ca.pem\""
    local agent_tls_name="# server_tls_name = \"control-plane\""
    if [[ "$MODE" == "agent" ]]; then
        agent_server_url="server_url = \"$(toml_string "$SERVER_URL")\""
        # The node's credentials live in this file only. The unit used to carry
        # them as well, and the environment silently beat the file, so an
        # operator editing the file saw no effect.
        if [[ -n "$API_KEY" ]]; then
            agent_api_key="api_key = \"$(toml_string "$API_KEY")\""
        fi
        if [[ -n "$SERVER_CA_CERT" ]]; then
            agent_ca_cert="server_ca_cert = \"$(toml_string "$SERVER_CA_CERT")\""
        fi
        if [[ -n "$SERVER_TLS_NAME" ]]; then
            agent_tls_name="server_tls_name = \"$(toml_string "$SERVER_TLS_NAME")\""
        fi
    fi

    # Loopback by default: a fresh install still has the seeded administrator
    # account, so the API/gRPC must not be reachable from the network until the
    # password has been changed (or the operator opts into --listen-public /
    # puts the console behind a reverse proxy).
    local admin_addr="127.0.0.1:9080" grpc_addr="127.0.0.1:9090"
    if [[ "$LISTEN_PUBLIC" == "true" ]]; then
        admin_addr="0.0.0.0:9080"
        grpc_addr="0.0.0.0:9090"
    fi

    local tls_sans_line="# tls_sans = [\"waf.example.com\"]"
    if [[ -n "$TLS_SANS" ]]; then
        local sans_entry sans_joined=""
        local IFS=','
        for sans_entry in $TLS_SANS; do
            [[ -n "$sans_entry" ]] || continue
            [[ -n "$sans_joined" ]] && sans_joined+=", "
            sans_joined+="\"$(toml_string "$sans_entry")\""
        done
        unset IFS
        tls_sans_line="tls_sans = [${sans_joined}]"
    fi

    # `umask 077` for the write itself: tee creates the file 0644 under the
    # default umask, and it holds the admin password and the JWT secret.
    (umask 077; $cmd tee "$config_file" >/dev/null <<EOF
# WAFred Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Mode: ${MODE}
#
# This file is read when WAFRED_CONFIG points at it (the systemd unit sets
# that). In agent mode this file is the source of truth: it wins over
# WAFRED_* environment variables, while command-line flags still win. Server
# and all-in-one keep the environment as an override. Unknown keys are reported
# at startup and ignored.

[server]
db_url = "$(toml_string "$DB_URL")"
# Admin API + gRPC listen on loopback unless --listen-public was given; agents
# on other hosts and remote dashboards need an explicit choice (or a proxy).
admin_addr = "${admin_addr}"
grpc_addr = "${grpc_addr}"
# gRPC control plane TLS: "tls" (default) serves agents over TLS, reusing the
# dashboard certificate — self-signed on first boot unless grpc_tls_cert/key
# are configured. "off" serves plaintext and is logged as degraded.
# grpc_tls_mode = "tls"
# Dashboard + REST API over HTTPS (passkeys require a secure origin).
# A self-signed certificate is generated on first boot; upload a real one in
# Settings -> Control plane HTTPS. Add the hostname you use to reach the
# dashboard so the generated certificate covers it:
${tls_sans_line}
tls_enabled = true
jwt_secret = "$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
admin_email = "$(toml_string "$ADMIN_EMAIL")"
admin_password = "$(toml_string "$ADMIN_PASSWORD")"
serve_frontend = true

# Used by the all-in-one mode and by agents; a server ignores this section.
[agent]
${agent_server_url}
${agent_api_key}
${agent_ca_cert}
${agent_tls_name}
cache_dir = "${DATA_DIR}/cache"
heartbeat_interval_secs = 30
log_batch_size = 100
log_flush_interval_secs = 5
max_body_log_size = 8192
fail_open = true
metrics_ship_interval_secs = 30

# Everything else comes from the environment, e.g.
#   WAFRED_ALLOW_REGISTRATION=false     WAFRED_CORS_ORIGINS=https://ui.example.com
#   WAFRED_JWT_EXPIRATION_HOURS=12      WAFRED_DB_MAX_CONNECTIONS=20
#   WAFRED_METRIC_RETENTION_DAYS=30     WAFRED_WEBHOOK_URL=https://hooks.example.com
#   WAFRED_PASSKEY_ENABLED=true         WAFRED_ES_ENABLED=true
EOF
    )

    # Not behind `if [[ -n "$cmd" ]]`: a root install has no sudo wrapper, and
    # skipping the branch left the file with the seeded admin password and the
    # JWT secret readable by every local user (0644, owned by root). It must be
    # wafred-owned as well, because the unit runs as User=wafred.
    if ! $cmd chown wafred:wafred "$config_file" 2>/dev/null; then
        warn "Could not hand ${config_file} to wafred:wafred — does the user exist?"
    fi
    if ! $cmd chmod 0640 "$config_file" 2>/dev/null; then
        warn "Could not chmod 0640 ${config_file}; it may stay readable by other local users."
    fi

    success "Configuration written to ${config_file}"
}

# Writes the instance secret key (env-only setting) to a 0600 environment file
# that the systemd unit reads. An existing key is kept: rotating it silently
# would make every previously sealed notification/AI/backup credential
# unreadable, and there is no automatic re-encryption.
write_secret_env_file() {
    local env_file="${CONFIG_DIR}/pingwaf.env" cmd=""
    [[ -w "$CONFIG_DIR" ]] || cmd="sudo"

    if [[ -f "$env_file" ]] && grep -q '^PINGWAF_SECRET_KEY=' "$env_file" 2>/dev/null; then
        info "Keeping the existing ${env_file} (rotating it would break sealed credentials)."
        return 0
    fi

    (umask 077; $cmd tee "$env_file" >/dev/null <<EOF
# PingWAF environment secrets — mode 0600, read by the systemd unit.
#
# PINGWAF_SECRET_KEY seals notification channel / AI provider / backup target
# credentials at rest. Treat this file like the database itself: rotating the
# key makes previously sealed credentials unreadable (there is no automatic
# re-encryption), so back it up and do not regenerate it on upgrade.
PINGWAF_SECRET_KEY=${PINGWAF_SECRET_KEY}
EOF
    )
    # systemd reads EnvironmentFile as root before dropping to User=pingwaf, so
    # the instance key stays root-only: the service process never needs to read
    # this file itself.
    if ! $cmd chown root:root "$env_file" 2>/dev/null; then
        warn "Could not hand ${env_file} to root:root."
    fi
    if ! $cmd chmod 0600 "$env_file" 2>/dev/null; then
        warn "Could not chmod 0600 ${env_file}; it may stay readable by other local users."
    fi
    success "Instance secret key written to ${env_file} (0600)"
}

if [[ "$OS" == "linux" ]]; then
    write_config
    write_secret_env_file
fi

# ─── Systemd Service ──────────────────────────────────────────────────────────
# An upgrade run (`--no-systemd`) replaces the binary but leaves the unit alone,
# so a unit written before CAP_NET_BIND_SERVICE was granted keeps failing to
# bind 80/443. Point the operator at the drop-in instead of pretending the
# upgrade fixed it. `setcap` is not an alternative here: the unit sets
# NoNewPrivileges=true, which makes the kernel ignore file capabilities.
check_unit_capabilities() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local dropin_dir="/etc/systemd/system/${SERVICE_NAME}.service.d"
    local granted=false conf

    if [[ -f "$unit_file" ]]; then
        if [[ -r "$unit_file" ]]; then
            if grep -q '^AmbientCapabilities=.*CAP_NET_BIND_SERVICE' "$unit_file"; then
                granted=true
            fi
        elif has sudo; then
            # The unit is written 0600 (it can carry the agent API key), so a
            # non-root upgrade run has to inspect it through sudo.
            if sudo grep -q '^AmbientCapabilities=.*CAP_NET_BIND_SERVICE' "$unit_file" 2>/dev/null; then
                granted=true
            fi
        else
            # Cannot read the unit: do not claim the capability is missing.
            return 0
        fi
    fi
    # `systemctl edit` writes a drop-in, which the main unit file never shows.
    if [[ -d "$dropin_dir" ]]; then
        for conf in "$dropin_dir"/*.conf; do
            [[ -r "$conf" ]] || continue
            if grep -q '^AmbientCapabilities=.*CAP_NET_BIND_SERVICE' "$conf"; then
                granted=true
            fi
        done
    fi
    [[ -f "$unit_file" ]] || return 0
    [[ "$granted" == "true" ]] && return 0
    warn "The existing unit does not grant CAP_NET_BIND_SERVICE: binding 80/443 will fail with \"Permission denied\" (bind() failed on 0.0.0.0:443)."
    echo "  Add it with: sudo systemctl edit ${SERVICE_NAME}"
    echo "    [Service]"
    echo "    AmbientCapabilities=CAP_NET_BIND_SERVICE"
    echo "    CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
}

install_systemd() {
    if [[ "$SKIP_SYSTEMD" == "true" ]]; then
        info "Skipping systemd service installation (--no-systemd)."
        check_unit_capabilities
        return
    fi

    if [[ "$OS" != "linux" ]]; then
        info "macOS detected — skipping systemd. Use launchd or run directly."
        return
    fi

    if ! has systemctl; then
        warn "systemctl not found — skipping service installation."
        return
    fi

    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local exec_start="${INSTALL_DIR}/${BINARY_NAME} ${MODE}"

    # Settings come from the generated file first, then these environment
    # variables, then the unit's command line. There is no SIGHUP reload: a
    # changed unit or config file takes effect with `systemctl restart`.
    local unit_after="After=network.target postgresql.service"
    local unit_wants="Wants=postgresql.service"
    # Every value is quoted and escaped: an `Environment=` line ends at the
    # newline, so an unescaped key would inject further unit directives.
    local agent_env
    agent_env="$(systemd_env WAFRED_CONFIG "${CONFIG_DIR}/wafred.toml")"
    if [[ "$MODE" == "agent" ]]; then
        unit_after="After=network-online.target"
        unit_wants="Wants=network-online.target"
        # A fresh install keeps the agent settings in the file only: two
        # copies meant the environment silently beat the file, so editing
        # /etc/wafred/wafred.toml did nothing. An existing file was written
        # by an older installer and may have no api_key, so keep the
        # environment as a fallback for it.
        if [[ "$CONFIG_PRESENT" == "true" ]]; then
            agent_env="${agent_env}
$(systemd_env WAFRED_SERVER_URL "$SERVER_URL")
$(systemd_env WAFRED_API_KEY "$API_KEY")
$(systemd_env WAFRED_CACHE_DIR "${DATA_DIR}/cache")"
            # The keys this installer newly understands may not exist in a file
            # written by an older version; the environment carries them until
            # the operator moves them into [agent].
            if [[ -n "$SERVER_CA_CERT" ]]; then
                agent_env="${agent_env}
$(systemd_env WAFRED_SERVER_CA_CERT "$SERVER_CA_CERT")"
            fi
            if [[ -n "$SERVER_TLS_NAME" ]]; then
                agent_env="${agent_env}
$(systemd_env WAFRED_SERVER_TLS_NAME "$SERVER_TLS_NAME")"
            fi
        fi
    else
        # The dashboard is served over HTTPS with a self-signed certificate
        # until a real one is uploaded. Add the hostname it is reached under so
        # the generated certificate covers it:
        # Environment=WAFRED_TLS_SANS=waf.red
        agent_env="${agent_env}
$(systemd_env WAFRED_TLS_ENABLED "true")"
    fi

    info "Creating systemd service..."

    local cmd=""
    [[ -w "/etc/systemd/system" ]] || cmd="sudo"

    # The unit can carry the agent enrollment key (upgrade path), so it is
    # written private (0600) and only readable by root.
    (umask 077; $cmd tee "$service_file" >/dev/null <<EOF
[Unit]
Description=WAFred - High Performance Web Application Firewall
Documentation=https://github.com/${REPO}
${unit_after}
${unit_wants}

[Service]
Type=simple
User=wafred
Group=wafred
ExecStart=${exec_start}
Restart=always
RestartSec=5
LimitNOFILE=65536
${agent_env}
# Log level; the default keeps sqlx's per-statement log out of the way:
Environment=RUST_LOG=info,sqlx=warn
# Instance secrets (PINGWAF_SECRET_KEY) live in a 0600 file; the leading dash
# keeps the unit working when the file does not exist (e.g. an agent node).
EnvironmentFile=-${CONFIG_DIR}/pingwaf.env

# The data plane binds 80/443 while running as the unprivileged wafred user.
# Ambient capabilities are the only form that survives NoNewPrivileges=true;
# the bounding set is narrowed to the same bit so nothing else can be regained.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    )
    if ! $cmd chmod 600 "$service_file" 2>/dev/null; then
        warn "Could not chmod 600 ${service_file}; it may be readable by other local users."
    fi

    $cmd systemctl daemon-reload
    success "Systemd service installed: ${SERVICE_NAME}.service"

    # An agent only contributes once it is running, so start it here — this is
    # what makes the dashboard's one-line enrolment command enough on its own.
    # Server modes stay manual: they need PostgreSQL ready and an attended
    # first boot.
    if [[ "$MODE" == "agent" ]]; then
        info "Starting the agent service..."
        if $cmd systemctl enable --now "$SERVICE_NAME"; then
            success "Service enabled and started: ${SERVICE_NAME}"
        else
            warn "The service did not start — inspect: journalctl -u ${SERVICE_NAME} -e"
            warn "After fixing, start it with: sudo systemctl enable --now ${SERVICE_NAME}"
        fi
        return
    fi

    info "To start WAFred:"
    echo "  sudo systemctl enable --now ${SERVICE_NAME}"
    echo "  sudo systemctl status ${SERVICE_NAME}"
}

install_systemd

# ─── PostgreSQL Check ─────────────────────────────────────────────────────────
check_postgres() {
    info "Checking PostgreSQL availability..."

    if has psql; then
        if postgres_reachable "$DB_URL"; then
            success "PostgreSQL connection successful."
        else
            # Never echo the connection string: it carries the DB password.
            warn "psql found but cannot connect to: $(mask_db_url "$DB_URL")"
            echo ""
            echo "  To set up PostgreSQL:"
            echo "    1. Install: sudo apt install postgresql-16"
            echo "    2. Create user & database:"
            echo "       sudo -u postgres createuser wafred"
            echo "       sudo -u postgres createdb -O wafred wafred"
            echo "       sudo -u postgres psql -c \"ALTER USER wafred PASSWORD 'wafred';\""
            echo ""
        fi
    else
        warn "PostgreSQL client (psql) not found."
        echo ""
        echo "  WAFred requires PostgreSQL 14+. Install it with:"
        echo ""
        if [[ "$OS" == "linux" ]]; then
            if has apt-get; then
                echo "    sudo apt install postgresql-16"
            elif has dnf; then
                echo "    sudo dnf install postgresql-server"
            elif has yum; then
                echo "    sudo yum install postgresql-server"
            else
                echo "    (install PostgreSQL from your distribution's package manager)"
            fi
        else
            echo "    brew install postgresql@16"
        fi
        echo ""
        echo "  Then create the database:"
        echo "    sudo -u postgres createuser wafred"
        echo "    sudo -u postgres createdb -O wafred wafred"
        echo "    sudo -u postgres psql -c \"ALTER USER wafred PASSWORD 'wafred';\""
        echo ""
    fi
}

if [[ "$MODE" == "agent" ]]; then
    info "Agent mode: skipping the PostgreSQL check, nodes keep no database."
else
    check_postgres
fi

# ─── Firewall Hints ───────────────────────────────────────────────────────────
print_firewall_hints() {
    if [[ "$OS" != "linux" ]]; then return; fi

    echo ""
    if [[ "$MODE" == "agent" ]]; then
        info "Firewall ports:"
        echo "    80/tcp   — HTTP traffic (proxied sites)"
        echo "    443/tcp  — HTTPS traffic (proxied sites)"
        echo "  Outbound to the control plane (${SERVER_URL}) must be allowed."
        echo "  80/443 are bound as User=wafred through the unit's CAP_NET_BIND_SERVICE — no root needed."
        echo ""
        if has ufw; then
            echo "  With UFW:"
            echo "    sudo ufw allow 80/tcp"
            echo "    sudo ufw allow 443/tcp"
        fi
        return
    fi

    info "Firewall ports:"
    echo "    80/tcp   — HTTP traffic (proxied sites)"
    echo "    443/tcp  — HTTPS traffic (proxied sites)"
    echo "    9080/tcp — Admin dashboard & REST API (HTTPS) — management network only"
    echo "    9090/tcp — gRPC control plane (agent connections) — only if agents are remote"
    echo ""
    echo "  Do NOT expose 9080/9090 before the administrator password has been"
    echo "  changed. The generated config binds both to 127.0.0.1 by default;"
    echo "  reinstall with --listen-public only when a proxy/remote agents need it."
    echo ""
    if has ufw; then
        echo "  With UFW (business ports):"
        echo "    sudo ufw allow 80/tcp"
        echo "    sudo ufw allow 443/tcp"
        echo "  For the management ports, restrict the source instead of opening them:"
        echo "    sudo ufw allow from <admin-cidr> to any port 9080 proto tcp"
        echo "    sudo ufw allow from <agent-cidr> to any port 9090 proto tcp"
    fi
}

print_firewall_hints

# ─── Success ──────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NO_COLOR}"
echo "${BOLD}${GREEN}  WAFred v${VERSION} installed successfully!${NO_COLOR}"
echo "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NO_COLOR}"
echo ""
echo "  Binary:    ${INSTALL_DIR}/${BINARY_NAME}"
if [[ "$OS" == "linux" ]]; then
    echo "  Config:    ${CONFIG_DIR}/wafred.toml"
    echo "  Data:      ${DATA_DIR}/"
    echo "  Service:   systemctl {start|stop|restart|status} ${SERVICE_NAME}"
fi

if [[ "$MODE" == "agent" ]]; then
    echo ""
    echo "  Next steps:"
    echo "    1. Confirm the node appears under Nodes in the dashboard"
    if [[ "$OS" == "linux" ]]; then
        echo "    2. If it does not: systemctl status ${SERVICE_NAME} && journalctl -u ${SERVICE_NAME} -e"
    else
        echo "    2. If it does not, run the agent in the foreground to see the error"
    fi
    echo "    3. Point another control plane at it by editing ${CONFIG_DIR}/wafred.toml"
    echo ""
else
    echo ""
    echo "  Quick start:"
    echo "    ${BINARY_NAME} ${MODE} --db-url \"${DB_URL}\""
    echo ""
    echo "  Dashboard: https://localhost:9080  (self-signed certificate)"
    if [[ "$LISTEN_PUBLIC" == "true" ]]; then
        echo "  ${YELLOW}⚠ Admin/gRPC listen on 0.0.0.0 — change the password and restrict 9080/9090 to an admin network before exposing them.${NO_COLOR}"
    else
        echo "  Listen:    127.0.0.1 only (admin 9080 / gRPC 9090); use --listen-public for remote agents or a dashboard proxy"
    fi
    if [[ "$CONFIG_PRESENT" == "true" ]]; then
        echo "  Administrator: unchanged — ${CONFIG_DIR}/wafred.toml was left as it was."
    else
        echo "  Administrator:"
        echo "    Email:    ${ADMIN_EMAIL}"
        if [[ "$ADMIN_PASSWORD" == "wafred123" ]]; then
            echo "    Password: wafred123 (the default — the console forces a change at first sign-in)"
        else
            echo "    Password: (the value you supplied, stored in ${CONFIG_DIR}/wafred.toml)"
        fi
    fi
    echo ""
    if [[ "$OS" == "linux" && "$SKIP_SYSTEMD" != "true" ]]; then
        echo "  Ports 80/443 are bound by User=wafred through the unit's"
        echo "  CAP_NET_BIND_SERVICE capability. Verify with:"
        echo "    systemctl show ${SERVICE_NAME} -p AmbientCapabilities"
        echo ""
    fi
    if [[ "$ADMIN_PASSWORD_GENERATED" == "true" ]]; then
        echo "  ${YELLOW}⚠ Save the generated administrator password now: it is not shown again.${NO_COLOR}"
    fi
    echo "  ${YELLOW}⚠ Back up ${CONFIG_DIR}/pingwaf.toml and ${CONFIG_DIR}/pingwaf.env.${NO_COLOR}"
    echo "  ${YELLOW}   Do NOT regenerate the JWT secret or PINGWAF_SECRET_KEY: previously sealed${NO_COLOR}"
    echo "  ${YELLOW}   credentials become unreadable and sessions are invalidated. Change the${NO_COLOR}"
    echo "  ${YELLOW}   administrator password from the dashboard (Settings → Account) instead.${NO_COLOR}"
    echo ""
    echo "  Next steps:"
    echo "    1. Ensure PostgreSQL is running and accessible"
    echo "    2. Edit ${CONFIG_DIR}/wafred.toml, then: sudo systemctl restart ${SERVICE_NAME}"
    echo "    3. Start the service: sudo systemctl enable --now ${SERVICE_NAME}"
    echo "    4. Open the dashboard and add your first site"
    echo ""
    echo "  Upgrade / rollback / uninstall:"
    echo "    Upgrade:   re-run this installer with --version <new>; the config and the"
    echo "               secrets in ${CONFIG_DIR} are kept. Then: sudo systemctl restart ${SERVICE_NAME}"
    echo "    Rollback:  re-run with --version <previous> (older releases stay on GitHub),"
    echo "               then: sudo systemctl restart ${SERVICE_NAME}"
    echo "    Backup:    sudo tar -czf pingwaf-config-\$(date +%F).tgz -C / etc/pingwaf"
    echo "               sudo chmod 600 pingwaf-config-*.tgz   # it holds the admin password and keys"
    echo "    Uninstall: sudo systemctl disable --now ${SERVICE_NAME}"
    echo "               sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service"
    echo "               sudo rm -f ${INSTALL_DIR}/${BINARY_NAME}"
    echo "               keep (or back up) ${CONFIG_DIR} and ${DATA_DIR}; remove the account with:"
    echo "               sudo userdel pingwaf"
    echo "    Never delete ${DATA_DIR} or drop the database before taking a backup."
    echo ""
fi
