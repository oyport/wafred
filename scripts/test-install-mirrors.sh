#!/usr/bin/env bash
# Exercise URL mapping and .env preservation without network, Docker, or root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

bash -n "$ROOT/install.sh"
bash -n "$ROOT/deploy/compose/install.sh"

assert_contains() {
    [[ "$1" == *"$2"* ]] || { printf 'missing: %s\n' "$2" >&2; exit 1; }
}

host_plan="$(bash "$ROOT/deploy/compose/install.sh" --mirror https://mirror.example.com/ --dry-run)"
assert_contains "$host_plan" 'https://mirror.example.com/raw.githubusercontent.com/oyport/wafred/main/docker-compose.yml'
assert_contains "$host_plan" 'mirror.example.com/ghcr.io/oyport/wafred:latest'

full_plan="$(bash "$ROOT/deploy/compose/install.sh" --mirror https://gh-proxy.org --mirror-mode full-url --image-mirror https://gh-proxy.org/docker/ --dry-run)"
assert_contains "$full_plan" 'https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/docker-compose.yml'
assert_contains "$full_plan" 'gh-proxy.org/docker/ghcr.io/oyport/wafred:latest'

binary_plan="$(bash "$ROOT/install.sh" --mode agent --mirror https://gh-proxy.org --mirror-mode full-url --dry-run)"
assert_contains "$binary_plan" 'mirror:      https://gh-proxy.org'
assert_contains "$binary_plan" 'mirror mode: full-url'

env_plan="$(WAFRED_MIRROR=https://gh-proxy.org WAFRED_MIRROR_MODE=full-url \
    bash "$ROOT/install.sh" --mode agent --dry-run)"
assert_contains "$env_plan" 'mirror mode: full-url'
compose_env_plan="$(WAFRED_MIRROR=https://gh-proxy.org WAFRED_MIRROR_MODE=full-url \
    WAFRED_IMAGE_MIRROR=https://gh-proxy.org/docker \
    bash "$ROOT/deploy/compose/install.sh" --dry-run)"
assert_contains "$compose_env_plan" 'gh-proxy.org/docker/ghcr.io/oyport/wafred:latest'

if bash "$ROOT/deploy/compose/install.sh" --mirror http://mirror.example.com --dry-run >/dev/null 2>&1; then
    echo 'accepted insecure mirror' >&2; exit 1
fi
if bash "$ROOT/install.sh" --mirror-mode full-url --dry-run >/dev/null 2>&1; then
    echo 'accepted mirror mode without mirror' >&2; exit 1
fi

mkdir -p "$TMP/bin"
cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
url='' output=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) output="$2"; shift 2 ;;
        https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
printf 'curl %s\n' "$url" >> "$MOCK_LOG"
if [[ -n "$output" && "$url" == *docker-compose.yml ]]; then
    cp "$FIXTURE_COMPOSE" "$output"
elif [[ "$url" == *api.github.com* ]]; then
    # A compact API response may have later string fields on the same line.
    printf '{"tag_name":"v1.0.0","name":"not-the-version"}\n'
else
    exit 22
fi
EOF
cat > "$TMP/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
[[ "$1" == compose ]]
EOF
chmod +x "$TMP/bin/curl" "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" MOCK_LOG="$TMP/requests.log" FIXTURE_COMPOSE="$ROOT/docker-compose.yml"

bash "$ROOT/deploy/compose/install.sh" --dir "$TMP/compose" --admin-password custom-secret \
    --mirror https://gh-proxy.org --mirror-mode full-url \
    --image-mirror https://gh-proxy.org/docker >/dev/null
grep -Fq 'curl https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/docker-compose.yml' "$MOCK_LOG"
grep -Fq 'WAFRED_IMAGE=gh-proxy.org/docker/ghcr.io/oyport/wafred' "$TMP/compose/.env"
grep -Fq 'WAFRED_ADMIN_PASSWORD=custom-secret' "$TMP/compose/.env"
grep -Fq 'docker compose up -d' "$MOCK_LOG"

bash "$ROOT/deploy/compose/install.sh" --dir "$TMP/compose" \
    --image-mirror https://second.example.com/registry >/dev/null
grep -Fq 'WAFRED_IMAGE=second.example.com/registry/ghcr.io/oyport/wafred' "$TMP/compose/.env"
grep -Fq 'WAFRED_ADMIN_PASSWORD=custom-secret' "$TMP/compose/.env"
[[ "$(grep -c '^WAFRED_IMAGE=' "$TMP/compose/.env")" == 1 ]]

bash "$ROOT/deploy/compose/install.sh" --dir "$TMP/default" >/dev/null
if grep -q '^WAFRED_IMAGE=' "$TMP/default/.env"; then
    echo 'default install unexpectedly uses a mirror' >&2; exit 1
fi

: > "$MOCK_LOG"
if bash "$ROOT/install.sh" --mode agent --mirror https://gh-proxy.org \
    --mirror-mode full-url --no-systemd >/dev/null 2>&1; then
    echo 'mock binary download unexpectedly succeeded' >&2; exit 1
fi
grep -Fq 'curl https://gh-proxy.org/https://api.github.com/repos/oyport/wafred/releases/latest' "$MOCK_LOG"
grep -Fq 'curl https://gh-proxy.org/https://github.com/oyport/wafred/releases/download/v1.0.0/wafred-linux-amd64.tar.xz' "$MOCK_LOG"

: > "$MOCK_LOG"
if bash "$ROOT/install.sh" --mode agent --version 1.0.0 \
    --mirror https://mirror.example.com --no-systemd >/dev/null 2>&1; then
    echo 'mock binary download unexpectedly succeeded' >&2; exit 1
fi
if grep -q 'api.github.com' "$MOCK_LOG"; then
    echo 'pinned version queried the GitHub API' >&2; exit 1
fi
grep -Fq 'curl https://mirror.example.com/github.com/oyport/wafred/releases/download/v1.0.0/wafred-linux-amd64.tar.xz' "$MOCK_LOG"

echo 'Installer mirror checks passed.'
