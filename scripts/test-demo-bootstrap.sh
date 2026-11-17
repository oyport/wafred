#!/usr/bin/env bash
set -euo pipefail

binary="${1:?path to the WAFred binary is required}"
work_dir="$(mktemp -d)"
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

export WAFRED_MODE=all-in-one
export WAFRED_DB_URL='postgres://wafred_test:local-test-password@127.0.0.1:5432/wafred_test?sslmode=disable'
export WAFRED_ADMIN_ADDR='127.0.0.1:19880' WAFRED_GRPC_ADDR='127.0.0.1:19890'
export WAFRED_LISTEN_HTTP_ADDR='127.0.0.1:18880' WAFRED_LISTEN_HTTPS_ADDR='127.0.0.1:18843'
export WAFRED_TLS_ENABLED=false WAFRED_GRPC_TLS_MODE=off
export WAFRED_ADMIN_EMAIL='admin@example.test' WAFRED_ADMIN_PASSWORD='Initial-password-42!'
export WAFRED_JWT_SECRET='only-for-the-isolated-test-12345678' WAFRED_CACHE_DIR="$work_dir/cache"
export WAFRED_DEMO_ENABLED=true WAFRED_DEMO_EMAIL='demo@waf.red' WAFRED_DEMO_PASSWORD='demo@waf.red'

"$binary" >"$work_dir/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 90); do
    if curl -fsS --max-time 1 http://127.0.0.1:19880/healthz >/dev/null 2>&1; then break; fi
    if ! kill -0 "$server_pid" 2>/dev/null; then cat "$work_dir/server.log" >&2; exit 1; fi
    sleep 1
done
base='http://127.0.0.1:19880/api/v1'
curl -fsS "$base/auth/status" | jq -e '.demo_credentials == null' >/dev/null
code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
    -d '{"email":"demo@waf.red","password":"demo@waf.red"}' "$base/auth/login")"
[[ "$code" == 401 ]]
admin="$(curl -fsS -H 'content-type: application/json' \
    -d '{"email":"admin@example.test","password":"Initial-password-42!"}' "$base/auth/login")"
token="$(jq -er '.access_token' <<<"$admin")"
[[ "$(jq -r '.user.must_change_password' <<<"$admin")" == true ]]
code="$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'content-type: application/json' \
    -H "Authorization: Bearer $token" \
    -d '{"current_password":"Initial-password-42!","new_password":"Changed-password-84!"}' "$base/auth/password")"
[[ "$code" == 204 ]]
curl -fsS "$base/auth/status" | jq -e '.demo_credentials.email == "demo@waf.red"' >/dev/null
demo="$(curl -fsS -H 'content-type: application/json' \
    -d '{"email":"demo@waf.red","password":"demo@waf.red"}' "$base/auth/login")"
token="$(jq -er '.access_token' <<<"$demo")"
curl -fsS -H "Authorization: Bearer $token" "$base/sites" | jq -e '.items | length == 1' >/dev/null
code="$(curl -sS -o "$work_dir/response.json" -w '%{http_code}' -H 'content-type: application/json' \
    -H "Authorization: Bearer $token" \
    -d '{"name":"test","domain":"test.invalid","upstream_address":"127.0.0.1:18881"}' "$base/sites")"
[[ "$code" == 403 ]]
jq -e '.error.code == "demo_read_only"' "$work_dir/response.json" >/dev/null
echo 'Fresh deployment and read-only account checks passed.'
