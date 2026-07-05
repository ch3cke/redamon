#!/usr/bin/env bash
# =============================================================================
# Test suite for the secret-generation logic in redamon.sh
#   - ensure_auth_secrets  -> now also emits MCP_AUTH_TOKEN (STRIDE S10)
#   - ensure_db_secrets     -> fresh-install generation + existing-install warn
#                              for POSTGRES_PASSWORD / NEO4J_PASSWORD (STRIDE S13)
#
# Pure unit tests: `docker` is stubbed, `.env` lives in a temp dir. No daemon
# needed, CI-friendly. Run:  bash tests/redamon_secrets_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (BASH_SOURCE guard prevents command dispatch).
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_true()  { if eval "$2"; then pass "$1"; else fail "$1 (cmd: $2)"; fi; }
assert_false() { if eval "$2"; then fail "$1 (cmd unexpectedly true: $2)"; else pass "$1"; fi; }
assert_eq()    { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

# Redirect the script's own info/warn chatter into a capture file per test.
LOGCAP=""
run_capturing() { LOGCAP="$("$@" 2>&1)"; }

echo "== ensure_auth_secrets: MCP_AUTH_TOKEN =="
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"
ensure_auth_secrets >/dev/null 2>&1
assert_true  "MCP_AUTH_TOKEN generated (64 hex)" "grep -qE '^MCP_AUTH_TOKEN=[0-9a-f]{64}\$' '$TMP/.env'"
assert_true  "AUTH_SECRET still generated"        "grep -qE '^AUTH_SECRET=[0-9a-f]{64}\$' '$TMP/.env'"
# Idempotency: second call must not duplicate.
ensure_auth_secrets >/dev/null 2>&1
assert_eq    "MCP_AUTH_TOKEN not duplicated" "$(grep -c '^MCP_AUTH_TOKEN=' "$TMP/.env")" "1"
rm -rf "$TMP"

echo "== ensure_db_secrets: FRESH install (no data volume) =="
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"
docker() { return 1; }   # volume inspect always fails -> fresh
ensure_db_secrets >/dev/null 2>&1
assert_true  "POSTGRES_PASSWORD generated (48 hex)" "grep -qE '^POSTGRES_PASSWORD=[0-9a-f]{48}\$' '$TMP/.env'"
assert_true  "NEO4J_PASSWORD generated (48 hex)"    "grep -qE '^NEO4J_PASSWORD=[0-9a-f]{48}\$' '$TMP/.env'"
# Idempotency on fresh: the line now exists -> no second append.
ensure_db_secrets >/dev/null 2>&1
assert_eq    "POSTGRES_PASSWORD not duplicated" "$(grep -c '^POSTGRES_PASSWORD=' "$TMP/.env")" "1"
unset -f docker; rm -rf "$TMP"

echo "== ensure_db_secrets: EXISTING volume on default -> warn, no change =="
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"; : > "$TMP/.env"
docker() { return 0; }   # volume inspect succeeds -> existing
before=$(md5sum "$TMP/.env" | awk '{print $1}')
out="$(ensure_db_secrets 2>&1)"
after=$(md5sum "$TMP/.env" | awk '{print $1}')
assert_eq    ".env byte-identical (no silent break)" "$before" "$after"
assert_true  "warns about POSTGRES default" "echo \"\$out\" | grep -q 'POSTGRES_PASSWORD is unset'"
assert_true  "warns about NEO4J default"    "echo \"\$out\" | grep -q 'NEO4J_PASSWORD is unset'"
assert_true  "warning mentions rotation"    "echo \"\$out\" | grep -qi 'rotate'"
unset -f docker; rm -rf "$TMP"

echo "== ensure_db_secrets: operator already pinned -> silent no-op =="
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"
printf 'POSTGRES_PASSWORD=custompw\nNEO4J_PASSWORD=custompw2\n' > "$TMP/.env"
docker() { return 1; }   # even 'fresh' must be ignored when line present
before=$(md5sum "$TMP/.env" | awk '{print $1}')
out="$(ensure_db_secrets 2>&1)"
after=$(md5sum "$TMP/.env" | awk '{print $1}')
assert_eq    ".env unchanged when pinned" "$before" "$after"
assert_true  "no warning when pinned"     "[ -z \"\$(echo \"\$out\" | grep -i unset)\" ]"
unset -f docker; rm -rf "$TMP"

# NOTE: run assertions in the PARENT shell (no `( … )` subshells) — a subshell
# increments PASS/FAIL in its own copy and the tally is lost, so a broken
# assertion there would silently read as green. Isolate env vars manually.
echo "== compose_project_name honours override =="
COMPOSE_PROJECT_NAME="myproj"
assert_eq "override respected" "$(compose_project_name)" "myproj"
unset COMPOSE_PROJECT_NAME

# Regression (compose_project_name_from_env): COMPOSE_PROJECT_NAME set in .env
# (not exported) must be honoured, else ensure_db_secrets resolves the wrong
# volume name, mis-detects a fresh install, and could regenerate a password
# against a live DB.
echo "== compose_project_name reads .env (regression) =="
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"
printf 'COMPOSE_PROJECT_NAME=envproj\n' > "$TMP/.env"
unset COMPOSE_PROJECT_NAME
assert_eq ".env project name honoured" "$(compose_project_name)" "envproj"
# And it must drive volume detection: stub docker to only 'find' envproj_*.
docker() {  # $3 is the volume name in: docker volume inspect <name>
    [[ "${3:-}" == "envproj_neo4j_data" || "${3:-}" == "envproj_postgres_data" ]] && return 0 || return 1
}
out="$(ensure_db_secrets 2>&1)"
# volume 'exists' under the .env project name -> must WARN, not generate.
assert_true  "existing-volume detected via .env project name" "echo \"\$out\" | grep -q 'is unset and'"
assert_false "no password regenerated against live DB"        "grep -q '^POSTGRES_PASSWORD=' '$TMP/.env'"
unset -f docker; rm -rf "$TMP"

echo
echo "-----------------------------------------"
printf 'Secrets suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
