#!/usr/bin/env bash
# =============================================================================
# RedAmon CLI - Simplified installation, update, and lifecycle management
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
GVM_FLAG_FILE="$SCRIPT_DIR/.gvm-enabled"
KBASE_FLAG_FILE="$SCRIPT_DIR/.kbase-enabled"
KBASE_DISABLED_FLAG_FILE="$SCRIPT_DIR/.kbase-disabled"
LEGACY_SKIPKBASE_FLAG_FILE="$SCRIPT_DIR/.skipkbase"

# Service lists
CORE_SERVICES="postgres neo4j docker-broker recon-orchestrator kali-sandbox agent webapp"
# Build-only images run on demand (NOT long-running services). All live under the
# compose `tools` profile and the redamon-* tag namespace. ai-attack-surface is the
# AI Attack Surface scanner (garak/pyrit/giskard/promptfoo). wcvs is the Web Cache
# Vulnerability Scanner, run docker-in-docker by the recon container for the web
# cache poisoning module.
TOOL_IMAGES="redamon-recon:latest redamon-vuln-scanner:latest redamon-github-hunter:latest redamon-trufflehog:latest redamon-baddns:latest redamon-ai-attack-surface:latest redamon-codefix-sandbox:latest redamon-wcvs:latest"
DEV_COMPOSE="-f docker-compose.yml -f docker-compose.dev.yml"

# Orchestrator-spawned containers that docker compose does NOT manage (they are
# created at runtime via the Docker API, so `compose down` leaves them behind and
# they must be wiped explicitly):
#   - AI Attack Surface scan containers:  redamon-ai-attack-<proj>-<run>
#   - On-demand local LLM (Ollama) judge/attacker:  redamon-local-llm
#   - CodeFix build sandboxes (T6/E10):  redamon-codefix-<job>
SPAWNED_CONTAINER_NAME_FILTERS=(--filter "name=redamon-ai-attack-" --filter "name=redamon-local-llm" --filter "name=redamon-codefix-")
# The on-demand local LLM image (pulled at runtime, not built) + its models volume.
LOCAL_LLM_IMAGE="${LOCAL_LLM_IMAGE:-ollama/ollama:latest}"
LOCAL_LLM_VOLUME="${LOCAL_LLM_VOLUME:-redamon_llm_models}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ____          _    _                         "
    echo " |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __"
    echo " | |_) / _ \\/ _\` | / _ \\ | '_ \` _ \\ / _ \\| '_ \\ "
    echo " |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |"
    echo " |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Adaptive build parallelism (memory-safe Docker builds)
# ---------------------------------------------------------------------------
# The Next.js `webapp` image build peaks at several GB of RAM. Building it in
# parallel with the heavy `agent` image (pip install + large layer export) has
# OOM-killed the webapp build on low-memory hosts ("Killed" / exit code 137).
# Two-layer mitigation, applied to EVERY `docker compose build` in this script
# via compose_build():
#   Layer 1: always build `webapp` on its own first. Once built its layers are
#            cached, so it never compiles concurrently with another image.
#   Layer 2: cap COMPOSE_PARALLEL_LIMIT for the remaining images based on the
#            memory/CPU actually available to the Docker BUILD ENGINE.
#
# Cross-platform: on macOS/Windows the Docker Desktop builder runs inside a Linux
# VM whose memory is capped independently of host RAM, so reading host RAM would
# be misleading. `docker info` reports the engine's real limits and is correct on
# Linux, macOS and Windows alike; host probing (/proc, sysctl) is only a fallback.
#
# Override: REDAMON_BUILD_PARALLEL=N forces the limit (N>=1), =0 leaves it
# unbounded. webapp isolation always applies regardless of the override.

BUILD_MEM_MB=0
BUILD_NCPU=1
BUILD_RES_SOURCE="unknown"

# Query a single `docker info` field, guarding against a wedged daemon. `timeout`
# is not present on stock macOS, so use it only when available.
_docker_info_field() {
    local field="$1" out=""
    if command -v timeout >/dev/null 2>&1; then
        out="$(timeout 8 docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    else
        out="$(docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    fi
    printf '%s' "$out"
}

# Populate BUILD_MEM_MB / BUILD_NCPU / BUILD_RES_SOURCE.
detect_build_resources() {
    local mem_bytes ncpu

    # Primary source: the Docker engine's own view (VM-aware on Mac/Windows).
    mem_bytes="$(_docker_info_field MemTotal)"
    ncpu="$(_docker_info_field NCPU)"
    mem_bytes="${mem_bytes//[^0-9]/}"
    ncpu="${ncpu//[^0-9]/}"

    if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
        BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
        BUILD_RES_SOURCE="docker info"
    else
        # Fallback: probe the host OS directly.
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin)
                mem_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
                mem_bytes="${mem_bytes//[^0-9]/}"
                if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
                    BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
                fi
                BUILD_RES_SOURCE="sysctl (host)"
                ;;
            *)  # Linux, WSL2, Git Bash/MSYS all expose /proc/meminfo
                if [[ -r /proc/meminfo ]]; then
                    local mem_kb
                    mem_kb="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
                    mem_kb="${mem_kb//[^0-9]/}"
                    if [[ -n "$mem_kb" && "$mem_kb" -gt 0 ]]; then
                        BUILD_MEM_MB=$(( mem_kb / 1024 ))
                    fi
                    BUILD_RES_SOURCE="/proc/meminfo (host)"
                fi
                ;;
        esac
    fi

    # CPU count: docker info value, else nproc, else sysctl, else 1.
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then
        if command -v nproc >/dev/null 2>&1; then
            ncpu="$(nproc 2>/dev/null || echo 1)"
        elif [[ "$(uname -s 2>/dev/null || echo unknown)" == "Darwin" ]]; then
            ncpu="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 1)"
        else
            ncpu=1
        fi
        ncpu="${ncpu//[^0-9]/}"
    fi
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then ncpu=1; fi
    BUILD_NCPU="$ncpu"
}

# Echo the chosen COMPOSE_PARALLEL_LIMIT. "0" means "leave unbounded".
# Assumes detect_build_resources() has already run.
pick_parallelism() {
    # Explicit override wins and skips heuristics entirely.
    if [[ -n "${REDAMON_BUILD_PARALLEL:-}" ]]; then
        local ov="${REDAMON_BUILD_PARALLEL//[^0-9]/}"
        if [[ -z "$ov" ]]; then ov=1; fi
        printf '%s' "$ov"
        return
    fi

    # Could not detect memory -> be conservative (serial).
    if [[ "$BUILD_MEM_MB" -le 0 ]]; then
        printf '1'
        return
    fi

    # Reserve headroom for the OS plus RedAmon containers that stay running
    # during `update` (neo4j/postgres/agent), and budget ~2GB per concurrent
    # heavy build.
    local reserve=2560 per_build=2048 usable mem_bound parallel
    usable=$(( BUILD_MEM_MB - reserve ))
    if [[ "$usable" -lt "$per_build" ]]; then
        mem_bound=1
    else
        mem_bound=$(( usable / per_build ))
    fi

    parallel="$mem_bound"
    if [[ "$BUILD_NCPU" -lt "$parallel" ]]; then parallel="$BUILD_NCPU"; fi
    if [[ "$parallel" -lt 1 ]]; then parallel=1; fi
    if [[ "$parallel" -gt 6 ]]; then parallel=6; fi
    printf '%s' "$parallel"
}

# Warn when the engine has so little memory that even the isolated webapp build
# may OOM -- no scheduling can fix that, the user must grant more memory.
maybe_warn_low_memory() {
    if [[ "$BUILD_MEM_MB" -gt 0 && "$BUILD_MEM_MB" -lt 5120 ]]; then
        warn "Low build memory: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}); the webapp build may still run out of memory."
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin|MINGW*|MSYS*|CYGWIN*)
                warn "  Increase it in Docker Desktop > Settings > Resources > Memory (6GB+ recommended), then re-run."
                ;;
            *)
                if grep -qi microsoft /proc/version 2>/dev/null; then
                    warn "  On WSL2, raise memory via %UserProfile%\\.wslconfig ([wsl2] memory=6GB), run 'wsl --shutdown', then re-run."
                else
                    warn "  Consider adding swap: sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile"
                fi
                ;;
        esac
    fi
}

# =============================================================================
# Memory governor (Part 4): startup RAM gate + adaptive per-service cap export.
# Both reuse detect_build_resources() (docker info / /proc / sysctl) so the
# figures match the rest of this script. Sizes accept g/m/k suffixes or bytes.
# =============================================================================

# Convert a Docker-style size ("2g","2048m","1073741824") to whole MB. Empty on
# invalid input. Plain numbers are bytes (matches resource_governor.parse_size).
_size_to_mb() {
    local v="${1:-}"
    v="$(printf '%s' "$v" | tr 'A-Z' 'a-z' | tr -d ' ')"
    [[ -z "$v" ]] && { printf ''; return; }
    v="${v%b}"                              # tolerate trailing 'b' (e.g. 512mb)
    local unit="" num="$v"
    case "$v" in
        *k) unit=k; num="${v%k}" ;;
        *m) unit=m; num="${v%m}" ;;
        *g) unit=g; num="${v%g}" ;;
        *t) unit=t; num="${v%t}" ;;
    esac
    # Allow a decimal (e.g. 1.5g, 0.5g); plain number = bytes.
    [[ "$num" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf ''; return; }
    # awk keeps the fraction ('1.5g' -> 1536), which pure bash integer math loses.
    awk -v n="$num" -v u="$unit" 'BEGIN{
        m = (u=="k")?1024 : (u=="m")?1048576 : (u=="g")?1073741824 : (u=="t")?1099511627776 : 1;
        printf "%d", int(n*m/1048576);
    }'
}

# Refuse to start when the host/VM can't hold the always-on core services, with
# a clear message, instead of failing mysteriously later. Returns 1 to abort.
# Override with REDAMON_SKIP_RAM_GATE=1 or REDAMON_MIN_RAM_MB=<mb>.
preflight_ram_gate() {
    [[ "${REDAMON_SKIP_RAM_GATE:-}" == "1" ]] && return 0
    detect_build_resources
    local required_mb baseline_mb headroom_mb
    if [[ -n "${REDAMON_MIN_RAM_MB:-}" ]]; then
        required_mb="${REDAMON_MIN_RAM_MB//[^0-9]/}"
    else
        baseline_mb="$(_size_to_mb "${SERVICE_BASELINE_MEM:-6g}")"; [[ -z "$baseline_mb" ]] && baseline_mb=6144
        headroom_mb="$(_size_to_mb "${OS_HEADROOM_MEM:-2g}")";      [[ -z "$headroom_mb" ]] && headroom_mb=2048
        required_mb=$(( baseline_mb + headroom_mb ))
    fi
    [[ -z "$required_mb" || "$required_mb" -le 0 ]] && return 0
    # ~512MB slack: docker-info MemTotal on a physical 8GB host reads ~7.7GB
    # (kernel/reserved), which should still pass an 8GB requirement.
    local threshold=$(( required_mb - 512 ))
    [[ "$threshold" -lt 0 ]] && threshold="$required_mb"
    if [[ "${BUILD_MEM_MB:-0}" -gt 0 && "$BUILD_MEM_MB" -lt "$threshold" ]]; then
        error "Insufficient memory for RedAmon core services: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}), need ~$(( required_mb / 1024 ))GB."
        error "Free up memory, raise the Docker VM memory, or set REDAMON_SKIP_RAM_GATE=1 to override."
        return 1
    fi
    return 0
}

# Export a clamped "<mb>m" cap for VAR unless the user already set it.
_export_clamped_cap() {
    local var="$1" val="$2" floor="$3" ceil="$4"
    [[ -n "${!var:-}" ]] && return 0          # respect explicit override
    [[ "$val" -lt "$floor" ]] && val="$floor"
    [[ "$val" -gt "$ceil" ]] && val="$ceil"
    export "$var=${val}m"
}

# Derive per-service memory caps from detected RAM and export them so
# docker-compose.yml `${VAR:-default}` picks them up. Always-on services get a
# static generous cap sized to the host (Part 4). No-op if RAM undetectable.
export_resource_caps() {
    detect_build_resources
    [[ "${BUILD_MEM_MB:-0}" -le 0 ]] && return 0
    local t="$BUILD_MEM_MB"
    # neo4j: the container mem_limit MUST exceed heap + pagecache or the JVM gets
    # OOM-killed. Derive NEO4J_MEM from the (clamped) heap+pagecache plus JVM
    # overhead headroom (metaspace, threads, direct buffers), never an
    # independent fraction that could land below heap+pagecache.
    local heap_mb pc_mb neo_mb eff_heap eff_pc
    heap_mb=$(( t * 15 / 100 )); [[ "$heap_mb" -lt 512 ]] && heap_mb=512; [[ "$heap_mb" -gt 4096 ]] && heap_mb=4096
    pc_mb=$(( t * 10 / 100 ));   [[ "$pc_mb"   -lt 512 ]] && pc_mb=512;   [[ "$pc_mb"   -gt 4096 ]] && pc_mb=4096
    # Derive the container limit from the EFFECTIVE heap/pagecache (a user's
    # NEO4J_HEAP override wins), or it could land below the JVM heap -> OOM at boot.
    eff_heap="$(_size_to_mb "${NEO4J_HEAP:-${heap_mb}m}")"; [[ -z "$eff_heap" ]] && eff_heap="$heap_mb"
    eff_pc="$(_size_to_mb "${NEO4J_PAGECACHE:-${pc_mb}m}")"; [[ -z "$eff_pc" ]] && eff_pc="$pc_mb"
    neo_mb=$(( eff_heap + eff_pc + 1024 ))
    [[ -z "${NEO4J_HEAP:-}" ]]      && export NEO4J_HEAP="${heap_mb}m"
    [[ -z "${NEO4J_PAGECACHE:-}" ]] && export NEO4J_PAGECACHE="${pc_mb}m"
    [[ -z "${NEO4J_MEM:-}" ]]       && export NEO4J_MEM="${neo_mb}m"
    _export_clamped_cap AGENT_MEM         $(( t * 12 / 100 )) 1024 4096
    _export_clamped_cap GVMD_MEM          $(( t * 12 / 100 )) 1024 3072
    _export_clamped_cap RECON_ORCHESTRATOR_MEM $(( t * 5 / 100 )) 512 2048
    _export_clamped_cap WEBAPP_MEM        $(( t * 6 / 100 )) 512  2048
    _export_clamped_cap POSTGRES_MEM      $(( t * 6 / 100 )) 512  2048
    _export_clamped_cap KALI_MEM          $(( t * 6 / 100 )) 512  2048
}

# Optional one-time compressed-RAM (zram) swap cushion so brief memory overshoots
# degrade gracefully (swap to compressed RAM) instead of OOM-killing. Linux-native
# host only; a NO-OP on macOS/Windows (Docker Desktop's VM manages its own swap)
# and when REDAMON_ENABLE_ZRAM != 1. Best-effort: never fatal, never interactive.
setup_zram() {
    [[ "${REDAMON_ENABLE_ZRAM:-}" == "1" ]] || return 0

    # Docker Desktop / WSL2 / mac: cannot add zram to the host VM from here.
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux) ;;
        *) info "zram: skipped (not a native Linux host)"; return 0 ;;
    esac
    if grep -qi microsoft /proc/version 2>/dev/null; then
        info "zram: skipped (WSL2 manages its own memory)"; return 0
    fi
    # Already have zram swap active? Leave it.
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q zram; then
        info "zram: already active"; return 0
    fi
    if ! command -v zramctl >/dev/null 2>&1; then
        warn "zram: zramctl not found; skipping (install util-linux/zram-tools to enable)"; return 0
    fi

    detect_build_resources
    local size="${REDAMON_ZRAM_SIZE:-}"
    if [[ -z "$size" ]]; then
        if [[ "${BUILD_MEM_MB:-0}" -le 0 ]]; then
            warn "zram: cannot size (RAM undetectable); set REDAMON_ZRAM_SIZE to enable"; return 0
        fi
        # Default: half of detected RAM, clamped to [512M, 8G].
        local half=$(( BUILD_MEM_MB / 2 ))
        [[ "$half" -gt 8192 ]] && half=8192
        [[ "$half" -lt 512 ]] && half=512
        size="${half}M"
    fi

    # Requires root; use sudo non-interactively so we never hang on a password.
    local SUDO=""
    if [[ "$(id -u)" != "0" ]]; then
        if sudo -n true 2>/dev/null; then SUDO="sudo -n"; else
            warn "zram: needs root and passwordless sudo is unavailable; skipping"; return 0
        fi
    fi

    local dev
    if dev="$($SUDO zramctl --find --size "$size" --algorithm zstd 2>/dev/null)" && [[ -n "$dev" ]]; then
        if $SUDO mkswap "$dev" >/dev/null 2>&1 && $SUDO swapon --priority 100 "$dev" 2>/dev/null; then
            success "zram: enabled ${size} compressed swap on ${dev}"
        else
            warn "zram: failed to enable swap on ${dev}; cleaning up"
            $SUDO zramctl --reset "$dev" 2>/dev/null || true
        fi
    else
        warn "zram: could not allocate a zram device; skipping"
    fi
    return 0
}

# Memory-safe replacement for `docker compose ... build ...`. Pass exactly the
# args that would follow `docker compose`, e.g.:
#   compose_build --profile tools build
#   compose_build --profile tools build recon vuln-scanner
#   compose_build build recon-orchestrator kali-sandbox agent webapp docker-broker
compose_build() {
    detect_build_resources
    local parallel; parallel="$(pick_parallelism)"

    # Find the service names (positional args after the `build` subcommand).
    local seen_build=false svc has_webapp=false svc_count=0
    for svc in "$@"; do
        if [[ "$seen_build" == false ]]; then
            if [[ "$svc" == "build" ]]; then seen_build=true; fi
            continue
        fi
        case "$svc" in
            -*) continue ;;   # skip build flags (--no-cache, --pull, ...)
        esac
        svc_count=$(( svc_count + 1 ))
        if [[ "$svc" == "webapp" ]]; then has_webapp=true; fi
    done

    # A build with no explicit service list builds everything -> webapp included.
    local isolate_webapp=false
    if [[ "$has_webapp" == true || "$svc_count" -eq 0 ]]; then
        isolate_webapp=true
    fi

    info "Docker build resources: ~$(( BUILD_MEM_MB / 1024 ))GB RAM / ${BUILD_NCPU} CPU (${BUILD_RES_SOURCE}); parallelism=${parallel}"
    maybe_warn_low_memory

    # Layer 1: build the RAM-heavy webapp on its own first.
    if [[ "$isolate_webapp" == true ]]; then
        info "Building webapp in isolation first (prevents out-of-memory during parallel build)..."
        docker compose build webapp
    fi

    # Layer 2: build the (remaining) images with a capped parallel limit. If
    # webapp was in the set it is now cached, so re-passing it is a no-op.
    if [[ -n "$parallel" && "$parallel" -ge 1 ]]; then
        COMPOSE_PARALLEL_LIMIT="$parallel" docker compose "$@"
    else
        docker compose "$@"   # REDAMON_BUILD_PARALLEL=0 -> unbounded
    fi
}

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '[:space:]'
    else
        echo "unknown"
    fi
}

is_gvm_enabled() {
    [[ -f "$GVM_FLAG_FILE" ]]
}

is_kbase_enabled() {
    [[ -f "$KBASE_FLAG_FILE" ]]
}

# One-time migration from the legacy `.skipkbase` flag (RedAmon <=4.9.3) to the
# new explicit flag pair (`.kbase-enabled` / `.kbase-disabled`). cmd_install
# always writes one of the two markers so the user's explicit choice is sticky
# across `clean` (which keeps KB data on disk). Behavior per case:
#   - .kbase-enabled or .kbase-disabled exists → already migrated → no-op
#   - .skipkbase exists                        → legacy default install (KB off) → convert to .kbase-disabled
#   - no markers, FAISS index on disk          → legacy --kbase install (KB on)  → create .kbase-enabled
#   - no markers, no data                      → fresh clone → create .kbase-disabled (README default)
# Called from every command except cmd_install (which sets the markers explicitly).
_migrate_legacy_kbase_flag() {
    if [[ -f "$KBASE_FLAG_FILE" || -f "$KBASE_DISABLED_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        return
    fi
    if [[ -f "$LEGACY_SKIPKBASE_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
        return
    fi
    if [[ -s "$SCRIPT_DIR/knowledge_base/data/index.faiss" ]]; then
        touch "$KBASE_FLAG_FILE"
    else
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
}

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. See: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 is not installed. See: https://docs.docker.com/compose/install/"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        error "Git is not installed."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

export_version() {
    export REDAMON_VERSION
    REDAMON_VERSION="$(get_version)"
}

ensure_auth_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"
    if ! grep -q '^AUTH_SECRET=' "$env_file" 2>/dev/null; then
        echo "AUTH_SECRET=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated AUTH_SECRET"
    fi
    if ! grep -q '^INTERNAL_API_KEY=' "$env_file" 2>/dev/null; then
        echo "INTERNAL_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated INTERNAL_API_KEY"
    fi
    if ! grep -q '^ORCHESTRATOR_API_KEY=' "$env_file" 2>/dev/null; then
        echo "ORCHESTRATOR_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated ORCHESTRATOR_API_KEY"
    fi
    # Shared bearer token the agent presents to the Kali MCP servers and the
    # servers validate on every inbound SSE request (STRIDE S10 defense-in-depth).
    # Stateless (not baked into any volume), so append-if-absent is safe.
    if ! grep -q '^MCP_AUTH_TOKEN=' "$env_file" 2>/dev/null; then
        echo "MCP_AUTH_TOKEN=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated MCP_AUTH_TOKEN"
    fi
}

# Compose project name (used to resolve the data-volume names). Must match
# docker compose's own derivation or ensure_db_secrets would mis-detect a fresh
# vs existing install and could regenerate a password against a live DB.
# Precedence mirrors compose: exported COMPOSE_PROJECT_NAME, then the same var in
# .env, then the sanitised working-directory basename.
compose_project_name() {
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
        echo "$COMPOSE_PROJECT_NAME"
        return
    fi
    local env_file="$SCRIPT_DIR/.env"
    if [ -f "$env_file" ]; then
        local from_env
        from_env="$(grep -E '^COMPOSE_PROJECT_NAME=' "$env_file" 2>/dev/null | head -1 | cut -d= -f2-)"
        if [ -n "$from_env" ]; then
            echo "$from_env"
            return
        fi
    fi
    basename "$SCRIPT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# True (0) if the named docker volume for THIS project already exists.
_data_volume_exists() {
    local suffix="$1"   # e.g. postgres_data
    local project; project="$(compose_project_name)"
    docker volume inspect "${project}_${suffix}" >/dev/null 2>&1
}

# Harden the datastore passwords (STRIDE S13/S1). The passwords are baked into
# the postgres/neo4j data volumes at FIRST init, so we only auto-generate on a
# FRESH install (volume absent). On an existing install still on the compose
# default we must NOT rewrite .env (it would break auth against the already
# initialised volume) — we warn loudly and point to the rotation procedure.
# Uses url/shell-safe hex so DATABASE_URL and NEO4J_AUTH need no escaping.
ensure_db_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"

    # (var, volume suffix, compose default) triples.
    local specs=(
        "POSTGRES_PASSWORD:postgres_data:redamon_secret"
        "NEO4J_PASSWORD:neo4j_data:changeme123"
    )

    local spec var suffix default
    for spec in "${specs[@]}"; do
        var="${spec%%:*}"
        suffix="$(echo "$spec" | cut -d: -f2)"
        default="${spec##*:}"

        # Operator already pinned it in .env — respect it, do nothing.
        if grep -q "^${var}=" "$env_file" 2>/dev/null; then
            continue
        fi

        if _data_volume_exists "$suffix"; then
            # Existing DB, initialised with the weak compose default. Changing
            # the password now would lock us out of the running volume.
            warn "${var} is unset and the ${suffix} volume already exists, so it is running on the DEFAULT password ('${default}')."
            warn "  Not changing it automatically (would break the existing database)."
            warn "  To rotate: set a strong ${var} in .env, then update the DB's own password to match (e.g. ALTER USER / neo4j 'dbms.security.changePassword'), or destroy the ${suffix} volume for a clean re-init if the data is disposable."
        else
            # Fresh install — generate before the DB volume is created so it
            # initialises with the strong value across all consumers.
            echo "${var}=$(openssl rand -hex 24)" >> "$env_file"
            info "Generated strong ${var} (fresh install)"
        fi
    done
}

ensure_admin() {
    # Wait for webapp to be healthy
    local retries=0
    while ! docker compose exec -T webapp wget -q --spider http://127.0.0.1:3000/api/health 2>/dev/null; do
        retries=$((retries + 1))
        if [[ $retries -ge 30 ]]; then
            warn "Webapp not ready -- skipping admin check"
            return
        fi
        sleep 2
    done

    local has_admin
    has_admin=$(docker compose exec -T webapp node scripts/check-admin.mjs 2>/dev/null | tr -d '[:space:]')

    if [[ "$has_admin" == "0" || -z "$has_admin" ]]; then
        echo ""
        warn "No admin user found. Let's create one."
        echo ""
        read -rp "  Admin name: " ADMIN_NAME </dev/tty
        read -rp "  Admin email: " ADMIN_EMAIL </dev/tty
        while true; do
            read -srp "  Admin password: " ADMIN_PASS </dev/tty
            echo ""
            read -srp "  Confirm password: " ADMIN_PASS2 </dev/tty
            echo ""
            [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]] && break
            warn "Passwords do not match. Try again."
        done
        docker compose exec -T \
            -e "ADMIN_NAME=$ADMIN_NAME" \
            -e "ADMIN_EMAIL=$ADMIN_EMAIL" \
            -e "ADMIN_PASSWORD=$ADMIN_PASS" \
            webapp node scripts/create-admin.mjs
        success "Admin user created."
        echo ""
    fi
}

cmd_reset_password() {
    echo ""
    read -rp "  User email: " EMAIL </dev/tty
    read -srp "  New password: " NEW_PASS </dev/tty
    echo ""
    read -srp "  Confirm password: " CONFIRM </dev/tty
    echo ""

    if [[ "$NEW_PASS" != "$CONFIRM" ]]; then
        error "Passwords do not match."
        exit 1
    fi

    docker compose exec -T \
        -e "RESET_EMAIL=$EMAIL" \
        -e "RESET_PASSWORD=$NEW_PASS" \
        webapp node scripts/reset-password.mjs
    success "Password updated."
    echo ""
}

# Wipe the orchestrator-spawned, non-compose-managed containers (AI Attack Surface
# scan containers + the on-demand local LLM). Safe to call anytime — a no-op when
# none are present. Must run BEFORE `compose down --volumes` so the local-llm
# container releases the models volume and it can actually be removed.
remove_spawned_containers() {
    local ids
    ids=$(docker ps -aq "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        info "Removing orchestrator-spawned AI containers (scan + local LLM)..."
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1 || true
    fi
}

remove_redamon_images() {
    # Remove locally-built redamon images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep '^redamon-' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove GVM / Greenbone images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep 'registry.community.greenbone.net' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove ProjectDiscovery + recon tool images (pulled at runtime by entrypoint)
    local runtime_images=(
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/katana"
        "projectdiscovery/nuclei"
        "projectdiscovery/subfinder"
        "projectdiscovery/dnsx"
        "projectdiscovery/uncover"
        "sxcurity/gau"
        "caffix/amass"
        "frost19k/puredns"
        "jauderho/hakrawler"
        "trufflesecurity/trufflehog"
        # On-demand local LLM (Ollama) for the AI Attack Surface judge/attacker —
        # pulled at runtime by the orchestrator, not built.
        "$LOCAL_LLM_IMAGE"
    )
    for img in "${runtime_images[@]}"; do
        docker rmi "$img" 2>/dev/null || true
    done
}

pull_gvm_images() {
    # GVM images are large (~250MB each) and can fail with "unexpected EOF"
    # due to a known Docker+Go 1.24 bug (moby/moby#49513) and Greenbone
    # registry instability. Pull individually with retries.
    local max_retries=5
    local gvm_services
    gvm_services=$(docker compose config --services 2>/dev/null | grep '^gvm-')

    if [[ -z "$gvm_services" ]]; then
        return 0
    fi

    # Skip pull if all GVM images already exist locally (pass force=true to override)
    local force="${1:-false}"
    if [[ "$force" != "true" ]]; then
        local need_pull=false
        local compose_json
        compose_json=$(docker compose config --format json 2>/dev/null)
        for svc in $gvm_services gvmd; do
            local img
            img=$(echo "$compose_json" | jq -r ".services.\"$svc\".image // empty")
            if [[ -n "$img" ]] && ! docker image inspect "$img" &>/dev/null; then
                need_pull=true
                break
            fi
        done
        if [[ "$need_pull" == "false" ]]; then
            info "GVM images already present locally, skipping pull."
            return 0
        fi
    fi

    info "Pulling GVM images (with retry)..."
    local failed=()
    for svc in $gvm_services; do
        local attempt=1
        while [[ $attempt -le $max_retries ]]; do
            if docker compose pull "$svc" 2>/dev/null; then
                break
            fi
            if [[ $attempt -lt $max_retries ]]; then
                warn "Pull failed for $svc (attempt $attempt/$max_retries), retrying..."
                sleep 5
            fi
            ((attempt++))
        done
        if [[ $attempt -gt $max_retries ]]; then
            failed+=("$svc")
        fi
    done

    # Also pull gvmd separately (no gvm- prefix)
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if docker compose pull gvmd 2>/dev/null; then
            break
        fi
        if [[ $attempt -lt $max_retries ]]; then
            warn "Pull failed for gvmd (attempt $attempt/$max_retries), retrying..."
            sleep 3
        fi
        ((attempt++))
    done
    if [[ $attempt -gt $max_retries ]]; then
        failed+=(gvmd)
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        error "Failed to pull after $max_retries attempts: ${failed[*]}"
        echo ""
        echo -e "  ${YELLOW}This is often caused by a Docker+Go 1.24 bug (moby/moby#49513).${NC}"
        echo -e "  ${YELLOW}Try: echo '{\"max-concurrent-downloads\":1}' | sudo tee /etc/docker/daemon.json${NC}"
        echo -e "  ${YELLOW}Then: sudo systemctl restart docker && ./redamon.sh up${NC}"
        exit 1
    fi
    success "All GVM images pulled successfully."
}

# ---------------------------------------------------------------------------
# Knowledge Base helpers
# ---------------------------------------------------------------------------

KB_CONFIG_YAML="$SCRIPT_DIR/knowledge_base/kb_config.yaml"

# Read a value from kb_config.yaml. Dotted paths are supported for nested
# keys. Falls back to $2 if the file, key, or python is unavailable.
#   $1: dotted key path (e.g. "runtime.mode" or "KB_ENABLED")
#   $2: fallback value
_kb_yaml_get() {
    local key="$1"
    local fallback="$2"
    python3 -c "
import sys, yaml
try:
    with open('$KB_CONFIG_YAML') as f:
        cfg = yaml.safe_load(f) or {}
    value = cfg
    for k in '$key'.split('.'):
        value = value[k]
    if isinstance(value, bool):
        print('true' if value else 'false')
    else:
        print(value)
except Exception:
    print('$fallback')
" 2>/dev/null || echo "$fallback"
}

# Feature gate mirroring is_gvm_enabled(). Single source of truth: the
# `.kbase-enabled` flag file, written by `install --kbase`. The README contract
# is that KB is opt-in — default install has no KB.
is_kb_enabled() {
    is_kbase_enabled
}

# Export KB-related env vars so downstream processes (docker compose, make)
# see a value that matches the flag file. Called from every cmd_* that
# shells out to docker compose. Always exports — the flag is authoritative,
# any pre-existing $KB_ENABLED in the environment is overwritten so direct
# `KB_ENABLED=true docker compose up` shenanigans can't lie to the agent
# when the image was built without KB deps.
_kb_export_env() {
    if is_kbase_enabled; then
        export KB_ENABLED="true"
        export SKIP_KB="false"
    else
        export KB_ENABLED="false"
        export SKIP_KB="true"
    fi
}

# Wait for the Neo4j container to become healthy. Starts it if not running.
# Returns 0 on success, 1 on timeout.
_kb_wait_neo4j() {
    if ! docker ps --format '{{.Names}}' | grep -q '^redamon-neo4j$'; then
        info "Neo4j not running — starting it..."
        docker compose up -d neo4j
    fi

    info "Waiting for Neo4j to become healthy..."
    local waited=0
    local max_wait=60
    while [[ $waited -lt $max_wait ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' \
                   redamon-neo4j 2>/dev/null || echo "unknown")
        if [[ "$health" == "healthy" ]]; then
            success "Neo4j is healthy"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    error "Neo4j did not become healthy within ${max_wait}s"
    error "Check: docker logs redamon-neo4j"
    return 1
}

# Check if the agent container has a CUDA-capable GPU available.
_kb_has_gpu() {
    docker exec redamon-agent python -c \
        "import torch; exit(0 if torch.cuda.is_available() else 1)" &>/dev/null
}

# Check if .env has an embedding API configured and ready to use.
_kb_has_api_key() {
    local env_file="$SCRIPT_DIR/.env"
    [[ -f "$env_file" ]] || return 1
    local use_api key
    use_api=$(grep -E '^KB_EMBEDDING_USE_API=' "$env_file" 2>/dev/null \
              | cut -d= -f2 | tr -d '"' | tr -d "'")
    key=$(grep -E '^KB_EMBEDDING_API_KEY=' "$env_file" 2>/dev/null \
          | cut -d= -f2 | tr -d '"' | tr -d "'")
    [[ "$use_api" == "true" && -n "$key" ]]
}

# Detect the best ingestion profile and show terminal feedback.
# Prints the chosen profile name to stdout. Shows an interactive
# prompt on CPU-only systems asking the user whether to run full
# ingestion or quick-start with fewer sources.
_kb_choose_profile() {
    if _kb_has_api_key; then
        local base_url
        base_url=$(grep -E '^KB_EMBEDDING_API_BASE_URL=' "$SCRIPT_DIR/.env" \
                   | cut -d= -f2 | tr -d '"' | tr -d "'")
        info "KB Embedding: API mode (${base_url:-https://api.openai.com/v1})" >&2
        info "Ingesting all lite sources via API embeddings..." >&2
        echo "lite"
        return
    fi

    if _kb_has_gpu; then
        info "KB Embedding: GPU detected" >&2
        info "Ingesting all lite sources with GPU acceleration..." >&2
        echo "lite"
        return
    fi

    # CPU-only with existing FAISS data: skip the interactive prompt.
    # The manifest dedup will skip unchanged chunks anyway, so a re-run
    # finishes in seconds. To upgrade the profile, use:
    #   ./redamon.sh kb build lite
    #
    # Note: FAISS files are created by Docker (root-owned, mode 600), so
    # we cannot read their contents as a normal user. Use -s (non-zero size)
    # instead of trying to parse the JSON.
    local faiss_index="$SCRIPT_DIR/knowledge_base/data/index.faiss"
    if [[ -s "$faiss_index" ]]; then
        info "KB Embedding: CPU mode (FAISS index exists, refreshing unchanged chunks)" >&2
        echo "cpu-lite"
        return
    fi

    # First-time CPU-only: show explanation and let user choose
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo "  Knowledge Base -- Embedding Configuration"                 >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2
    echo "  No GPU and no embedding API key detected."                 >&2
    echo "  The KB needs to convert security datasets into vector"     >&2
    echo "  embeddings. On CPU this is slow for large datasets."       >&2
    echo ""                                                            >&2
    echo "  Source          Chunks    Est. time on CPU"                 >&2
    echo "  --------------- --------- ----------------"                >&2
    echo "  tool_docs            ~35   ~2 min"                         >&2
    echo "  gtfobins            ~400   ~7 min"                         >&2
    echo "  lolbas              ~450   ~7 min"                         >&2
    echo "  owasp               ~880   ~35 min"                        >&2
    echo "  exploitdb        ~45,000   ~3 hours"                       >&2
    echo ""                                                            >&2
    echo "  Option 1: Quick start (~15 min)"                           >&2
    echo "    Ingest tool_docs + gtfobins + lolbas only."              >&2
    echo "    You can add owasp/exploitdb later."                      >&2
    echo ""                                                            >&2
    echo "  Option 2: Full ingestion (~4 hours)"                       >&2
    echo "    Ingest all 5 sources now. Go grab a coffee."             >&2
    echo ""                                                            >&2
    echo "  Tip: To skip this wait in the future, configure an"        >&2
    echo "  embedding API in .env (see .env.example):"                 >&2
    echo "    KB_EMBEDDING_USE_API=true"                                >&2
    echo "    KB_EMBEDDING_API_KEY=sk-..."                              >&2
    echo "    KB_EMBEDDING_API_BASE_URL=  (leave empty for OpenAI)"    >&2
    echo "  With an API, full ingestion takes ~2-3 minutes."           >&2
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2

    read -rp "  Run full ingestion now? [y/N] " full_ingest </dev/tty

    if [[ "$full_ingest" =~ ^[Yy]$ ]]; then
        info "Full ingestion selected. This will take a while..." >&2
        echo "lite"
    else
        info "Quick start selected (tool_docs + gtfobins + lolbas)" >&2
        echo "cpu-lite"
    fi
}

# Internal: run `make kb-build-<profile>` with Neo4j health check first.
# Fails gracefully -- callers decide whether to treat failure as fatal.
_kb_bootstrap() {
    local profile="${1:-lite}"
    _kb_export_env
    _kb_wait_neo4j || return 1
    info "Bootstrapping Knowledge Base (profile=${profile})..."
    make -C knowledge_base "kb-build-${profile}" MODE=docker
}

# Status helpers: read KB and Tavily state directly from disk/env without
# requiring Python deps, running containers, or Neo4j connections. These
# should always succeed (or return a safe fallback) so `./redamon.sh status`
# works in any state.

# Count FAISS vectors by reading chunk_ids.json directly. No Python dep
# required — uses python3's stdlib json module, which is always present.
# Returns "0" if the file is missing or unreadable.
_kb_get_faiss_count() {
    local chunk_ids="$SCRIPT_DIR/knowledge_base/data/chunk_ids.json"
    if [[ ! -f "$chunk_ids" ]]; then
        echo "0"
        return
    fi
    python3 -c "
import json, sys
try:
    with open('$chunk_ids') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 0)
except Exception:
    print('0')
" 2>/dev/null || echo "0"
}

# Count Neo4j KBChunk nodes via cypher-shell inside the neo4j container.
# Returns "0" if the container isn't running, "unknown" if the query fails.
_kb_get_neo4j_count() {
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        echo "0"
        return
    fi
    local pass="${NEO4J_PASSWORD:-changeme123}"
    local user="${NEO4J_USER:-neo4j}"
    local count
    count=$(docker exec redamon-neo4j cypher-shell \
        -u "$user" -p "$pass" --format plain \
        "MATCH (c:KBChunk) RETURN count(c) AS total" 2>/dev/null \
        | tail -n 1 | tr -d '[:space:]"' || true)
    # Validate it's a non-negative integer; fall back to unknown otherwise
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
    local gvm_mode="false"
    local kbase_mode="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --gvm)   gvm_mode="true" ;;
            --kbase) kbase_mode="true" ;;
            *) error "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done

    print_banner
    check_prerequisites

    local version
    version="$(get_version)"
    info "Installing RedAmon v${version}..."
    if [[ "$gvm_mode" == "true" ]]; then
        info "Mode: Full stack (with GVM/OpenVAS)"
        touch "$GVM_FLAG_FILE"
    else
        info "Mode: Core services (without GVM/OpenVAS)"
        rm -f "$GVM_FLAG_FILE"
    fi
    # KB is OPT-IN at install time. The install always writes ONE of the two
    # markers (.kbase-enabled or .kbase-disabled) so the user's explicit choice
    # is sticky — `clean` keeps KB data on disk, and without an explicit
    # "disabled" marker the migration heuristic would later see leftover FAISS
    # data and re-enable KB. The legacy `.skipkbase` flag is removed.
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    if [[ "$kbase_mode" == "true" ]]; then
        info "Mode: Including Knowledge Base (--kbase)"
        touch "$KBASE_FLAG_FILE"
        rm -f "$KBASE_DISABLED_FLAG_FILE"
    else
        info "Mode: Skipping Knowledge Base (default; pass --kbase to enable)"
        rm -f "$KBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
    _kb_export_env
    echo ""

    # Export version for docker build arg
    export_version

    # Generate auth secrets if not present
    ensure_auth_secrets
    ensure_db_secrets

    # Build all images (tools + core services)
    info "Building all images (this may take a while on first run)..."
    compose_build --profile tools build

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    # Start services (force-recreate ensures compose changes like command: are applied)
    info "Starting services..."
    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d --force-recreate
    else
        # shellcheck disable=SC2086
        docker compose up -d --force-recreate $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon v${version} is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # Bootstrap the Knowledge Base if enabled (reads KB_ENABLED from kb_config.yaml).
    # Install always runs a fresh bootstrap -- first-time setup populates FAISS +
    # Neo4j from committed caches. Graceful failure: if bootstrap fails
    # (network, missing deps, etc.) the agent still starts with an empty KB
    # and the user gets a clear retry command.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB bootstrap failed -- agent will start with an empty KB"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    else
        info "KB_ENABLED=false -- skipping Knowledge Base bootstrap"
    fi

    echo ""
    echo -e "  ${CYAN}Status:${NC}  ./redamon.sh status"
    echo ""
    echo -e "  ${YELLOW}If RedAmon is useful to you, a GitHub star helps others find the project:${NC}"
    echo -e "  ${CYAN}https://github.com/samugit83/redamon${NC}"
    echo ""
    if [[ "$gvm_mode" == "true" ]]; then
        warn "GVM/OpenVAS feed sync takes ~30 minutes on first run."
        echo -e "  ${CYAN}GVM credentials:${NC} admin / admin"
    fi
}

cmd_update() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    print_banner
    check_prerequisites

    local old_version
    old_version="$(get_version)"
    info "Current version: v${old_version}"
    info "Checking for updates..."
    echo ""

    # Save current HEAD
    local old_head new_head
    if [[ -n "${REDAMON_UPDATE_FROM:-}" ]]; then
        # We were re-exec'd by our previous self after the pull (see below). Reuse
        # the recorded pre-pull HEAD and do NOT pull again — just run the rebuild
        # logic from the freshly-pulled (newer) script.
        old_head="$REDAMON_UPDATE_FROM"
        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
    else
        old_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        # Pull latest (try upstream tracking branch first, then origin/master)
        if ! git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
            if ! git -C "$SCRIPT_DIR" pull --ff-only origin master 2>/dev/null; then
                error "Could not pull updates. You may have local changes."
                echo ""
                echo "  Try one of:"
                echo "    git stash && ./redamon.sh update && git stash pop"
                echo "    git commit -am 'local changes' && ./redamon.sh update"
                exit 1
            fi
        fi

        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        if [[ "$old_head" == "$new_head" ]]; then
            success "Already up to date (v$(get_version))."
            return
        fi

        # Self-heal across versions: re-exec the freshly-pulled script so the
        # update logic from the version being INSTALLED runs (it may know about
        # services or build rules this older copy does not — e.g. a new service
        # added in the target release). Guarded by REDAMON_UPDATE_FROM so we do
        # not pull or loop again.
        export REDAMON_UPDATE_FROM="$old_head"
        exec bash "$SCRIPT_DIR/redamon.sh" update
    fi

    local new_version
    new_version="$(get_version)"
    info "Updating v${old_version} -> v${new_version}"
    echo ""

    # Detect what changed
    local changed_files
    changed_files="$(git -C "$SCRIPT_DIR" diff --name-only "$old_head" "$new_head")"

    # Map changed paths to services
    local rebuild_core=()
    local rebuild_tools=()
    local rebuild_all=false

    if echo "$changed_files" | grep -q "^docker-compose\.yml$"; then
        rebuild_all=true
    fi

    # Track services that need restart only (volume-mounted source code changes)
    local restart_only=()

    if [[ "$rebuild_all" == "true" ]]; then
        info "docker-compose.yml changed -- rebuilding core service images"
        rebuild_core=(recon-orchestrator kali-sandbox agent webapp docker-broker)
    else
        # webapp: always needs rebuild (no volume mount in production)
        if echo "$changed_files" | grep -q "^webapp/"; then
            rebuild_core+=(webapp)
        fi

        # recon-orchestrator: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^recon_orchestrator/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(recon-orchestrator)
        elif echo "$changed_files" | grep -q "^recon_orchestrator/"; then
            restart_only+=(recon-orchestrator)
        fi

        # kali-sandbox: rebuild only if Dockerfile/entrypoint changed, else restart
        if echo "$changed_files" | grep -q "^mcp/kali-sandbox/\(Dockerfile\|entrypoint\)"; then
            rebuild_core+=(kali-sandbox)
        elif echo "$changed_files" | grep -q "^mcp/"; then
            restart_only+=(kali-sandbox)
        fi

        # agent: always rebuild when agentic/ changes — source code is baked into
        # the image (no volume mount for ./agentic:/app), so restart alone won't
        # pick up .py changes.
        if echo "$changed_files" | grep -q "^agentic/"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -qE "^(knowledge_base|graph_db)/"; then
            rebuild_core+=(agent)
        fi

        # docker-broker: the Docker-socket filtering proxy. Rebuild when its
        # source changes (it builds from ./docker_broker, no volume mount).
        if echo "$changed_files" | grep -q "^docker_broker/"; then
            rebuild_core+=(docker-broker)
        fi
    fi

    # Tool-profile images build ONLY from their own source dirs — a docker-compose.yml
    # change never alters their content. So rebuild a tool image ONLY when its source
    # actually changed, even under rebuild_all. This avoids spuriously rebuilding heavy
    # / fragile tool images (e.g. ai-attack-surface, whose pyrit deps need a Rust
    # toolchain on arm64) on an unrelated compose change.
    if echo "$changed_files" | grep -q "^recon/"; then
        rebuild_tools+=(recon)
    fi
    # wcvs: the Web Cache Vulnerability Scanner image (web cache poisoning module),
    # run docker-in-docker by the recon container. Build-only; rebuild when its
    # Dockerfile (or pinned WCVS_REF) changes.
    if echo "$changed_files" | grep -q "^wcvs/"; then
        rebuild_tools+=(wcvs)
    fi
    if echo "$changed_files" | grep -q "^gvm_scan/"; then
        rebuild_tools+=(vuln-scanner)
    fi
    if echo "$changed_files" | grep -q "^github_secret_hunt/"; then
        rebuild_tools+=(github-secret-hunter)
    fi
    if echo "$changed_files" | grep -q "^trufflehog_scan/"; then
        rebuild_tools+=(trufflehog-scanner)
    fi
    if echo "$changed_files" | grep -q "^baddns_scan/"; then
        rebuild_tools+=(baddns-scanner)
    fi
    # ai-attack-surface: heavy build-only image (Node + promptfoo + per-tool venvs).
    # The adapter .py files are volume-mounted into the scan container at spawn
    # (hot-reload, no rebuild); ONLY the baked-in toolchain — the Dockerfile or any
    # requirements file — needs a rebuild.
    if echo "$changed_files" | grep -qE "^ai_attack_surface_scan/(Dockerfile|.*requirements)"; then
        rebuild_tools+=(ai-attack-surface)
    fi
    # codefix-sandbox: the isolated CodeFix build sandbox (T6/E10). Build-only
    # image; rebuild when anything in its build context changes.
    if echo "$changed_files" | grep -q "^codefix_sandbox/"; then
        rebuild_tools+=(codefix-sandbox)
    fi

    # Export version for build arg
    export_version

    # Rebuild tool-profile images. A tool image is build-only (not a running core
    # service), so a failure here must NOT abort the rest of the update (core
    # services, broker, auth key). Warn and continue; the existing tool image keeps
    # working until its build is fixed.
    if [[ ${#rebuild_tools[@]} -gt 0 ]]; then
        info "Rebuilding tool images: ${rebuild_tools[*]}"
        if ! compose_build --profile tools build "${rebuild_tools[@]}"; then
            warn "One or more tool images failed to build (${rebuild_tools[*]}); continuing with the core update. Re-run the build later: docker compose --profile tools build ${rebuild_tools[*]}"
        fi
    fi

    # Rebuild core service images
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Rebuilding service images: ${rebuild_core[*]}"
        compose_build build "${rebuild_core[@]}"
    fi

    # Clean up dangling images left by rebuilds
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Restart rebuilt core services (tool images are build-only, not running).
    # When docker-compose.yml changed (rebuild_all), recreate ALL core services so
    # compose-level changes — e.g. the memory-governor mem_limits + neo4j heap —
    # reach the NON-rebuilt ones too (neo4j, postgres). A per-service --no-deps loop
    # would skip those. export_resource_caps first so the adaptive per-service caps
    # are applied, matching `up`.
    if [[ "$rebuild_all" == "true" ]]; then
        info "Recreating core services to apply docker-compose.yml changes..."
        export_resource_caps
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    elif [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Restarting rebuilt services..."
        for svc in "${rebuild_core[@]}"; do
            docker compose up -d --no-deps "$svc"
        done
    fi

    # Recreate GVM containers when docker-compose.yml changed (picks up command/image/volume changes)
    if [[ "$rebuild_all" == "true" ]] && is_gvm_enabled; then
        info "Recreating GVM containers to apply compose changes..."
        pull_gvm_images true
        docker compose up -d --force-recreate gvm-redis gvm-postgres gvmd gvm-ospd
    fi

    # Restart services with volume-mounted code changes (no rebuild needed)
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        info "Restarting services for code changes: ${restart_only[*]}"
        docker compose restart "${restart_only[@]}"
    fi

    echo ""
    success "Updated to v${new_version}!"
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        local rebuilt_list="${rebuild_core[*]:+${rebuild_core[*]} }${rebuild_tools[*]}"
        echo -e "  ${CYAN}Rebuilt:${NC}  ${rebuilt_list}"
    fi
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Restarted:${NC} ${restart_only[*]}"
    fi
    if [[ ${#rebuild_core[@]} -eq 0 && ${#rebuild_tools[@]} -eq 0 && ${#restart_only[@]} -eq 0 ]]; then
        info "No container images or source code needed updating."
    fi
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
    echo ""

    # Ensure auth secrets exist (first update after auth feature is added)
    ensure_auth_secrets
    ensure_db_secrets

    # Ensure an admin user exists (prompts if none found)
    ensure_admin
}

ensure_tool_images() {
    local missing=false
    for img in $TOOL_IMAGES; do
        if ! docker image inspect "$img" &>/dev/null; then
            missing=true
            break
        fi
    done
    if [[ "$missing" == "true" ]]; then
        info "Tool images not found, building them (first time only)..."
        export_version
        compose_build --profile tools build
        success "Tool images built."
    fi
}

cmd_up_dev() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    local gvm_flag="false"
    if is_gvm_enabled; then
        gvm_flag="true"
    fi

    ensure_tool_images
    ensure_auth_secrets
    ensure_db_secrets

    info "Starting RedAmon in DEV mode (GVM: ${gvm_flag})..."

    if [[ "$gvm_flag" == "true" ]]; then
        pull_gvm_images
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d
    else
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon DEV is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser (hot-reload)${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # Refresh the Knowledge Base if enabled (behavior B -- always run ingest,
    # trust manifest dedup). Same rationale as cmd_up. Dev mode still benefits
    # from fresh KB on restart.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_up() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    local gvm_mode="false"
    if is_gvm_enabled; then
        gvm_mode="true"
    fi

    # Memory governor (Part 4): refuse to start if the host can't hold the core
    # services, and export adaptive per-service memory caps for docker-compose.
    if ! preflight_ram_gate; then
        exit 1
    fi
    export_resource_caps
    setup_zram   # optional one-time compressed-swap cushion (REDAMON_ENABLE_ZRAM=1)

    ensure_tool_images
    ensure_auth_secrets
    ensure_db_secrets

    info "Starting RedAmon (GVM: ${gvm_mode})..."

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d
    else
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # Refresh the Knowledge Base if enabled. Behavior B: always run the ingest
    # pipeline on up. The two-layer dedup (file hashes + manifest) skips
    # unchanged work, and NVD uses the `since` mechanism for incremental
    # updates -- so a routine restart is ~20-30s even though it touches the
    # network. First-ever up is ~2-3 min (full NVD fetch + embedding).
    # Fresh-clone scenario: no FAISS on disk -> full bootstrap.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_down() {
    info "Stopping RedAmon..."
    # The on-demand LLM + any in-flight AI scan containers are orchestrator-spawned
    # (not compose-managed), so stop them too — otherwise the local LLM keeps
    # holding RAM after `down`.
    remove_spawned_containers
    docker compose down
    success "All services stopped. Volumes and images preserved."
}

cmd_clean() {
    warn "This will remove all RedAmon containers and images."
    warn "Your data (databases, reports, scan results) will be preserved in Docker volumes."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers..."
    remove_spawned_containers
    docker compose --profile tools down

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    success "All RedAmon containers and images removed. Volumes preserved."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_purge() {
    echo ""
    warn "This will PERMANENTLY DELETE:"
    warn "  - All RedAmon containers and images"
    warn "  - ALL DATA: PostgreSQL, Neo4j, GVM feeds, reports, scan results"
    warn "  - Host-side KB index state (FAISS index, manifest, last-ingest marker)"
    warn "  - KB dedup state (.manifest.json, .file_hashes.json)"
    warn "  - Downloaded source files under knowledge_base/data/cache are PRESERVED"
    echo ""
    echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
    echo ""
    read -rp "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers and removing volumes..."
    # Remove orchestrator-spawned containers FIRST: the on-demand local LLM holds
    # the models volume, so `down --volumes` can't remove it until that container
    # is gone.
    remove_spawned_containers
    docker compose --profile tools down --volumes --remove-orphans
    # Belt-and-suspenders: explicitly drop the local-LLM models volume in case it
    # was created outside the compose lifecycle.
    docker volume rm "$LOCAL_LLM_VOLUME" >/dev/null 2>&1 || true
    # The CodeFix sandbox network is created at runtime by the orchestrator (no
    # compose service is attached), so `compose down` never removes it.
    docker network rm redamon-codefix-net >/dev/null 2>&1 || true

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    # Host-side KB state files that must be wiped in lockstep with the
    # Neo4j volume. Leaving these behind after a purge causes a
    # split-brain on reinstall: Neo4j is empty but FAISS still has
    # stale vectors, and the dedup layers still think every chunk is
    # already ingested, so the bootstrap build becomes a no-op and
    # Neo4j stays empty.
    #
    # The on-disk content under knowledge_base/data/cache (tarballs,
    # CSVs, YAML templates, markdown) is deliberately preserved —
    # those are ~30+ MB of downloaded source files that don't need to
    # be re-fetched from GitHub/GitLab/NVD on every reinstall. What we
    # DO wipe are the dedup sidecars that model "what Neo4j already
    # has":
    #   - .manifest.json          (chunk-level hash dedup, Layer 2)
    #   - .file_hashes.json       (file-level hash dedup, Layer 1)
    # These live inside data/cache but are state, not content.
    info "Removing host-side KB index state..."
    # These files are created by Docker (root-owned), so normal rm may fail.
    # Try without sudo first; escalate only if needed.
    local kb_files=(
        "$SCRIPT_DIR/knowledge_base/data/index.faiss"
        "$SCRIPT_DIR/knowledge_base/data/chunk_ids.json"
        "$SCRIPT_DIR/knowledge_base/data/index.faiss.manifest.json"
        "$SCRIPT_DIR/knowledge_base/data/.last_ingest"
    )
    if ! rm -f "${kb_files[@]}" 2>/dev/null; then
        warn "Root-owned files detected, elevating with sudo..."
        sudo rm -f "${kb_files[@]}"
    fi

    info "Removing host-side KB dedup state (manifest + file hashes)..."
    if ! rm -f "$SCRIPT_DIR/knowledge_base/data/cache/.manifest.json" 2>/dev/null; then
        sudo rm -f "$SCRIPT_DIR/knowledge_base/data/cache/.manifest.json"
    fi
    # Wipe every per-source .file_hashes.json without touching the
    # downloaded content alongside it. -print is for operator feedback.
    if [[ -d "$SCRIPT_DIR/knowledge_base/data/cache" ]]; then
        if ! find "$SCRIPT_DIR/knowledge_base/data/cache" \
            -type f -name '.file_hashes.json' -print -delete \
            2>/dev/null; then
            sudo find "$SCRIPT_DIR/knowledge_base/data/cache" \
                -type f -name '.file_hashes.json' -print -delete \
                2>/dev/null || true
        fi
    fi

    rm -f "$GVM_FLAG_FILE"
    rm -f "$KBASE_FLAG_FILE"
    rm -f "$KBASE_DISABLED_FLAG_FILE"
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    success "Full cleanup complete. All RedAmon data and images have been removed."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_status() {
    _migrate_legacy_kbase_flag

    local version
    version="$(get_version)"

    print_banner
    echo -e "  ${CYAN}Version:${NC}       v${version}"

    # GVM feature gate
    if is_gvm_enabled; then
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   false"
    fi

    # KB feature gate (from kb_config.yaml / env var)
    if is_kb_enabled; then
        echo -e "  ${CYAN}KB_ENABLED:${NC}    ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}KB_ENABLED:${NC}    false"
    fi

    # KB data state — always shown, independent of KB_ENABLED
    local faiss_count neo4j_count kb_state
    faiss_count=$(_kb_get_faiss_count)
    neo4j_count=$(_kb_get_neo4j_count)

    if [[ "$faiss_count" == "0" && "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}empty${NC}"
    elif [[ "$faiss_count" == "unknown" || "$neo4j_count" == "unknown" ]]; then
        kb_state="${YELLOW}unknown${NC}"
    elif [[ "$faiss_count" == "0" || "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}partial${NC}"
    else
        kb_state="${GREEN}populated${NC}"
    fi
    echo -e "  ${CYAN}KB:${NC}            ${kb_state} (FAISS: ${faiss_count} vectors; NEO4J: ${neo4j_count} chunks)"

    echo ""

    # Container list — filter to redamon containers only. Keeps the header
    # row and any container whose name starts with "redamon-".
    docker compose ps | grep -E '^(NAME|redamon-)' || {
        # grep returns non-zero if no lines match (no containers running).
        # Fall back to plain ps so the user still sees the "no services" message.
        docker compose ps
    }

    # Orchestrator-spawned AI containers (NOT compose-managed, so absent above):
    # the on-demand local LLM + any in-flight AI Attack Surface scan containers.
    local spawned
    spawned=$(docker ps "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" \
                --format '    {{.Names}}  ({{.Status}})' 2>/dev/null || true)
    if [[ -n "$spawned" ]]; then
        echo ""
        echo -e "  ${CYAN}AI Attack Surface (on-demand, orchestrator-spawned):${NC}"
        echo "$spawned"
    fi
}

# ---------------------------------------------------------------------------
# Knowledge Base commands
# ---------------------------------------------------------------------------

cmd_kb_build() {
    local profile="${1:-lite}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Unknown KB profile: $profile"
            echo "Usage: ./redamon.sh kb build [lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    info "Building Knowledge Base (profile=${profile})"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Running ingestion pipeline..."
    if ! make -C knowledge_base "kb-build-${profile}" MODE=docker; then
        error "KB build failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base built successfully"
    make -C knowledge_base kb-stats MODE=docker
}

cmd_kb_update() {
    local source="${1:-}"

    print_banner
    _kb_export_env
    _kb_wait_neo4j || exit 1

    if [[ -n "$source" ]]; then
        case "$source" in
            nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools) ;;
            *)
                error "Unknown KB source: $source"
                echo "Valid sources: nvd, exploitdb, nuclei, gtfobins, lolbas, owasp, tools"
                exit 1
                ;;
        esac
        info "Updating KB source: ${source}"
        if ! make -C knowledge_base "kb-update-${source}" MODE=docker; then
            error "KB update failed for ${source}"
            exit 1
        fi
    else
        info "Updating all KB sources (incremental)"
        local failed=()
        for src in nvd exploitdb nuclei gtfobins lolbas owasp tools; do
            echo ""
            info "→ ${src}"
            make -C knowledge_base "kb-update-${src}" MODE=docker || failed+=("$src")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo ""
            warn "Some sources failed to update: ${failed[*]}"
        fi
    fi

    echo ""
    success "Knowledge Base update complete"
    make -C knowledge_base kb-stats MODE=docker
}

cmd_kb_rebuild() {
    local profile="${1:-standard}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Invalid profile '$profile'. Use cpu-lite, lite, standard, or full."
            echo "Usage: ./redamon.sh kb rebuild [cpu-lite|lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    warn "This will WIPE and rebuild the entire Knowledge Base."
    info "Profile: $profile"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Rebuilding Knowledge Base from scratch..."
    if ! make -C knowledge_base "kb-rebuild-${profile}" MODE=docker; then
        error "KB rebuild failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base rebuilt"
    make -C knowledge_base kb-stats MODE=docker
}

cmd_kb_stats() {
    _kb_export_env
    _kb_wait_neo4j || exit 1
    make -C knowledge_base kb-stats MODE=docker
}

cmd_kb_help() {
    echo -e "${BOLD}Usage:${NC} ./redamon.sh kb <command> [args]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}build [profile]${NC}    Build KB — profile: lite (default) | standard | full"
    echo -e "  ${GREEN}update [source]${NC}    Update KB — all sources, or one: nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools"
    echo -e "  ${GREEN}rebuild${NC}            Wipe and rebuild (standard profile)"
    echo -e "  ${GREEN}stats${NC}              Show FAISS + Neo4j chunk counts"
    echo -e "  ${GREEN}help${NC}               Show this help"
    echo ""
    echo -e "${BOLD}Profiles:${NC}"
    echo "  lite      tool_docs + metasploit + gtfobins + lolbas + owasp + exploitdb + NVD (90 days)"
    echo "  standard  same sources as lite + NVD (2 years)"
    echo "  full      standard + Nuclei (requires redamon-kali container running)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh kb build             # Build lite KB (default)"
    echo "  ./redamon.sh kb build standard    # Build with 2 years of NVD"
    echo "  ./redamon.sh kb rebuild           # Wipe + rebuild standard (default)"
    echo "  ./redamon.sh kb rebuild lite      # Wipe + rebuild lite profile"
    echo "  ./redamon.sh kb rebuild full      # Wipe + rebuild full profile (incl. nuclei)"
    echo "  ./redamon.sh kb update nvd        # Incremental NVD refresh"
    echo "  ./redamon.sh kb update            # Update all sources"
    echo "  ./redamon.sh kb stats             # See what's in the KB"
    echo ""
}

cmd_help() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./redamon.sh <command> [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}              Build and start RedAmon (no GVM, no Knowledge Base)"
    echo -e "  ${GREEN}install --gvm${NC}        Build and start RedAmon (with GVM/OpenVAS)"
    echo -e "  ${GREEN}install --kbase${NC}      Build with Knowledge Base (~4.4 GB heavier, local KB enabled)"
    echo -e "  ${GREEN}update${NC}           Pull latest version and smart-rebuild changed services"
    echo -e "  ${GREEN}up${NC}               Start services"
    echo -e "  ${GREEN}up dev${NC}           Start in dev mode (hot-reload, auto-detects GVM mode)"
    echo -e "  ${GREEN}down${NC}             Stop services (preserves data)"
    echo -e "  ${GREEN}clean${NC}            Remove containers and images (keeps data)"
    echo -e "  ${GREEN}purge${NC}            Remove everything including all data"
    echo -e "  ${GREEN}status${NC}           Show running services, version, GVM, and KB state"
    echo -e "  ${GREEN}kb <command>${NC}     Knowledge Base management (build/update/rebuild/stats)"
    echo -e "  ${GREEN}help${NC}             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh install               # First-time setup (lightweight: no GVM, no KB)"
    echo "  ./redamon.sh install --kbase       # First-time setup with local Knowledge Base"
    echo "  ./redamon.sh install --gvm         # First-time setup with GVM/OpenVAS"
    echo "  ./redamon.sh install --gvm --kbase # First-time setup with everything"
    echo "  ./redamon.sh update           # Update to latest version"
    echo "  ./redamon.sh up               # Start after reboot"
    echo "  ./redamon.sh up dev           # Dev mode with hot-reload (auto-detects GVM)"
    echo "  ./redamon.sh reset-password   # Reset a user's password"
    echo "  ./redamon.sh kb build lite    # Build Knowledge Base"
    echo "  ./redamon.sh kb update        # Refresh all KB sources"
    echo "  ./redamon.sh kb stats         # Show KB chunk counts"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Dispatch only when executed directly. When the script is sourced (e.g. by the
# test suite in tests/redamon_build_test.sh) this guard prevents the cd and the
# command dispatch from running, so the helper functions can be loaded and unit-
# tested in isolation.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
cd "$SCRIPT_DIR"

case "${1:-help}" in
    install) shift; cmd_install "$@" ;;
    update)  cmd_update ;;
    up)
        if [[ "${2:-}" == "dev" ]]; then
            cmd_up_dev
        else
            cmd_up
        fi
        ;;
    down)    cmd_down ;;
    clean)   cmd_clean ;;
    purge)   cmd_purge ;;
    status)  cmd_status ;;
    kb)
        shift
        case "${1:-help}" in
            build)   shift; cmd_kb_build   "${1:-lite}" ;;
            update)  shift; cmd_kb_update  "${1:-}" ;;
            rebuild) shift; cmd_kb_rebuild "${1:-standard}" ;;
            stats)   cmd_kb_stats ;;
            help|--help|-h|"") cmd_kb_help ;;
            *)
                error "Unknown kb command: $1"
                cmd_kb_help
                exit 1
                ;;
        esac
        ;;
    reset-password) cmd_reset_password ;;
    help|--help|-h) cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
fi
