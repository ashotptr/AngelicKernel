#!/usr/bin/env bash
# ===========================================================================
# openfire_baseline.sh — Deploy Openfire in Docker for Capstone comparison
#
# Capstone §9.2 — "Benchmarking against Openfire (heavyweight Java baseline)"
# Capstone methodology — Comparison baselines table in the paper
#
# WHAT THIS SCRIPT DOES:
#   1. Pulls and starts Openfire in Docker.
#   2. Waits for the web admin interface to be ready.
#   3. Creates test users via Openfire's REST API (XEP-0077 / admin API).
#   4. Measures Openfire's memory footprint (RSS via /proc in the container).
#   5. Optionally runs the Tsung benchmark scenario against Openfire.
#   6. Prints a comparison summary vs AngelicKernel and Prosody.
#
# REQUIREMENTS:
#   sudo apt install docker.io tsung curl
#
# USAGE:
#   ./openfire_baseline.sh              # full run (deploy + RSS + optional Tsung)
#   ./openfire_baseline.sh --skip-bench # deploy only, no Tsung
#   ./openfire_baseline.sh --no-docker  # assume Openfire already running on port 5223
#
# NOTES ON OPENFIRE SETUP:
#   Openfire requires a database. The official Docker image defaults to an
#   embedded HSQLDB which is fine for benchmarking. On first start, Openfire
#   must be initialised via its web admin UI (http://localhost:9090).
#   This script automates that initialisation via the REST API.
# ===========================================================================
set -e

DOMAIN="angelic.local"
XMPP_PORT=5223         # avoid conflict with unikernel on 5222
ADMIN_PORT=9090
CONTAINER_NAME="openfire_baseline"
BENCH_SCENARIO="tsung_angelic_openfire.xml"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

SKIP_BENCH=0
NO_DOCKER=0
for arg in "$@"; do
    [[ "$arg" == "--skip-bench" ]] && SKIP_BENCH=1
    [[ "$arg" == "--no-docker"  ]] && NO_DOCKER=1
done

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Start Openfire container
# ──────────────────────────────────────────────────────────────────────────────
if [[ ${NO_DOCKER} -eq 0 ]]; then
    if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
        info "Stopping existing Openfire container..."
        docker stop "${CONTAINER_NAME}" >/dev/null
        docker rm   "${CONTAINER_NAME}" >/dev/null
    fi

    info "Starting Openfire container (XMPP port ${XMPP_PORT}, admin ${ADMIN_PORT})..."

    # The sameersbn/openfire image is a well-maintained community image.
    # We map the XMPP port to 5223 and admin to 9090.
    docker run -d \
        --name "${CONTAINER_NAME}" \
        -p "${XMPP_PORT}:5222" \
        -p "${ADMIN_PORT}:9090" \
        -e OPENFIRE_DOMAIN="${DOMAIN}" \
        sameersbn/openfire:latest \
        >/dev/null

    ok "Openfire container started (ID: $(docker ps -q --filter name=${CONTAINER_NAME}))"

    # ── Wait for Openfire web admin ──────────────────────────────────────
    info "Waiting for Openfire web admin (port ${ADMIN_PORT})..."
    for i in $(seq 1 60); do
        if curl -sf "http://127.0.0.1:${ADMIN_PORT}/setup/index.jsp" >/dev/null 2>&1; then
            ok "Openfire web admin ready (took ${i}s)"
            break
        fi
        sleep 2
        if [[ $i -eq 60 ]]; then
            err "Openfire admin UI not ready within 120s"
            docker logs "${CONTAINER_NAME}" | tail -20
            exit 1
        fi
    done

    # ── Automated setup via REST API ─────────────────────────────────────
    info "Initialising Openfire via REST API..."

    # Step 1: Complete the setup wizard (embedded DB, default admin credentials)
    # The setup wizard has a specific sequence:
    # 1. Set server name
    # 2. Choose database (embedded)
    # 3. Set admin credentials
    # 4. Finish
    #
    # Openfire's setup API is documented at:
    # https://www.igniterealtime.org/projects/openfire/documentation.jsp

    # POST to complete setup with embedded database
    curl -sf -X POST "http://127.0.0.1:${ADMIN_PORT}/setup/setup-datasource-embedded.jsp" \
         --data-urlencode "continue=true" \
         >/dev/null 2>&1 || true

    # Set server name
    curl -sf -X POST "http://127.0.0.1:${ADMIN_PORT}/setup/setup-host-settings.jsp" \
         -d "domain=${DOMAIN}&serverName=${DOMAIN}&continue=true" \
         >/dev/null 2>&1 || true

    # Skip profile settings (default)
    curl -sf -X POST "http://127.0.0.1:${ADMIN_PORT}/setup/setup-profile-settings.jsp" \
         -d "storageType=default&continue=true" \
         >/dev/null 2>&1 || true

    # Set admin password
    curl -sf -X POST "http://127.0.0.1:${ADMIN_PORT}/setup/setup-admin-settings.jsp" \
         -d "email=admin@angelic.local&newPassword=admin&newPasswordConfirm=admin&continue=true" \
         >/dev/null 2>&1 || true

    # Finish
    curl -sf -X POST "http://127.0.0.1:${ADMIN_PORT}/setup/setup-finished.jsp" \
         -d "continue=true" \
         >/dev/null 2>&1 || true

    sleep 5

    # ── Wait for XMPP port ───────────────────────────────────────────────
    info "Waiting for Openfire XMPP port ${XMPP_PORT}..."
    for i in $(seq 1 30); do
        if nc -z 127.0.0.1 "${XMPP_PORT}" 2>/dev/null; then
            ok "Openfire XMPP port ready (took ${i}s)"
            break
        fi
        sleep 1
        if [[ $i -eq 30 ]]; then
            warn "XMPP port not ready in 30s — may still be initialising"
        fi
    done
    sleep 3

    # ── Create test users via REST API ────────────────────────────────────
    info "Creating test users via Openfire REST API..."

    # Openfire REST API plugin must be enabled. The sameersbn image includes it.
    # Auth: Basic admin:admin
    BASE_URL="http://127.0.0.1:${ADMIN_PORT}/plugins/restapi/v1"
    AUTH="admin:admin"

    for user_pass in "user1:pass1" "user2:pass2"; do
        username="${user_pass%%:*}"
        password="${user_pass##*:}"

        curl -sf -X POST "${BASE_URL}/users" \
             -u "${AUTH}" \
             -H "Content-Type: application/json" \
             -d "{\"username\":\"${username}\",\"password\":\"${password}\",\"email\":\"${username}@${DOMAIN}\"}" \
             >/dev/null 2>&1 && ok "User ${username} created" \
             || warn "User ${username} may already exist or REST API not ready"
    done

    info "Enabling MUC service..."
    curl -sf -X POST "${BASE_URL}/chatrooms" \
         -u "${AUTH}" \
         -H "Content-Type: application/json" \
         -d '{"roomName":"benchroom","naturalName":"Benchmark Room","description":"Load test room","persistent":true}' \
         >/dev/null 2>&1 || warn "Could not pre-create MUC room (may be auto-created)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Measure memory footprint
# ──────────────────────────────────────────────────────────────────────────────
info "Measuring Openfire memory footprint..."

# Openfire is a Java process; measure the JVM's RSS
OF_PID=$(docker exec "${CONTAINER_NAME}" sh -c "ps aux | grep '[o]penfire' | awk '{print \$2}'" 2>/dev/null | head -1 || true)

if [[ -n "${OF_PID}" && "${OF_PID}" != "0" ]]; then
    OF_RSS_KB=$(docker exec "${CONTAINER_NAME}" \
        awk '/VmRSS/{print $2}' "/proc/${OF_PID}/status" 2>/dev/null || echo "N/A")
    OF_RSS_MB=$(echo "scale=0; ${OF_RSS_KB:-0} / 1024" | bc 2>/dev/null || echo "N/A")
    OF_RSS_MB="${OF_RSS_MB:-N/A}"
    ok "Openfire baseline RSS: ${OF_RSS_KB} KB (${OF_RSS_MB} MB)"
else
    # Alternative: use docker stats
    DOCKER_STATS=$(docker stats --no-stream --format "{{.MemUsage}}" "${CONTAINER_NAME}" 2>/dev/null | head -1 || echo "N/A")
    warn "Could not read /proc RSS directly. Docker stats: ${DOCKER_STATS}"
    OF_RSS_KB="N/A"
    OF_RSS_MB="N/A"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Optional Tsung benchmark
# ──────────────────────────────────────────────────────────────────────────────
if [[ ${SKIP_BENCH} -eq 0 ]]; then
    if ! command -v tsung &>/dev/null; then
        warn "Tsung not found — skipping benchmark"
        warn "Install: sudo apt install tsung"
    else
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        info "Generating Tsung scenario for Openfire (port ${XMPP_PORT})..."
        sed "s/port=\"5222\"/port=\"${XMPP_PORT}\"/" \
            "${SCRIPT_DIR}/tsung_angelic.xml" \
            > "/tmp/${BENCH_SCENARIO}"

        info "Running Tsung against Openfire..."
        LOG_DIR=~/.tsung/log/openfire_$(date +%Y%m%d_%H%M%S)
        tsung -f "/tmp/${BENCH_SCENARIO}" -l "${LOG_DIR}" start

        ok "Tsung complete. Generating report..."
        (cd "${LOG_DIR}" && perl /usr/share/tsung/tsung_stats.pl)
        ok "Report: ${LOG_DIR}/report.html"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Print comparison summary
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════"
echo " Openfire Baseline Summary"
echo "═══════════════════════════════════════════════════════════"
echo " Container:    ${CONTAINER_NAME}"
echo " XMPP Port:    127.0.0.1:${XMPP_PORT}"
echo " Admin Port:   127.0.0.1:${ADMIN_PORT}  (admin/admin)"
echo " Domain:       ${DOMAIN}"
echo " Memory (RSS): ${OF_RSS_MB} MB  (${OF_RSS_KB} KB)"
echo
echo " Comparison summary (fill in from actual Tsung results):"
echo "═══════════════════════════════════════════════════════════"
echo " Server             │ RSS idle │ P50 lat  │ Peak msg/s"
echo " ───────────────────┼──────────┼──────────┼──────────"
echo " AngelicKernel      │  ? MB    │  ? ms    │  ?       "
echo " Prosody 0.12 (Lua) │  ? MB    │  ? ms    │  ?       "
echo " Openfire 4.8 (JVM) │ ${OF_RSS_MB} MB│  ? ms    │  ?       "
echo "═══════════════════════════════════════════════════════════"
echo
echo " Openfire footnotes:"
echo "   - JVM requires ~200-400 MB RSS at idle (includes JIT code cache)"
echo "   - GC pauses add latency jitter not present in unikernel"
echo "   - Startup time: typically 30-60 s vs <1 s for AngelicKernel"
echo
echo " Relevant Capstone §9.2 metric: Memory footprint vs Prosody"
echo "   If AngelicKernel < Prosody < Openfire: all three tiers confirmed."
echo "═══════════════════════════════════════════════════════════"

if [[ ${NO_DOCKER} -eq 0 ]]; then
    info "Leaving Openfire running for manual testing."
    info "Admin UI: http://localhost:${ADMIN_PORT}  (admin/admin)"
    info "Stop: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"
fi
