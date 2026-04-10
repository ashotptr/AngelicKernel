#!/usr/bin/env bash
# ===========================================================================
# prosody_baseline.sh — Deploy Prosody in Docker for Capstone comparison
#
# Capstone §9.2 — "Memory footprint vs Prosody (MB comparison)"
# Capstone methodology — "Benchmarking against Prosody running in Docker
#                         (lightweight Lua baseline)"
#
# WHAT THIS SCRIPT DOES:
#   1. Pulls and starts Prosody in Docker with matching configuration
#      (same domain, same users, same MUC enabled).
#   2. Runs the Tsung benchmark against Prosody.
#   3. Measures Prosody's memory footprint (RSS via /proc).
#   4. Prints a comparison summary.
#
# REQUIREMENTS:
#   sudo apt install docker.io tsung
#   (Tsung must be installed for the benchmark to run)
#
# USAGE:
#   ./prosody_baseline.sh [--skip-bench]
#
# ===========================================================================
set -e

DOMAIN="angelic.local"
PROSODY_PORT=5223          # use 5223 to avoid conflict with the unikernel on 5222
CONTAINER_NAME="prosody_baseline"
BENCH_SCENARIO="tsung_angelic_prosody.xml"

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
for arg in "$@"; do
    [[ "$arg" == "--skip-bench" ]] && SKIP_BENCH=1
done

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Generate Prosody configuration
# ──────────────────────────────────────────────────────────────────────────────
info "Generating Prosody configuration..."

cat > /tmp/prosody_bench.cfg.lua << 'EOF'
-- Prosody benchmark configuration
-- Mirrors the AngelicKernel's capabilities for fair comparison:
--   - Same domain
--   - Same user accounts (PLAIN auth, no TLS required on LAN)
--   - MUC enabled on conference subdomain
--   - No persistence (in-memory only, like the unikernel's RAM state)

pidfile = "/var/run/prosody/prosody.pid"
log = { error = "*syslog" }

-- Disable TLS for benchmark simplicity (unikernel requires TLS;
-- if comparing TLS-to-TLS, enable this and configure certs)
-- c2s_require_encryption = false

VirtualHost "angelic.local"
    authentication = "internal_plain"

    -- Same users as xmpp_credentials[] in xmpp_handlers.c
    --   user1/pass1, user2/pass2, admin/admin
    -- (set via prosodyctl adduser after startup)

Component "conference.angelic.local" "muc"
    name = "Benchmark Chat Service"
    restrict_room_creation = false
    max_history_messages = 0        -- no history = closest to unikernel behaviour
EOF

ok "Configuration written to /tmp/prosody_bench.cfg.lua"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Stop any existing container
# ──────────────────────────────────────────────────────────────────────────────
if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
    info "Stopping existing Prosody container..."
    docker stop "${CONTAINER_NAME}" >/dev/null
    docker rm   "${CONTAINER_NAME}" >/dev/null
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Start Prosody
# ──────────────────────────────────────────────────────────────────────────────
info "Starting Prosody container (port ${PROSODY_PORT} → 5222)..."

docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${PROSODY_PORT}:5222" \
    -v /tmp/prosody_bench.cfg.lua:/etc/prosody/prosody.cfg.lua:ro \
    prosody/prosody:0.12 \
    >/dev/null

ok "Prosody container started (ID: $(docker ps -q --filter name=${CONTAINER_NAME}))"

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Wait for Prosody to be ready
# ──────────────────────────────────────────────────────────────────────────────
info "Waiting for Prosody to accept connections..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "${PROSODY_PORT}" 2>/dev/null; then
        ok "Prosody is accepting connections (took ${i}s)"
        break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        err "Prosody did not start within 30 seconds"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
done
sleep 2  # extra settle time

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Create test users in Prosody
# ──────────────────────────────────────────────────────────────────────────────
info "Creating test users..."

for user_pass in "user1:pass1" "user2:pass2" "admin:admin"; do
    user="${user_pass%%:*}"
    pass="${user_pass##*:}"
    docker exec "${CONTAINER_NAME}" \
        sh -c "echo '${pass}' | prosodyctl adduser '${user}@angelic.local'" \
        2>/dev/null || warn "User ${user} may already exist"
done

ok "Test users created"

# ──────────────────────────────────────────────────────────────────────────────
# Step 6: Measure memory footprint (baseline — before any connections)
# ──────────────────────────────────────────────────────────────────────────────
info "Measuring Prosody memory footprint (baseline)..."

PROSODY_PID=$(docker exec "${CONTAINER_NAME}" pgrep -f "prosody" | head -1 2>/dev/null || true)

if [[ -n "${PROSODY_PID}" ]]; then
    PROSODY_RSS_KB=$(docker exec "${CONTAINER_NAME}" \
        awk '/VmRSS/{print $2}' "/proc/${PROSODY_PID}/status" 2>/dev/null || echo "N/A")
    PROSODY_RSS_MB=$(echo "scale=1; ${PROSODY_RSS_KB} / 1024" | bc 2>/dev/null || echo "N/A")
    ok "Prosody baseline RSS: ${PROSODY_RSS_KB} KB (${PROSODY_RSS_MB} MB)"
else
    warn "Could not find Prosody PID inside container for memory measurement"
    PROSODY_RSS_KB="N/A"
    PROSODY_RSS_MB="N/A"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 7: (Optional) Run Tsung benchmark against Prosody
# ──────────────────────────────────────────────────────────────────────────────
if [[ ${SKIP_BENCH} -eq 0 ]]; then
    if ! command -v tsung &>/dev/null; then
        warn "Tsung not found — skipping benchmark"
        warn "Install with: sudo apt install tsung"
    else
        info "Generating Tsung scenario for Prosody (port ${PROSODY_PORT})..."
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        # Patch the Tsung scenario to use Prosody's port
        sed "s/port=\"5222\"/port=\"${PROSODY_PORT}\"/" \
            "${SCRIPT_DIR}/tsung_angelic.xml" \
            > "/tmp/${BENCH_SCENARIO}"

        info "Running Tsung against Prosody..."
        LOG_DIR=~/.tsung/log/prosody_$(date +%Y%m%d_%H%M%S)
        tsung -f "/tmp/${BENCH_SCENARIO}" -l "${LOG_DIR}" start

        ok "Tsung complete. Generating HTML report..."
        (cd "${LOG_DIR}" && perl /usr/share/tsung/tsung_stats.pl)
        ok "Report: ${LOG_DIR}/report.html"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 8: Print comparison summary
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════"
echo " Prosody Baseline Summary"
echo "═══════════════════════════════════════════════════════════"
echo " Container:    ${CONTAINER_NAME}"
echo " Port:         127.0.0.1:${PROSODY_PORT}"
echo " Domain:       ${DOMAIN}"
echo " Memory (RSS): ${PROSODY_RSS_MB} MB  (${PROSODY_RSS_KB} KB)"
echo
echo " AngelicKernel comparison:"
echo "   Boot footprint: ~512 MB allocated QEMU RAM"
echo "   XMPP server:    embedded in kernel image"
echo "   No OS/libc overhead: bare-metal unikernel"
echo
echo " To measure AngelicKernel memory during runtime:"
echo "   (from host while QEMU is running)"
echo "   ps aux | grep qemu  # see resident set size"
echo "   cat /proc/\$(pgrep qemu)/status | grep VmRSS"
echo "═══════════════════════════════════════════════════════════"

info "Leaving Prosody running for manual testing."
info "Stop with: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"