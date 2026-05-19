#!/usr/bin/env bash

set -e

DOMAIN="angelic.local"
PROSODY_PORT=5223
CONTAINER_NAME="prosody_baseline"
BENCH_SCENARIO="tsung_angelic_prosody.xml"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${CYAN}[info]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[error]${NC} $*" >&2; }

SKIP_BENCH=0
for arg in "$@"; do
    [[ "$arg" == "--skip-bench" ]] && SKIP_BENCH=1
done

info "generating prosody configuration"

cat > /tmp/prosody_bench.cfg.lua << 'EOF'
pidfile = "/var/run/prosody/prosody.pid"
log = { error = "*syslog" }

VirtualHost "angelic.local"
    authentication = "internal_plain"

Component "conference.angelic.local" "muc"
    name = "Benchmark Chat Service"
    restrict_room_creation = false
    max_history_messages = 0
EOF

ok "configuration written to /tmp/prosody_bench.cfg.lua"

if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
    info "stopping existing prosody container"
    docker stop "${CONTAINER_NAME}" >/dev/null
    docker rm "${CONTAINER_NAME}" >/dev/null
fi

info "starting prosody container (port ${PROSODY_PORT} → 5222)"

docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${PROSODY_PORT}:5222" \
    -v /tmp/prosody_bench.cfg.lua:/etc/prosody/prosody.cfg.lua:ro \
    prosody/prosody:latest \
    >/dev/null

ok "prosody container started (id: $(docker ps -q --filter name=${CONTAINER_NAME}))"

info "waiting for prosody to accept connections"
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "${PROSODY_PORT}" 2>/dev/null; then
        ok "prosody is accepting connections (took ${i}s)"
        break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        err "prosody did not start within 30 seconds"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
done
sleep 2

info "creating test users"

for user_pass in "user1:pass1" "user2:pass2" "admin:admin"; do
    user="${user_pass%%:*}"
    pass="${user_pass##*:}"
    docker exec "${CONTAINER_NAME}" \
        sh -c "echo '${pass}' | prosodyctl adduser '${user}@angelic.local'" \
        2>/dev/null || warn "User ${user} may already exist"
done

ok "test users created"

info "measuring prosody memory footprint (baseline)"

PROSODY_PID=$(docker exec "${CONTAINER_NAME}" pgrep -f "prosody" | head -1 2>/dev/null || true)

if [[ -n "${PROSODY_PID}" ]]; then
    PROSODY_RSS_KB=$(docker exec "${CONTAINER_NAME}" \
        awk '/VmRSS/{print $2}' "/proc/${PROSODY_PID}/status" 2>/dev/null || echo "N/A")
    PROSODY_RSS_MB=$(echo "scale=1; ${PROSODY_RSS_KB} / 1024" | bc 2>/dev/null || echo "N/A")
    ok "prosody baseline rss: ${PROSODY_RSS_KB} kb (${PROSODY_RSS_MB} mb)"
else
    warn "could not find prosody pid inside container for memory measurement"
    PROSODY_RSS_KB="N/A"
    PROSODY_RSS_MB="N/A"
fi

if [[ ${SKIP_BENCH} -eq 0 ]]; then
    if ! command -v tsung &>/dev/null; then
        warn "tsung not found, skipping benchmark"
        warn "install with: sudo apt install tsung"
    else
        info "generating tsung scenario for prosody (port ${PROSODY_PORT})"
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        sed "s/port=\"5222\"/port=\"${PROSODY_PORT}\"/" \
            "${SCRIPT_DIR}/tsung_angelic.xml" \
            > "/tmp/${BENCH_SCENARIO}"

        info "running tsung against prosody"
        LOG_DIR=~/.tsung/log/prosody_$(date +%Y%m%d_%H%M%S)
        tsung -f "/tmp/${BENCH_SCENARIO}" -l "${LOG_DIR}" start

        ok "tsung complete, generating html report"
        (cd "${LOG_DIR}" && perl /usr/share/tsung/tsung_stats.pl)
        ok "report: ${LOG_DIR}/report.html"
    fi
fi

echo
echo "prosody baseline summary"
echo "container: ${CONTAINER_NAME}"
echo "port: 127.0.0.1:${PROSODY_PORT}"
echo "domain: ${DOMAIN}"
echo "memory (RSS): ${PROSODY_RSS_MB} mb (${PROSODY_RSS_KB} kb)"
echo
echo "AngelicKernel comparison:"
echo "boot footprint: ~512 mb allocated qemu ram"
echo "xmpp server: embedded in kernel image"
echo "no os/libc overhead: bare-metal unikernel"
echo
echo "to measure AngelicKernel memory during runtime:"
echo "(from host while qemu is running)"
echo "ps aux | grep qemu # see resident set size"
echo "cat /proc/\$(pgrep qemu)/status | grep VmRSS"

info "leaving prosody running for manual testing"
info "stop with: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"