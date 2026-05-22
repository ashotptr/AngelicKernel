#!/usr/bin/env bash

set -e

DOMAIN="angelic.local"
XMPP_PORT=5223
ADMIN_PORT=9090
CONTAINER_NAME="openfire_baseline"
BENCH_SCENARIO="tsung_angelic_openfire.xml"

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
NO_DOCKER=0
for arg in "$@"; do
    [[ "$arg" == "--skip-bench" ]] && SKIP_BENCH=1
    [[ "$arg" == "--no-docker" ]] && NO_DOCKER=1
done

if [[ ${NO_DOCKER} -eq 0 ]]; then
    if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
        info "stopping existing openfire container"
        docker stop "${CONTAINER_NAME}" >/dev/null
        docker rm "${CONTAINER_NAME}" >/dev/null
    fi

    info "starting openfire container (xmpp port ${XMPP_PORT}, admin ${ADMIN_PORT})"

    docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${XMPP_PORT}:5222" \
    -p "${ADMIN_PORT}:9090" \
    sameersbn/openfire:latest \
    >/dev/null

    ok "openfire container started (id: $(docker ps -q --filter name=${CONTAINER_NAME}))"

    info "waiting for openfire web admin (port ${ADMIN_PORT})"
    for i in $(seq 1 60); do
        if nc -z 127.0.0.1 "${ADMIN_PORT}" 2>/dev/null; then
            ok "openfire admin port open (took ${i}s)"
            break
        fi
        sleep 2
        if [[ $i -eq 60 ]]; then
            err "openfire admin port not open within 120s"
            docker logs "${CONTAINER_NAME}" | tail -20
            exit 1
        fi
    done

    sleep 5

    info "waiting for openfire rest api to become available"
    for i in $(seq 1 45); do
        if curl -sf -u "admin:admin" \
                "http://127.0.0.1:${ADMIN_PORT}/plugins/restapi/v1/system/properties" \
                >/dev/null 2>&1; then
            ok "openfire REST api ready (took ${i}s)"
            break
        fi
        sleep 2
        if [[ $i -eq 45 ]]; then
            warn "REST api not ready in 90s — proceeding anyway"
        fi
    done


    sleep 5

    info "waiting for openfire xmpp port ${XMPP_PORT}"
    for i in $(seq 1 30); do
        if nc -z 127.0.0.1 "${XMPP_PORT}" 2>/dev/null; then
            ok "openfire xmpp port ready (took ${i}s)"
            break
        fi
        sleep 1
        if [[ $i -eq 30 ]]; then
            warn "xmpp port not ready in 30s, may still be initialising"
        fi
    done
    sleep 3

    info "creating test users via openfire rest api"

    BASE_URL="http://127.0.0.1:${ADMIN_PORT}/plugins/restapi/v1"
    AUTH="admin:admin"

    for user_pass in "user1:pass1" "user2:pass2"; do
        username="${user_pass%%:*}"
        password="${user_pass##*:}"

        curl -sf -X POST "${BASE_URL}/users" \
             -u "${AUTH}" \
             -H "Content-Type: application/json" \
             -d "{\"username\":\"${username}\",\"password\":\"${password}\",\"email\":\"${username}@${DOMAIN}\"}" \
             >/dev/null 2>&1 && ok "user ${username} created" \
             || warn "user ${username} may already exist or rest api not ready"
    done

    info "enabling muc service"
    curl -sf -X POST "${BASE_URL}/chatrooms" \
         -u "${AUTH}" \
         -H "Content-Type: application/json" \
         -d '{"roomName":"benchroom","naturalName":"benchmark room","description":"load test room","persistent":true}' \
         >/dev/null 2>&1 || warn "could not pre-create muc room (may be auto-created)"
fi

info "measuring openfire memory footprint"

OF_PID=$(docker exec "${CONTAINER_NAME}" sh -c "ps aux | grep '[o]penfire' | awk '{print \$2}'" 2>/dev/null | head -1 || true)

if [[ -n "${OF_PID}" && "${OF_PID}" != "0" ]]; then
    OF_RSS_KB=$(docker exec "${CONTAINER_NAME}" \
        awk '/VmRSS/{print $2}' "/proc/${OF_PID}/status" 2>/dev/null || echo "N/A")
    OF_RSS_MB=$(echo "scale=0; ${OF_RSS_KB:-0} / 1024" | bc 2>/dev/null || echo "N/A")
    OF_RSS_MB="${OF_RSS_MB:-N/A}"
    ok "openfire baseline rss: ${OF_RSS_KB} kb (${OF_RSS_MB} mb)"
else
    DOCKER_STATS=$(docker stats --no-stream --format "{{.MemUsage}}" "${CONTAINER_NAME}" 2>/dev/null | head -1 || echo "N/A")
    warn "could not read /proc rss directly, docker stats: ${DOCKER_STATS}"
    OF_RSS_KB="N/A"
    OF_RSS_MB="N/A"
fi

if [[ ${SKIP_BENCH} -eq 0 ]]; then
    if ! command -v tsung &>/dev/null; then
        warn "tsung not found, skipping benchmark"
        warn "install: sudo apt install tsung"
    else
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        info "generating tsung scenario for openfire (port ${XMPP_PORT})"
        sed "s/port=\"5222\"/port=\"${XMPP_PORT}\"/" \
            "${SCRIPT_DIR}/tsung_angelic.xml" \
            > "/tmp/${BENCH_SCENARIO}"

        info "running tsung against openfire"
        LOG_DIR=~/.tsung/log/openfire_$(date +%Y%m%d_%H%M%S)
        tsung -f "/tmp/${BENCH_SCENARIO}" -l "${LOG_DIR}" start

        ok "tsung complete, generating report"
        (cd "${LOG_DIR}" && perl /usr/share/tsung/tsung_stats.pl)
        ok "report: ${LOG_DIR}/report.html"
    fi
fi

echo
echo "openfire baseline summary"
echo "container: ${CONTAINER_NAME}"
echo "xmpp port: 127.0.0.1:${XMPP_PORT}"
echo "admin port: 127.0.0.1:${ADMIN_PORT} (admin/admin)"
echo "domain: ${DOMAIN}"
echo "memory (rss): ${OF_RSS_MB} mb (${OF_RSS_KB} kb)"
echo
echo "summary"
echo "server │ rss idle │ "
echo "openfire │ ${OF_RSS_MB} │ ? "

if [[ ${NO_DOCKER} -eq 0 ]]; then
    info "leaving openfire running for manual testing"
    info "admin ui: http://localhost:${ADMIN_PORT} (admin/admin)"
    info "stop: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"
fi
