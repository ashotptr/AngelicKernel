# AngelicKernel XMPP — Testing & Benchmarking Guide

## Quick Start

```bash
cd testing && bash run_all_benchmarks.sh
```

Results land in `testing/results/TIMESTAMP/`.

---

## Project Structure

```
testing/
├── raw_tests/raw_xmpp_tester.py     # Low-level RFC 6120/6121/XEP-0045 tests
├── slixmpp_tests/slixmpp_suite.py   # Async higher-level tests
├── compliance/compliance_report.py  # Combined markdown report
├── benchmarks/                      # Boot, load, baseline scripts
└── graphs/generate_graphs.py        # Paper figures
```

---

## Test Suites

### Layer 1 — Raw TCP

```bash
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --filter 6120
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --filter 6121
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --filter 0045
python3 raw_tests/raw_xmpp_tester.py --host angelic.local --port 5222 --json graphs/data/compliance.json
```

### Layer 2 — slixmpp Async

```bash
python3 slixmpp_tests/slixmpp_suite.py --host angelic.local --port 5222
python3 slixmpp_tests/slixmpp_suite.py --host angelic.local --port 5222 --filter muc
```

### Layer 3 — Compliance Report

```bash
cd testing/compliance
python3 compliance_report.py --host angelic.local --port 5222 --output report.md
```

### Layer 4 — Tigase TTS-NG (200+ functional tests)

```bash
git clone https://github.com/tigase/tigase-tts-ng.git && cd tigase-tts-ng
cp scripts/tests-runner-settings.dist.sh scripts/tests-runner-settings.sh
# Edit settings: SERVER_IP, SERVER_DOMAIN, credentials, SKIP_DB_SETUP=true, SKIP_SERVER_STARTUP=true
mvn -Pdist clean install -DskipTests
./scripts/tests-runner.sh --custom tigase.tests.xmpp.*   # core
./scripts/tests-runner.sh --custom tigase.tests.muc.*    # MUC only
./scripts/tests-runner.sh --all-tests
```

---

## Benchmarks

### Boot Time

```bash
python3 testing/benchmarks/boot_time_measure.py --host 127.0.0.1 --port 5222 --runs 5 --output testing/graphs/data/boot_times.csv
```

**Target: < 500 ms** (use `--accel kvm`; QEMU-TCG adds ~1-2 s overhead).

### Load Test (Tsung)

```bash
sudo apt install tsung
tsung -f testing/benchmarks/tsung_angelic.xml start
# Report: cd ~/.tsung/log/<timestamp> && perl /usr/share/tsung/tsung_stats.pl
```

### Baselines

```bash
bash testing/benchmarks/prosody_baseline.sh
bash testing/benchmarks/openfire_baseline.sh
```

### MPK Cycles

Add `-serial file:serial.log` to `run.sh`, then:

```bash
grep -oP "Result: \K[0-9]+" serial.log > testing/graphs/data/mpk_cycles.txt
```

**Target: < 20 cycles per WRPKRU** (typically 4-8 on real Intel hardware).

---

## Paper Figures

```bash
pip install matplotlib numpy
python3 testing/graphs/generate_graphs.py --data-dir testing/graphs/data --fig-dir testing/graphs/figures
python3 testing/graphs/generate_graphs.py --demo   # synthetic data to verify layout
```

| Figure | Content |
|--------|---------|
| `fig1_mpk_cycles.pdf` | MPK Gate Overhead |
| `fig2_boot_time.pdf` | Boot Time (TCP-ready / XMPP-ready) |
| `fig3_latency.pdf` | Message Latency P50/P95/P99 |
| `fig4_throughput.pdf` | Groupchat Throughput Under Load |
| `fig5_memory.pdf` | Memory Footprint Comparison |
| `fig6_compliance.pdf` | Protocol Compliance Heat-Map |
| `fig7_dashboard.pdf` | Summary Dashboard |

Data files go in `testing/graphs/data/`: `mpk_cycles.txt`, `boot_times.csv`, `tsung_latency.csv`, `tsung_throughput.csv`, `memory_footprint.csv`, `compliance.json`.

---

## Online Compliance Testers

Requires a publicly reachable server. Options:

- **Tailscale** — private mesh, forward port 5222 via `socat`
- **ngrok** — `ngrok tcp 5222` (TCP tunnels require paid plan)
- **VPS + real domain** — set A + SRV DNS records, tunnel via `autossh -R 5222:localhost:5222 user@vps`

Then submit to:
- **https://compliance.conversations.im** — XMPP Compliance Suite 2023
- **https://xmpp.net/** — TLS/SSL grading
- **https://www.jabber.at/online/** — reachability check

Update `XMPP_DOMAIN` in `src/xmpp/xmpp_core.h` to your real domain before testing.

---