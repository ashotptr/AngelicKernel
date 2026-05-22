# AngelicKernel XMPP — Testing & Benchmarking

## Project Structure

```
testing/
├── raw_tests/raw_xmpp_tester.py
├── slixmpp_tests/slixmpp_suite.py
├── compliance/compliance_report.py
├── benchmarks/
└── graphs/generate_graphs.py
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

### Layer 4 — Tigase TTS-NG

```bash
git clone https://github.com/tigase/tigase-tts-ng.git && cd tigase-tts-ng
cp scripts/tests-runner-settings.dist.sh scripts/tests-runner-settings.sh
mvn -Pdist clean install -DskipTests
./scripts/tests-runner.sh --custom tigase.tests.xmpp.*
./scripts/tests-runner.sh --custom tigase.tests.muc.*
./scripts/tests-runner.sh --all-tests
```

---

## Benchmarks

### Boot Time

```bash
python3 testing/benchmarks/boot_time_measure.py --host 127.0.0.1 --port 5222 --runs 5 --output testing/graphs/data/boot_times.csv
```

### Load Test (Tsung)

```bash
sudo apt install tsung
tsung -f testing/benchmarks/tsung_angelic.xml start
```

### Baselines

```bash
bash testing/benchmarks/prosody_baseline.sh
bash testing/benchmarks/openfire_baseline.sh
```

### MPK Cycles

```bash
grep -oP "Result: \K[0-9]+" serial.log > testing/graphs/data/mpk_cycles.txt
```

---

## Figures

```bash
pip install matplotlib numpy
python3 testing/graphs/generate_graphs.py --data-dir testing/graphs/data --fig-dir testing/graphs/figures
python3 testing/graphs/generate_graphs.py --demo
```

---

## Online Compliance Testers

Requires a publicly reachable server.

- **https://compliance.conversations.im**
- **https://xmpp.net/**
- **https://www.jabber.at/online/**

---
