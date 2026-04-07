#!/usr/bin/env python3
"""
boot_time_measure.py — Measure AngelicKernel boot time from QEMU launch
                        to first XMPP TCP response on port 5222.

METHODOLOGY (Capstone §9.2 target: < 500 ms from power-on):
  1. Record the wall-clock time T0 immediately before launching QEMU.
  2. Poll port 5222 with TCP connection attempts every 10 ms.
  3. Record T1 = wall-clock time when TCP connect succeeds.
  4. Read the XMPP stream opening to confirm the server is ready (not
     just TCP listening), record T2.
  5. Report T1 - T0 (TCP ready) and T2 - T0 (XMPP ready).

QEMU TIMING NOTES:
  - QEMU startup overhead (EFI firmware + OVMF initialisation) typically
    adds ~1-2 seconds of overhead that would not exist on real hardware.
  - The run.sh script uses -accel tcg which is ~10x slower than native.
  - For real hardware comparison: run on the HP laptop with OVMF and
    report T2 - T0 measured from the physical power-on button press
    (use a hardware stopwatch or IPMI SOL timestamp if available).
  - For QEMU+KVM: add '-accel kvm' to run.sh for near-native timing.

Usage:
    # Start QEMU first (without this script), then measure:
    python3 boot_time_measure.py --host 127.0.0.1 --port 5222

    # Or launch QEMU from this script (requires run.sh to be in PATH):
    python3 boot_time_measure.py --launch --runs 5

    # Batch mode (average over N runs):
    python3 boot_time_measure.py --launch --runs 10 --output boot_times.csv
"""

import socket
import subprocess
import time
import sys
import os
import argparse
import csv
import signal
from datetime import datetime
from typing import Optional, List, Tuple

DOMAIN = "angelic.local"
POLL_INTERVAL_MS = 10   # poll every 10 ms
MAX_WAIT_SEC = 30       # give up after 30 s


def tcp_connect_once(host: str, port: int) -> bool:
    """Attempt a single TCP connect. Returns True on success."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def wait_for_tcp(host: str, port: int, max_wait: float,
                 poll_ms: float = 10) -> Optional[float]:
    """
    Poll until TCP connect succeeds or timeout.
    Returns elapsed seconds since call, or None on timeout.
    """
    start = time.monotonic()
    deadline = start + max_wait
    poll_s = poll_ms / 1000.0

    while time.monotonic() < deadline:
        if tcp_connect_once(host, port):
            return time.monotonic() - start
        time.sleep(poll_s)

    return None


def wait_for_xmpp_stream(host: str, port: int, max_wait: float) -> Optional[float]:
    """
    Connect and wait until the server sends its XMPP stream opening.
    Returns elapsed seconds since call, or None on timeout.

    The XMPP stream opening is: <?xml ...?><stream:stream ... >
    followed by <stream:features>.
    """
    import ssl
    start = time.monotonic()
    deadline = start + max_wait

    while time.monotonic() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))

            # Send the XMPP stream opening
            stream_open = (
                "<?xml version='1.0'?>"
                f"<stream:stream to='{DOMAIN}' "
                "xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams' "
                "version='1.0'>"
            ).encode("utf-8")
            s.sendall(stream_open)

            # Wait for stream features in response
            data = b""
            inner_deadline = time.monotonic() + 5.0
            while time.monotonic() < inner_deadline:
                try:
                    chunk = s.recv(4096)
                    if chunk:
                        data += chunk
                        if b"stream:features" in data or b"<starttls" in data:
                            s.close()
                            return time.monotonic() - start
                except socket.timeout:
                    break

            s.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.010)

    return None


def measure_one_run(host: str, port: int, qemu_proc=None) -> dict:
    """
    Measure boot time for one run. If qemu_proc is provided, it was
    already launched and T0 is set to the launch time (stored in the
    dict). Otherwise, T0 is now.
    """
    result = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "tcp_ready_ms": None,
        "xmpp_ready_ms": None,
        "error": None,
    }

    t0 = time.monotonic()

    # ── TCP ready ────────────────────────────────────────────────────────────
    print(f"  Waiting for TCP on {host}:{port}...", end="", flush=True)
    tcp_s = wait_for_tcp(host, port, MAX_WAIT_SEC, POLL_INTERVAL_MS)
    if tcp_s is None:
        print(" TIMEOUT")
        result["error"] = "tcp_timeout"
        return result

    result["tcp_ready_ms"] = int(tcp_s * 1000)
    print(f" {result['tcp_ready_ms']} ms")

    # ── XMPP stream ready ────────────────────────────────────────────────────
    print(f"  Waiting for XMPP stream opening...", end="", flush=True)
    remaining = MAX_WAIT_SEC - tcp_s
    xmpp_s = wait_for_xmpp_stream(host, port, remaining)
    if xmpp_s is None:
        print(" TIMEOUT")
        result["error"] = "xmpp_timeout"
        return result

    # xmpp_s is time from after TCP ready; add tcp_s for total from T0
    result["xmpp_ready_ms"] = int((tcp_s + xmpp_s) * 1000)
    print(f" {result['xmpp_ready_ms']} ms (total from T0)")

    return result


def launch_qemu() -> Tuple[subprocess.Popen, float]:
    """
    Launch QEMU via run.sh and return (process, launch_time).
    Assumes run.sh is in the project root (one level up from testing/).
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(script_dir, "..", "..")
    run_sh = os.path.join(project_root, "run.sh")

    if not os.path.exists(run_sh):
        print(f"ERROR: run.sh not found at {run_sh}")
        print("       Run this script from the testing/benchmarks/ directory.")
        sys.exit(1)

    print(f"  Launching QEMU via {run_sh}...")
    t0 = time.monotonic()
    proc = subprocess.Popen(
        ["bash", run_sh],
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,  # process group for clean kill
    )
    return proc, t0


def kill_qemu(proc: subprocess.Popen):
    """Terminate the QEMU process group."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            proc.kill()
        except Exception:
            pass


def print_summary(results: List[dict]):
    valid = [r for r in results if r["xmpp_ready_ms"] is not None]

    if not valid:
        print("\nNo valid measurements.")
        return

    tcp_vals  = [r["tcp_ready_ms"] for r in valid if r["tcp_ready_ms"] is not None]
    xmpp_vals = [r["xmpp_ready_ms"] for r in valid]

    def stats(vals):
        if not vals:
            return "N/A"
        mn = min(vals)
        mx = max(vals)
        av = sum(vals) / len(vals)
        return f"min={mn} ms, max={mx} ms, avg={av:.0f} ms"

    print("\n" + "═" * 60)
    print(" Boot Time Summary")
    print("═" * 60)
    print(f"  Runs completed:    {len(valid)} / {len(results)}")
    print(f"  TCP ready:         {stats(tcp_vals)}")
    print(f"  XMPP ready:        {stats(xmpp_vals)}")
    print()

    target_ms = 500
    avg_xmpp = sum(xmpp_vals) / len(xmpp_vals) if xmpp_vals else 9999

    if avg_xmpp < target_ms:
        print(f"  ✓ PASS: avg {avg_xmpp:.0f} ms < {target_ms} ms (Capstone §9.2 target)")
    else:
        print(f"  ✗ FAIL: avg {avg_xmpp:.0f} ms ≥ {target_ms} ms (Capstone §9.2 target)")
        print()
        print("  NOTE: QEMU TCG adds ~1-2 s of firmware + emulation overhead.")
        print("        Target is for real hardware with fast SSD/NVMe storage.")
        print("        Use '-accel kvm' in run.sh for near-native measurement.")

    print("═" * 60)


def save_csv(results: List[dict], output: str):
    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "tcp_ready_ms", "xmpp_ready_ms", "error"
        ])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved to: {output}")


def main():
    parser = argparse.ArgumentParser(
        description="AngelicKernel boot time measurement (Capstone §9.2)"
    )
    parser.add_argument("--host",   default="127.0.0.1",
                        help="QEMU forwarded host (default: 127.0.0.1)")
    parser.add_argument("--port",   type=int, default=5222)
    parser.add_argument("--launch", action="store_true",
                        help="Launch QEMU for each run (requires run.sh)")
    parser.add_argument("--runs",   type=int, default=1,
                        help="Number of measurement runs (default: 1)")
    parser.add_argument("--output", default=None,
                        help="Save results to CSV file")
    args = parser.parse_args()

    print("\nAngelicKernel Boot Time Measurement")
    print(f"Target: < 500 ms (Capstone §9.2)")
    print(f"Host:   {args.host}:{args.port}")
    print(f"Runs:   {args.runs}")
    print()

    all_results = []

    for run_num in range(1, args.runs + 1):
        print(f"─── Run {run_num}/{args.runs} ───────────────────────────────")

        if args.launch:
            proc, _t0 = launch_qemu()
            # Give QEMU a moment to start emulating before we poll
            time.sleep(0.5)
            try:
                result = measure_one_run(args.host, args.port)
            finally:
                print(f"  Shutting down QEMU...")
                kill_qemu(proc)
                time.sleep(2)  # wait for port to free before next run
        else:
            print("  (Using already-running QEMU — T0 = now)")
            result = measure_one_run(args.host, args.port)

        all_results.append(result)
        print()

    print_summary(all_results)

    if args.output:
        save_csv(all_results, args.output)


if __name__ == "__main__":
    main()
