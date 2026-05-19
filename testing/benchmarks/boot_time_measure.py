#!/usr/bin/env python3

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
POLL_INTERVAL_MS = 10
MAX_WAIT_SEC = 30


def tcp_connect_once(host: str, port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(0.1)
        s.connect((host, port))
        s.close()

        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def wait_for_tcp(host: str, port: int, max_wait: float, poll_ms: float = 10) -> Optional[float]:
    start = time.monotonic()
    deadline = start + max_wait
    poll_s = poll_ms / 1000.0

    while time.monotonic() < deadline:
        if tcp_connect_once(host, port):
            return time.monotonic() - start

        time.sleep(poll_s)

    return None

def wait_for_xmpp_stream(host: str, port: int, max_wait: float) -> Optional[float]:
    import ssl
    start = time.monotonic()
    deadline = start + max_wait

    while time.monotonic() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(2.0)
            s.connect((host, port))

            stream_open = (
                "<?xml version='1.0'?>"
                f"<stream:stream to='{DOMAIN}' "
                "xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams' "
                "version='1.0'>"
            ).encode("utf-8")

            s.sendall(stream_open)

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
    result = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "tcp_ready_ms": None,
        "xmpp_ready_ms": None,
        "error": None,
    }

    t0 = time.monotonic()

    print(f"waiting for tcp on {host}:{port}", end="", flush=True)

    tcp_s = wait_for_tcp(host, port, MAX_WAIT_SEC, POLL_INTERVAL_MS)

    if tcp_s is None:
        print("timeout")

        result["error"] = "tcp_timeout"

        return result

    result["tcp_ready_ms"] = int(tcp_s * 1000)

    print(f" {result['tcp_ready_ms']} ms")

    print(f"waiting for xmpp stream opening", end="", flush=True)

    remaining = MAX_WAIT_SEC - tcp_s
    xmpp_s = wait_for_xmpp_stream(host, port, remaining)

    if xmpp_s is None:
        print("timeout")

        result["error"] = "xmpp_timeout"

        return result

    result["xmpp_ready_ms"] = int((tcp_s + xmpp_s) * 1000)

    print(f" {result['xmpp_ready_ms']} ms (total from t0)")

    return result


def launch_qemu() -> Tuple[subprocess.Popen, float]:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(script_dir, "..", "..")
    run_sh = os.path.join(project_root, "run.sh")

    if not os.path.exists(run_sh):
        print(f"run.sh not found at {run_sh}")
        print("run this script from the testing/benchmarks/ directory")

        sys.exit(1)

    print(f"launching qemu via {run_sh}.")

    t0 = time.monotonic()

    proc = subprocess.Popen(
        ["bash", run_sh],
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )

    return proc, t0


def kill_qemu(proc: subprocess.Popen):
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
        print("\nno valid measurements")
        return

    tcp_vals = [r["tcp_ready_ms"] for r in valid if r["tcp_ready_ms"] is not None]
    xmpp_vals = [r["xmpp_ready_ms"] for r in valid]

    def stats(vals):
        if not vals:
            return "N/A"

        mn = min(vals)
        mx = max(vals)
        av = sum(vals) / len(vals)

        return f"min={mn} ms, max={mx} ms, avg={av:.0f} ms"

    print("\nboot time summary")
    print(f"runs completed: {len(valid)} / {len(results)}")
    print(f"tcp ready: {stats(tcp_vals)}")
    print(f"xmpp ready: {stats(xmpp_vals)}")
    print()

    target_ms = 500
    avg_xmpp = sum(xmpp_vals) / len(xmpp_vals) if xmpp_vals else 9999

    if avg_xmpp < target_ms:
        print(f"✓ pass: avg {avg_xmpp:.0f} ms < {target_ms} ms")
    else:
        print(f"✗ fail: avg {avg_xmpp:.0f} ms ≥ {target_ms} ms")
        print()

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
        description="AngelicKernel boot time measurement"
    )
    parser.add_argument("--host", default="127.0.0.1", help="qemu forwarded host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--launch", action="store_true", help="launch qemu for each run")
    parser.add_argument("--runs", type=int, default=1, help="number of measurement runs (default: 1)")
    parser.add_argument("--output", default=None, help="save results to csv file")
    args = parser.parse_args()

    print("\nAngelicKernel boot time measurement")
    print(f"target: < 500 ms")
    print(f"host: {args.host}:{args.port}")
    print(f"runs: {args.runs}")
    print()

    all_results = []

    for run_num in range(1, args.runs + 1):
        print(f"run {run_num}/{args.runs}")

        if args.launch:
            proc, _t0 = launch_qemu()
            time.sleep(0.5)
            try:
                result = measure_one_run(args.host, args.port)
            finally:
                print(f"shutting down qemu")

                kill_qemu(proc)

                time.sleep(2)
        else:
            print("using already-running qemu — t0 = now)")

            result = measure_one_run(args.host, args.port)

        all_results.append(result)

        print()

    print_summary(all_results)

    if args.output:
        save_csv(all_results, args.output)

if __name__ == "__main__":
    main()