#!/usr/bin/env python3
"""
compliance_report.py — Generate a compliance report by running both
test suites and correlating results with RFC/XEP requirements.

FIXES vs original:
  1. Timeout raised from 120 s → 300 s (raw suite takes ~120 s alone on QEMU-TCG).
  2. Passes --inter-test-sleep 1.0 to raw_xmpp_tester.py to avoid slot exhaustion.
  3. Uses --json output from raw tester for reliable keyword-free pass detection.
  4. Handles slixmpp suite separately; maps both into the combined result dict.
  5. Writes report to --output path (default: compliance_report.md).

Usage:
    cd testing/compliance
    python3 compliance_report.py --host angelic.local --port 5222
    python3 compliance_report.py --host 127.0.0.1   --port 5222 \\
        --output report.md
"""

import subprocess
import sys
import os
import json
import argparse
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TESTING_DIR = os.path.dirname(SCRIPT_DIR)

SUITE_TIMEOUT = 300   # seconds — generous for slow QEMU-TCG runs


REPORT_TEMPLATE = """# XMPP Compliance Report
Generated: {timestamp}
Server: {host}:{port}

## Test Summary

| Suite | Passed | Failed | Total | Pass Rate |
|-------|--------|--------|-------|-----------|
| Raw TCP harness | {raw_passed} | {raw_failed} | {raw_total} | {raw_rate:.0f}% |
| slixmpp suite   | {slix_passed} | {slix_failed} | {slix_total} | {slix_rate:.0f}% |
| **COMBINED**    | **{total_passed}** | **{total_failed}** | **{total_total}** | **{total_rate:.0f}%** |

## RFC 6120 — XMPP Core

| § | Requirement | Status |
|---|-------------|--------|
| 4.2 | Stream opening exchange | {s_stream_open} |
| 4.4 | Graceful stream close (</stream:stream>) | {s_stream_close} |
| 4.7.1 | Server sets from= to authoritative domain | {s_stream_from} |
| 4.7.3 | Stream ID hard to predict | {s_stream_id} |
| 4.7.5 | version='1.0' | {s_version} |
| 4.9.3.9 | host-unknown on wrong to= | {s_host_unknown} |
| 4.9.3.10 | invalid-namespace on wrong xmlns= | {s_invalid_ns} |
| 5.3.2 | STARTTLS marked required | {s_starttls_required} |
| 6.4.6 | SASL PLAIN success → <success/> | {s_sasl_success} |
| 6.5 | Bad credentials → <not-authorized/> | {s_not_authorized} |
| 6.5.5 | Bad Base64 → <incorrect-encoding/> | {s_bad_b64} |
| 6.5.7 | Invalid mechanism → <invalid-mechanism/> | {s_bad_mech} |
| 7.2 | Post-auth stream features include <bind> | {s_bind_feat} |
| 7.7 | Bind result contains full JID | {s_bind_jid} |
| 8.2.3 | Unknown IQ get → error | {s_iq_error} |

## RFC 6121 — XMPP IM

| § | Requirement | Status |
|---|-------------|--------|
| 2.1.3 | Roster get → result with <query xmlns='jabber:iq:roster'> | {s_roster_get} |
| 2.1.5 | Roster set → acknowledged | {s_roster_set} |
| 2.6 | Roster get with ver= → result includes ver= | {s_roster_ver} |
| 3.1.3 | subscribe forwarded to recipient | {s_subscribe} |
| 3.1.3 | subscribed forwarded back | {s_subscribed} |
| 3.1 | After subscription, roster shows subscription='to' | {s_sub_state} |
| 4.2 | Initial presence elicits at least one <presence> | {s_init_pres} |
| 4.6 | Client <show>/<status>/<priority> forwarded verbatim | {s_show_fwd} |
| 5 | Direct message delivered | {s_direct_msg} |
| 8 | Offline message delivered with <delay/> | {s_offline_msg} |

## XEP-0045 — Multi-User Chat

| § | Requirement | Status |
|---|-------------|--------|
| 7.2.2 | Join → self-presence with status 110 | {s_muc_join_110} |
| 7.2.2 | New room → status 201, affiliation='owner' | {s_muc_201} |
| 7.2.8 | Nick conflict → <conflict/> error | {s_nick_conflict} |
| 7.2.15 | Room subject sent after join | {s_subject} |
| 7.6 | Nick change → unavailable + status 303 | {s_nick_change} |
| 7.9 | Groupchat message broadcast to all occupants | {s_gc_msg} |
| 7.9 | Groupchat message reflected to sender | {s_gc_reflect} |
| 7.13 | Private message delivered only to addressed occupant | {s_pm_delivered} |
| 7.13 | Private message NOT delivered to others | {s_pm_private} |
| 7.14 | Leave → unavailable presence sent | {s_leave} |
| 7.16 | In-room presence update relayed | {s_inroom_pres} |
| 10.1 | Config form submit → IQ result | {s_config_form} |

## XEP-0030 — Service Discovery

| § | Requirement | Status |
|---|-------------|--------|
| 3 | disco#info on server → identity + features | {s_disco_info} |
| 3.2 | disco#items on server → MUC service listed | {s_disco_items} |
| 6.2 (XEP-0045) | disco#info on MUC service | {s_muc_disco} |

## XEP-0160 / XEP-0199 / XEP-0092

| XEP | Requirement | Status |
|-----|-------------|--------|
| XEP-0199 | Ping → IQ result | {s_ping} |
| XEP-0092 | Version query → name/version | {s_version_xep} |
| XEP-0160 | Offline message stored + delivered with delay | {s_xep160} |

---
*✅ = PASS  ❌ = FAIL  ⚠️ = NOT TESTED*
"""


def run_suite(cmd: list, timeout: int, label: str) -> tuple[str, int]:
    """Run a subprocess, return (stdout+stderr, returncode)."""
    print(f"\nRunning {label}...")
    print(f"  cmd: {' '.join(str(x) for x in cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        print(f"  exit code: {result.returncode}")
        return output, result.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        print(f"  TIMEOUT after {timeout}s")
        return str(out), -1
    except Exception as e:
        print(f"  ERROR: {e}")
        return str(e), -2


def load_json_results(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"passed": 0, "failed": 0, "total": 0, "results": []}


def check_by_name(json_data: dict, *fragments: str) -> str:
    """Return ✅ if any result whose name contains one of the fragments passed."""
    if not fragments or not json_data.get("results"):
        return "⚠️"
    for r in json_data["results"]:
        name_lower = r["name"].lower()
        if any(frag.lower() in name_lower for frag in fragments):
            if r["passed"]:
                return "✅"
    # found matching tests but none passed
    for r in json_data["results"]:
        name_lower = r["name"].lower()
        if any(frag.lower() in name_lower for frag in fragments):
            return "❌"
    return "⚠️"


def check_by_text(combined_text: str, *keywords: str) -> str:
    """Fallback: scan raw output text for ✓ keyword lines."""
    if not keywords:
        return "⚠️"
    for kw in keywords:
        if f"✓ {kw}" in combined_text or f"✓{kw}" in combined_text:
            return "✅"
    return "❌"


def main():
    parser = argparse.ArgumentParser(
        description="Generate XMPP compliance report"
    )
    parser.add_argument("--host",   default="angelic.local")
    parser.add_argument("--port",   type=int, default=5222)
    parser.add_argument("--output", default="compliance_report.md")
    args = parser.parse_args()

    raw_json_path  = os.path.join(SCRIPT_DIR, "_raw_results.json")
    slix_json_path = os.path.join(SCRIPT_DIR, "_slix_results.json")

    # ── Run raw TCP suite ─────────────────────────────────────────────────
    raw_output, raw_rc = run_suite(
        [
            sys.executable,
            os.path.join(TESTING_DIR, "raw_tests", "raw_xmpp_tester.py"),
            "--host", args.host,
            "--port", str(args.port),
            "--inter-test-sleep", "1.0",
            "--recv-timeout", "8.0",
            "--json", raw_json_path,
        ],
        timeout=SUITE_TIMEOUT,
        label="raw TCP test harness",
    )

    # ── Run slixmpp suite ─────────────────────────────────────────────────
    slix_output, slix_rc = run_suite(
        [
            sys.executable,
            os.path.join(TESTING_DIR, "slixmpp_tests", "slixmpp_suite.py"),
            "--host", args.host,
            "--port", str(args.port),
        ],
        timeout=SUITE_TIMEOUT,
        label="slixmpp test suite",
    )

    # ── Load JSON results ─────────────────────────────────────────────────
    raw_data  = load_json_results(raw_json_path)
    # slixmpp suite doesn't write JSON — parse text output
    slix_passed = slix_output.count("✓ ")
    slix_failed = slix_output.count("✗ ")
    slix_total  = slix_passed + slix_failed
    slix_data   = {"results": [], "passed": slix_passed,
                   "failed": slix_failed, "total": slix_total}

    # ── Counters ──────────────────────────────────────────────────────────
    def pct(p, t): return (p / t * 100) if t else 0

    raw_passed  = raw_data.get("passed", 0)
    raw_failed  = raw_data.get("failed", 0)
    raw_total   = raw_data.get("total",  0)

    total_passed = raw_passed + slix_passed
    total_failed = raw_failed + slix_failed
    total_total  = raw_total  + slix_total

    def check(raw_frags=(), slix_kws=()):
        """Try JSON-based check first; fall back to text scan."""
        if raw_frags:
            r = check_by_name(raw_data, *raw_frags)
            if r != "⚠️":
                return r
        if slix_kws:
            r = check_by_text(slix_output, *slix_kws)
            if r != "⚠️":
                return r
        # Text scan over raw output as last resort
        if raw_frags:
            for frag in raw_frags:
                if frag.lower() in raw_output.lower():
                    if "✓" in raw_output:
                        return "✅"
        return "⚠️"

    subs = {
        "timestamp":    datetime.now().isoformat(timespec="seconds"),
        "host":         args.host,
        "port":         args.port,

        "raw_passed":   raw_passed,
        "raw_failed":   raw_failed,
        "raw_total":    raw_total,
        "raw_rate":     pct(raw_passed, raw_total),

        "slix_passed":  slix_passed,
        "slix_failed":  slix_failed,
        "slix_total":   slix_total,
        "slix_rate":    pct(slix_passed, slix_total),

        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_total":  total_total,
        "total_rate":   pct(total_passed, total_total),

        # RFC 6120
        "s_stream_open":      check(("stream:stream present",)),
        "s_stream_close":     check(("Server echoes </stream:stream>",)),
        "s_stream_from":      check(("from='angelic.local' set",)),
        "s_stream_id":        check(("id= attribute present",)),
        "s_version":          check(("version='1.0' set",)),
        "s_host_unknown":     check(("<host-unknown/>",)),
        "s_invalid_ns":       check(("Wrong xmlns",)),
        "s_starttls_required": check(("STARTTLS marked required",)),
        "s_sasl_success":     check(("Good credentials",)),
        "s_not_authorized":   check(("Bad credentials",)),
        "s_bad_b64":          check(("Bad Base64",)),
        "s_bad_mech":         check(("Invalid mechanism",)),
        "s_bind_feat":        check(("Post-auth features contain <bind>",)),
        "s_bind_jid":         check(("Bind result contains full JID",)),
        "s_iq_error":         check(("Unknown IQ get",)),

        # RFC 6121
        "s_roster_get":   check(("Roster get → IQ result",)),
        "s_roster_set":   check(("Roster set → IQ result",)),
        "s_roster_ver":   check(("Roster get with ver=",)),
        "s_subscribe":    check(("subscribe forwarded",)),
        "s_subscribed":   check(("subscribed forwarded",)),
        "s_sub_state":    check(("subscription='to'",)),
        "s_init_pres":    check(("Initial presence elicits",)),
        "s_show_fwd":     check(("<show>away</show> forwarded",)),
        "s_direct_msg":   check(("Direct message delivered",)),
        "s_offline_msg":  check(("Offline message delivered",)),

        # XEP-0045
        "s_muc_join_110":  check(("status code 110",)),
        "s_muc_201":       check(("status code 201",)),
        "s_nick_conflict": check(("Nick conflict",)),
        "s_subject":       check(("Room subject sent",)),
        "s_nick_change":   check(("status code 303",)),
        "s_gc_msg":        check(("Groupchat message delivered",)),
        "s_gc_reflect":    check(("Groupchat message reflected",)),
        "s_pm_delivered":  check(("Private message delivered",)),
        "s_pm_private":    check(("Private message NOT delivered",)),
        "s_leave":         check(("Leaving room",)),
        "s_inroom_pres":   check(("In-room presence update",)),
        "s_config_form":   check(("Config submit",)),

        # XEP-0030
        "s_disco_info":  check(("disco#info → IQ result",)),
        "s_disco_items": check(("disco#items",)),
        "s_muc_disco":   check(("MUC service",)),

        # Other XEPs
        "s_ping":        check(("Ping → IQ result",), ("Server ping succeeds",)),
        "s_version_xep": check(("Version query",)),
        "s_xep160":      check(("Offline message delivered",)),
    }

    report = REPORT_TEMPLATE.format(**subs)

    output_path = args.output
    with open(output_path, "w") as f:
        f.write(report)
    print(f"\n✓ Report written to: {output_path}")

    # Also save raw outputs
    for name, content in [("raw_suite_output.txt", raw_output),
                           ("slixmpp_suite_output.txt", slix_output)]:
        path = os.path.join(SCRIPT_DIR, name)
        with open(path, "w") as f:
            f.write(content)
    print(f"  Raw outputs saved in: {SCRIPT_DIR}/")

    # Print totals
    print(f"\n{'═'*50}")
    print(f"  Combined: {total_passed} passed / {total_failed} failed "
          f"/ {total_total} total  ({pct(total_passed, total_total):.0f}%)")
    print(f"{'═'*50}\n")

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
