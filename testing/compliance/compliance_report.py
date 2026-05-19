#!/usr/bin/env python3

import subprocess
import sys
import os
import json
import argparse
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TESTING_DIR = os.path.dirname(SCRIPT_DIR)

SUITE_TIMEOUT = 600


REPORT_TEMPLATE = """# xmpp compliance report
generated: {timestamp}
server: {host}:{port}

## test summary

| suite | passed | failed | total | pass rate |
|-------|--------|--------|-------|-----------|
| raw tcp harness | {raw_passed} | {raw_failed} | {raw_total} | {raw_rate:.0f}% |
| slixmpp suite | {slix_passed} | {slix_failed} | {slix_total} | {slix_rate:.0f}% |
| combined | {total_passed} | {total_failed} | {total_total} | {total_rate:.0f}% |

## rfc 6120 — xmpp core

| § | requirement | status |
|---|-------------|--------|
| 4.2 | stream opening exchange | {s_stream_open} |
| 4.4 | graceful stream close (</stream:stream>) | {s_stream_close} |
| 4.7.1 | server sets from= to authoritative domain | {s_stream_from} |
| 4.7.3 | stream id hard to predict | {s_stream_id} |
| 4.7.5 | version='1.0' | {s_version} |
| 4.9.3.9 | host-unknown on wrong to= | {s_host_unknown} |
| 4.9.3.10 | invalid-namespace on wrong xmlns= | {s_invalid_ns} |
| 5.3.2 | STARTTLS marked required | {s_starttls_required} |
| 6.4.6 | SASL PLAIN success → <success/> | {s_sasl_success} |
| 6.5 | bad credentials → <not-authorized/> | {s_not_authorized} |
| 6.5.5 | bad base64 → <incorrect-encoding/> | {s_bad_b64} |
| 6.5.7 | invalid mechanism → <invalid-mechanism/> | {s_bad_mech} |
| 7.2 | post-auth stream features include <bind> | {s_bind_feat} |
| 7.7 | bind result contains full jid | {s_bind_jid} |
| 8.2.3 | unknown iq get → error | {s_iq_error} |

## rfc 6121 — xmpp im

| § | requirement | status |
|---|-------------|--------|
| 2.1.3 | roster get → result with <query xmlns='jabber:iq:roster'> | {s_roster_get} |
| 2.1.5 | roster set → acknowledged | {s_roster_set} |
| 2.6 | roster get with ver= → result includes ver= | {s_roster_ver} |
| 3.1.3 | subscribe forwarded to recipient | {s_subscribe} |
| 3.1.3 | subscribed forwarded back | {s_subscribed} |
| 3.1 | after subscription, roster shows subscription='to' | {s_sub_state} |
| 4.2 | initial presence elicits at least one <presence> | {s_init_pres} |
| 4.6 | client <show>/<status>/<priority> forwarded verbatim | {s_show_fwd} |
| 5 | direct message delivered | {s_direct_msg} |
| 8 | offline message delivered with <delay/> | {s_offline_msg} |

## xep-0045 — multi-user chat

| § | requirement | status |
|---|-------------|--------|
| 7.2.2 | join → self-presence with status 110 | {s_muc_join_110} |
| 7.2.2 | new room → status 201, affiliation='owner' | {s_muc_201} |
| 7.2.8 | nick conflict → <conflict/> error | {s_nick_conflict} |
| 7.2.15 | room subject sent after join | {s_subject} |
| 7.6 | nick change → unavailable + status 303 | {s_nick_change} |
| 7.9 | groupchat message broadcast to all occupants | {s_gc_msg} |
| 7.9 | groupchat message reflected to sender | {s_gc_reflect} |
| 7.13 | private message delivered only to addressed occupant | {s_pm_delivered} |
| 7.13 | private message not delivered to others | {s_pm_private} |
| 7.14 | leave → unavailable presence sent | {s_leave} |
| 7.16 | in-room presence update relayed | {s_inroom_pres} |
| 10.1 | config form submit → iq result | {s_config_form} |

## xep-0030 — service discovery

| § | requirement | status |
|---|-------------|--------|
| 3 | disco#info on server → identity + features | {s_disco_info} |
| 3.2 | disco#items on server → muc service listed | {s_disco_items} |
| 6.2 (xep-0045) | disco#info on muc service | {s_muc_disco} |

## xep-0160 / xep-0199 / xep-0092

| xep | requirement | status |
|-----|-------------|--------|
| xep-0199 | ping → iq result | {s_ping} |
| xep-0092 | version query → name/version | {s_version_xep} |
| xep-0160 | offline message stored + delivered with delay | {s_xep160} |

---
*✅ = pass ❌ = fail ⚠️ = not tested*
"""

def run_suite(cmd: list, timeout: int, label: str) -> tuple[str, int]:
    print(f"\nrunning {label}")
    print(f"cmd: {' '.join(str(x) for x in cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr

        print(f"exit code: {result.returncode}")

        return output, result.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", errors="replace") + \
              (e.stderr or b"").decode("utf-8", errors="replace")

        print(f"timeout after {timeout}s")

        return str(out), -1
    except Exception as e:
        print(f"{e}")

        return str(e), -2

def load_json_results(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"passed": 0, "failed": 0, "total": 0, "results": []}

def check_by_name(json_data: dict, *fragments: str) -> str:
    if not fragments or not json_data.get("results"):
        return "⚠️"
    for r in json_data["results"]:
        name_lower = r["name"].lower()

        if any(frag.lower() in name_lower for frag in fragments):
            if r["passed"]:
                return "✅"

    for r in json_data["results"]:
        name_lower = r["name"].lower()

        if any(frag.lower() in name_lower for frag in fragments):
            return "❌"

    return "⚠️"

def check_by_text(combined_text: str, *keywords: str) -> str:
    if not keywords:
        return "⚠️"
    for kw in keywords:
        if f"✓ {kw}" in combined_text or f"✓{kw}" in combined_text:
            return "✅"

    return "❌"


def main():
    parser = argparse.ArgumentParser(
        description="generate xmpp compliance report"
    )
    parser.add_argument("--host", default="angelic.local")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--output", default="compliance_report.md")
    args = parser.parse_args()

    raw_json_path = os.path.join(SCRIPT_DIR, "_raw_results.json")
    slix_json_path = os.path.join(SCRIPT_DIR, "_slix_results.json")

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
        label="raw tcp test harness",
    )

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

    raw_data = load_json_results(raw_json_path)
    slix_passed = slix_output.count("✓ ")
    slix_failed = slix_output.count("✗ ")
    slix_total = slix_passed + slix_failed
    slix_data = {"results": [], "passed": slix_passed, "failed": slix_failed, "total": slix_total}

    def pct(p, t): 
        return (p / t * 100) if t else 0

    raw_passed = raw_data.get("passed", 0)
    raw_failed = raw_data.get("failed", 0)
    raw_total = raw_data.get("total", 0)

    total_passed = raw_passed + slix_passed
    total_failed = raw_failed + slix_failed
    total_total = raw_total + slix_total

    def check(raw_frags=(), slix_kws=()):
        if raw_frags:
            r = check_by_name(raw_data, *raw_frags)

            if r != "⚠️":
                return r

        if slix_kws:
            r = check_by_text(slix_output, *slix_kws)

            if r != "⚠️":
                return r

        if raw_frags:
            for frag in raw_frags:
                if frag.lower() in raw_output.lower():
                    if "✓" in raw_output:
                        return "✅"

        return "⚠️"

    subs = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "host": args.host,
        "port": args.port,

        "raw_passed": raw_passed,
        "raw_failed": raw_failed,
        "raw_total": raw_total,
        "raw_rate": pct(raw_passed, raw_total),

        "slix_passed": slix_passed,
        "slix_failed": slix_failed,
        "slix_total": slix_total,
        "slix_rate": pct(slix_passed, slix_total),

        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_total": total_total,
        "total_rate": pct(total_passed, total_total),

        "s_stream_open": check(("stream:stream present",)),
        "s_stream_close": check(("server echoes </stream:stream>",)),
        "s_stream_from": check(("from='angelic.local' set",)),
        "s_stream_id": check(("id= attribute present",)),
        "s_version": check(("version='1.0' set",)),
        "s_host_unknown": check(("<host-unknown/>",)),
        "s_invalid_ns": check(("wrong xmlns",)),
        "s_starttls_required": check(("STARTTLS marked required",)),
        "s_sasl_success": check(("good credentials",)),
        "s_not_authorized": check(("bad credentials",)),
        "s_bad_b64": check(("bad base64",)),
        "s_bad_mech": check(("invalid mechanism",)),
        "s_bind_feat": check(("post-auth features contain <bind>",)),
        "s_bind_jid": check(("bind result contains full jid",)),
        "s_iq_error": check(("unknown iq get",)),

        "s_roster_get": check(("roster get → iq result",)),
        "s_roster_set": check(("roster set → iq result",)),
        "s_roster_ver": check(("roster get with ver=",)),
        "s_subscribe": check(("subscribe forwarded",)),
        "s_subscribed": check(("subscribed forwarded",)),
        "s_sub_state": check(("subscription='to'",)),
        "s_init_pres": check(("initial presence elicits",)),
        "s_show_fwd": check(("<show>away</show> forwarded",)),
        "s_direct_msg": check(("direct message delivered",)),
        "s_offline_msg": check(("offline message delivered",)),

        "s_muc_join_110": check(("status code 110",)),
        "s_muc_201": check(("status code 201",)),
        "s_nick_conflict": check(("nick conflict",)),
        "s_subject": check(("room subject sent",)),
        "s_nick_change": check(("status code 303",)),
        "s_gc_msg": check(("groupchat message delivered",)),
        "s_gc_reflect": check(("groupchat message reflected",)),
        "s_pm_delivered": check(("private message delivered",)),
        "s_pm_private": check(("private message not delivered",)),
        "s_leave": check(("leaving room",)),
        "s_inroom_pres": check(("in-room presence update",)),
        "s_config_form": check(("config submit",)),

        "s_disco_info": check(("disco#info → iq result",)),
        "s_disco_items": check(("disco#items",)),
        "s_muc_disco": check(("muc service",)),

        "s_ping": check(("ping → iq result",), ("server ping succeeds",)),
        "s_version_xep": check(("version query",)),
        "s_xep160": check(("offline message delivered",)),
    }

    report = REPORT_TEMPLATE.format(**subs)

    output_path = args.output

    with open(output_path, "w") as f:
        f.write(report)

    print(f"\n✓ report written to: {output_path}")

    for name, content in [("raw_suite_output.txt", raw_output), ("slixmpp_suite_output.txt", slix_output)]:
        path = os.path.join(SCRIPT_DIR, name)

        with open(path, "w") as f:
            f.write(content)

    print(f"raw outputs saved in: {SCRIPT_DIR}/")

    print(f"\ncombined: {total_passed} passed / {total_failed} failed "
          f"/ {total_total} total ({pct(total_passed, total_total):.0f}%)")

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
