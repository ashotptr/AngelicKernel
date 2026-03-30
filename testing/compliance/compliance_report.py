#!/usr/bin/env python3
"""
compliance_report.py — Generate a compliance report by running both
test suites and correlating results with the RFC/XEP requirements.

Usage:
    python3 compliance_report.py --host angelic.local --port 5222 --output report.md
"""

import subprocess
import sys
import argparse
import json
from datetime import datetime

REPORT_TEMPLATE = """
# XMPP Compliance Report
Generated: {timestamp}
Server: {host}:{port}

## Test Summary

| Suite | Passed | Failed | Total | Pass Rate |
|-------|--------|--------|-------|-----------|
{summary_rows}

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


def main():
    parser = argparse.ArgumentParser(description="Generate XMPP compliance report")
    parser.add_argument("--host", default="angelic.local")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--output", default="compliance_report.md")
    args = parser.parse_args()

    print(f"Running compliance tests against {args.host}:{args.port}...")
    print("This collects output from both test suites.\n")

    print("Running raw TCP test harness...")
    
    raw_result = subprocess.run(
        [sys.executable, "../raw_tests/raw_xmpp_tester.py", "--host", args.host, "--port", str(args.port)],
        capture_output=True, text=True, timeout=120
    )

    raw_output = raw_result.stdout + raw_result.stderr

    print("Running slixmpp test suite...")

    slix_result = subprocess.run(
        [sys.executable, "../slixmpp_tests/slixmpp_suite.py", "--host", args.host, "--port", str(args.port)],
        capture_output=True, text=True, timeout=120
    )

    slix_output = slix_result.stdout + slix_result.stderr

    combined = raw_output + "\n" + slix_output

    def check(keywords):
        if not keywords:
            return "⚠️"
        for kw in keywords:
            if f"✓ {kw}" in combined or f"✓{kw}" in combined:
                return "✅"
        return "❌"

    subs = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "host": args.host,
        "port": args.port,
        "summary_rows": "| Raw TCP harness | (see above) | (see above) | — | — |\n"
                        "| slixmpp suite   | (see above) | (see above) | — | — |",
        # RFC 6120
        "s_stream_open": check(["stream:stream present"]),
        "s_stream_close": check(["Server echoes </stream:stream>"]),
        "s_stream_from": check(["from='angelic.local' set"]),
        "s_stream_id": check(["id= attribute present"]),
        "s_version": check(["version='1.0' set"]),
        "s_host_unknown": check(["<host-unknown/> condition"]),
        "s_invalid_ns": check(["Wrong xmlns → stream error"]),
        "s_starttls_required": check(["STARTTLS marked required"]),
        "s_sasl_success": check(["Good credentials → <success/>"]),
        "s_not_authorized": check(["Bad credentials → <failure>"]),
        "s_bad_b64": check(["Bad Base64 → <incorrect-encoding/>"]),
        "s_bad_mech": check(["Invalid mechanism → <invalid-mechanism/>"]),
        "s_bind_feat": check(["Post-auth features contain <bind>"]),
        "s_bind_jid": check(["Bind result contains full JID"]),
        "s_iq_error": check(["Unknown IQ get → IQ error"]),
        # RFC 6121
        "s_roster_get": check(["Roster get → IQ result"]),
        "s_roster_set": check(["Roster set → IQ result"]),
        "s_roster_ver": check(["Roster get with ver="]),
        "s_subscribe": check(["subscribe forwarded to recipient"]),
        "s_subscribed": check(["subscribed forwarded back"]),
        "s_sub_state": check(["roster shows subscription='to'"]),
        "s_init_pres": check(["Initial presence elicits"]),
        "s_show_fwd": check(["<show>away</show> forwarded"]),
        "s_direct_msg": check(["Direct message delivered"]),
        "s_offline_msg": check(["Offline message delivered"]),
        # XEP-0045
        "s_muc_join_110": check(["status code 110"]),
        "s_muc_201": check(["status code 201"]),
        "s_nick_conflict": check(["<conflict/"]),
        "s_subject": check(["Room subject sent"]),
        "s_nick_change": check(["status code 303"]),
        "s_gc_msg": check(["Groupchat message received"]),
        "s_gc_reflect": check(["reflected to sender"]),
        "s_pm_delivered": check(["Private MUC message delivered"]),
        "s_pm_private": check(["NOT delivered to others"]),
        "s_leave": check(["Leave → unavailable"]),
        "s_inroom_pres": check(["In-room presence update"]),
        "s_config_form": check(["Config submit → IQ result"]),
        # XEP-0030
        "s_disco_info": check(["disco#info → IQ result"]),
        "s_disco_items": check(["disco#items on server"]),
        "s_muc_disco": check(["disco#info on MUC service"]),
        # Other XEPs
        "s_ping": check(["Ping → IQ result", "Server ping succeeds"]),
        "s_version_xep": check(["Version query succeeds"]),
        "s_xep160": check(["Offline message delivered"]),
    }

    report = REPORT_TEMPLATE.format(**subs)

    with open(args.output, "w") as f:
        f.write(report)

    print(f"\nReport written to: {args.output}")

    with open("raw_test_output.txt", "w") as f:
        f.write(raw_output)
    with open("slixmpp_test_output.txt", "w") as f:
        f.write(slix_output)

    print("Raw output saved to raw_test_output.txt and slixmpp_test_output.txt")

if __name__ == "__main__":
    main()
