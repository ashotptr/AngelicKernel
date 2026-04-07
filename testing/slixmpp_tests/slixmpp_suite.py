#!/usr/bin/env python3
"""
slixmpp_suite.py — Higher-level XMPP compliance tests using slixmpp.

Tests RFC 6121 IM features and XEP-0045 MUC at the protocol layer
using a real, well-tested XMPP client library.

FIX (2025): Removed deprecated 'disable_starttls' kwarg from connect().
Modern slixmpp (1.8+) handles TLS negotiation automatically via the
ssl_context attribute and feature negotiation. The old kwarg was
removed in slixmpp ~1.7.

Install:
    pip install slixmpp colorama

Usage:
    python3 slixmpp_suite.py --host angelic.local --port 5222
"""

import asyncio
import logging
import ssl
import sys
import time
import argparse
import traceback
from typing import Optional, List
from dataclasses import dataclass, field
from colorama import Fore, Style, init as colorama_init

colorama_init()

try:
    import slixmpp
    from slixmpp import ClientXMPP
    from slixmpp.exceptions import IqError, IqTimeout
except ImportError:
    print("slixmpp not installed. Run: pip install slixmpp")
    sys.exit(1)

logging.getLogger("slixmpp").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

DOMAIN = "angelic.local"
MUC_SVC = f"conference.{DOMAIN}"

USERS = {
    "user1": "pass1",
    "user2": "pass2",
    "admin": "admin",
}


@dataclass
class TestResult:
    name:   str
    passed: bool
    detail: str = ""


results: List[TestResult] = []


def ok(msg):
    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {msg}")


def fail(msg):
    print(f"  {Fore.RED}✗{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} {msg}")


def header(msg):
    print(f"\n{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA} {msg}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}")


def record(name: str, passed: bool, detail: str = ""):
    results.append(TestResult(name, passed, detail))
    if passed:
        ok(name)
    else:
        fail(f"{name}: {detail}")


def make_permissive_ssl_ctx() -> ssl.SSLContext:
    """
    Build a permissive SSLContext that accepts the kernel's ephemeral
    self-signed ECDSA P-256 certificate without CA chain or hostname check.

    The AngelicKernel generates a fresh self-signed cert at every boot
    (CN=angelic.local, no CA). Standard TLS verification would reject it.
    This is intentional for an embedded unikernel in a trusted LAN.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Allow TLS 1.2 (what mbedTLS 3.6 provides on the server side)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class TestClient(ClientXMPP):
    """
    A slixmpp ClientXMPP subclass with helpers for test scenarios.

    Key changes vs the broken version:
    - No disable_starttls kwarg (removed in slixmpp 1.7+).
    - ssl_context is set on the instance before connect(); slixmpp
      picks it up via the 'ssl' argument path internally.
    - The connect() call now passes use_ssl=False (we start plain,
      then let the STARTTLS feature negotiation do the upgrade).
    """

    def __init__(self, host: str, port: int, user: str, password: str):
        jid_str = f"{user}@{DOMAIN}"
        super().__init__(jid_str, password)
        self._host = host
        self._port = port
        self.received_messages: List[slixmpp.Message] = []
        self.received_presence: List[slixmpp.Presence] = []
        self.session_event = asyncio.Event()

        self.register_plugin("xep_0030")
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0199")
        self.register_plugin("xep_0092")

        self.add_event_handler("session_start", self._on_session)
        self.add_event_handler("message",       self._on_message)
        self.add_event_handler("presence",      self._on_presence)

        # The permissive SSLContext is used by slixmpp for the TLS upgrade.
        # slixmpp reads self.ssl_context when performing STARTTLS.
        self.ssl_context = make_permissive_ssl_ctx()
        # Legacy attribute checked by older slixmpp builds
        self.ca_certs = None

    async def _on_session(self, _event):
        await self.get_roster()
        self.send_presence()
        self.session_event.set()

    def _on_message(self, msg):
        self.received_messages.append(msg)

    def _on_presence(self, pres):
        self.received_presence.append(pres)

    async def start(self) -> bool:
        """
        Connect and wait for session_start. Returns True on success.

        Modern slixmpp connect() signature (1.8+):
            connect(host=None, port=None, use_ssl=False, ...)
        The STARTTLS upgrade happens automatically when the server
        advertises <starttls><required/></starttls> in stream features.
        """
        try:
            # use_ssl=False → start with plain TCP; slixmpp will
            # perform STARTTLS when the server demands it.
            self.connect(host=self._host, port=self._port, use_ssl=False)
            try:
                await asyncio.wait_for(self.session_event.wait(), timeout=15)
                return True
            except asyncio.TimeoutError:
                warn(f"Timeout waiting for session_start for {self.boundjid}")
                return False
        except Exception as e:
            warn(f"Connection failed for {self.boundjid}: {e}")
            return False

    async def stop(self):
        try:
            self.disconnect(wait=1)
            await asyncio.sleep(0.5)
        except Exception:
            pass

    def clear_received(self):
        self.received_messages.clear()
        self.received_presence.clear()

    async def wait_for_message(self, body_contains: str,
                                timeout: float = 5.0) -> Optional[slixmpp.Message]:
        """Wait until a message with the given body text arrives."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            for msg in self.received_messages:
                if body_contains in str(msg["body"]):
                    return msg
            await asyncio.sleep(0.1)
        return None

    async def wait_for_presence(self, from_contains: str = "",
                                 ptype: str = "",
                                 timeout: float = 5.0) -> Optional[slixmpp.Presence]:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            for pres in self.received_presence:
                frm = str(pres["from"])
                typ = str(pres["type"])
                if (not from_contains or from_contains in frm) \
                   and (not ptype or ptype == typ):
                    return pres
            await asyncio.sleep(0.1)
        return None


# ─── Individual test scenarios ────────────────────────────────────────────────

async def test_connect_and_session(host, port):
    """Basic connection, TLS, SASL, bind, session."""
    header("slixmpp — Connection + Session Establishment")
    c = TestClient(host, port, "user1", "pass1")
    try:
        ok_flag = await c.start()
        record("Session start completes (TLS + SASL PLAIN + bind)",
               ok_flag, "timed out" if not ok_flag else "")
        if ok_flag:
            full = str(c.boundjid.full)
            record("Bound JID has resource", "/" in full, full)
            record("Bound JID domain is correct", DOMAIN in full, full)
    finally:
        await c.stop()


async def test_roster_get(host, port):
    """RFC 6121 §2.1 — Roster get."""
    header("slixmpp — RFC 6121 Roster Get")
    c = TestClient(host, port, "user1", "pass1")
    try:
        if not await c.start():
            warn("Session failed"); return
        roster = c.client_roster
        record("Roster object accessible after session_start",
               roster is not None)
        # Check that the roster IQ round-trip succeeded (no exception above)
        record("Roster get IQ completed without error", True)
    finally:
        await c.stop()


async def test_roster_update_and_subscription(host, port):
    """RFC 6121 §3 — Add contact, subscribe, check roster state."""
    header("slixmpp — RFC 6121 Roster + Subscription Flow")
    alice = TestClient(host, port, "user1", "pass1")
    bob   = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        if not (ok1 and ok2):
            warn("Session failed for one or both users"); return

        alice.clear_received()
        bob.clear_received()

        bare_bob = f"user2@{DOMAIN}"
        try:
            await alice.update_roster(bare_bob, name="Bob")
            record("Roster set IQ succeeds (RFC 6121 §2.1.5)", True)
        except (IqError, IqTimeout) as e:
            record("Roster set IQ succeeds (RFC 6121 §2.1.5)", False, str(e))
            return

        alice.send_presence(pto=bare_bob, ptype="subscribe")
        await asyncio.sleep(1.5)

        sub_received = any(
            "subscribe" in str(p.get("type", ""))
            for p in bob.received_presence
        )
        record("Bob receives subscription request (RFC 6121 §3.1.3)",
               sub_received,
               f"Bob presence types: {[str(p['type']) for p in bob.received_presence]}")

        bare_alice = f"user1@{DOMAIN}"
        bob.send_presence(pto=bare_alice, ptype="subscribed")
        await asyncio.sleep(1.5)

        sub_ack = any(
            "subscribed" in str(p.get("type", ""))
            for p in alice.received_presence
        )
        record("Alice receives subscribed confirmation (RFC 6121 §3.1.3)",
               sub_ack,
               f"Alice presence types: {[str(p['type']) for p in alice.received_presence]}")

        await alice.get_roster()
        roster_item = alice.client_roster.get(bare_bob)
        if roster_item:
            sub_state = roster_item["subscription"]
            record("Alice roster shows subscription='to' after subscribed (RFC 6121 §3.1)",
                   sub_state in ("to", "both"),
                   f"got subscription='{sub_state}'")
        else:
            record("Alice roster shows subscription='to' after subscribed (RFC 6121 §3.1)",
                   False, "Bob not in Alice's roster")
    finally:
        await alice.stop()
        await bob.stop()


async def test_direct_message(host, port):
    """RFC 6121 §5 — Direct chat message."""
    header("slixmpp — RFC 6121 Direct Message")
    sender = TestClient(host, port, "user1", "pass1")
    recvr  = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await sender.start()
        ok2 = await recvr.start()
        if not (ok1 and ok2):
            warn("Session failed"); return
        recvr.clear_received()

        body = f"slixmpp-test-{int(time.time())}"
        bare2 = f"user2@{DOMAIN}"
        sender.send_message(mto=bare2, mbody=body, mtype="chat")

        msg = await recvr.wait_for_message(body, timeout=5)
        record("Direct message delivered (RFC 6121 §5)",
               msg is not None, f"body: {body}")
        if msg:
            record("Message from= is sender (RFC 6120 §8.1.2)",
                   "user1" in str(msg["from"]), str(msg["from"]))
    finally:
        await sender.stop()
        await recvr.stop()


async def test_muc_join_and_chat(host, port):
    """XEP-0045 §7.2 / §7.9 — MUC join + groupchat."""
    header("slixmpp — XEP-0045 MUC Join + Groupchat")
    alice = TestClient(host, port, "user1", "pass1")
    bob   = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        if not (ok1 and ok2):
            warn("Session failed"); return

        room_name = f"slixtest{int(time.time()) % 10000}"
        room_jid  = f"{room_name}@{MUC_SVC}"

        alice_muc = alice["xep_0045"]
        bob_muc   = bob["xep_0045"]

        alice.clear_received()
        await alice_muc.join_muc_wait(room_jid, "alice", maxwait=8)
        record("Alice joins MUC room (XEP-0045 §7.2)", True)

        # Submit instant room config to unlock the room
        await asyncio.sleep(0.5)
        try:
            config = await alice_muc.get_room_config(room_jid)
            await alice_muc.set_room_config(room_jid, config)
        except Exception:
            pass

        bob.clear_received()
        await bob_muc.join_muc_wait(room_jid, "bob", maxwait=8)
        record("Bob joins existing MUC room (XEP-0045 §7.2)", True)

        await asyncio.sleep(0.5)

        body = f"gc-test-{int(time.time())}"
        alice.clear_received()
        bob.clear_received()
        alice.send_message(mto=room_jid, mbody=body, mtype="groupchat")
        await asyncio.sleep(2)

        bob_got = any(body in str(m["body"]) for m in bob.received_messages)
        record("Groupchat message received by other occupant (XEP-0045 §7.9)",
               bob_got,
               f"Bob messages: {[str(m['body'])[:40] for m in bob.received_messages]}")

        alice_got = any(body in str(m["body"]) for m in alice.received_messages)
        record("Groupchat message reflected to sender (XEP-0045 §7.9)",
               alice_got,
               f"Alice messages: {[str(m['body'])[:40] for m in alice.received_messages]}")

        await alice_muc.leave_muc(room_jid, "alice")
        await bob_muc.leave_muc(room_jid, "bob")
    finally:
        await alice.stop()
        await bob.stop()


async def test_muc_private_message(host, port):
    """XEP-0045 §7.13 — Private message within room."""
    header("slixmpp — XEP-0045 Private MUC Message")
    alice   = TestClient(host, port, "user1", "pass1")
    bob     = TestClient(host, port, "user2", "pass2")
    charlie = TestClient(host, port, "admin", "admin")
    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        ok3 = await charlie.start()
        if not (ok1 and ok2 and ok3):
            warn("Session failed"); return

        room_jid = f"privateroom{int(time.time()) % 10000}@{MUC_SVC}"
        alice_muc   = alice["xep_0045"]
        bob_muc     = bob["xep_0045"]
        charlie_muc = charlie["xep_0045"]

        await alice_muc.join_muc_wait(room_jid, "alice", maxwait=8)
        await asyncio.sleep(0.3)
        try:
            config = await alice_muc.get_room_config(room_jid)
            await alice_muc.set_room_config(room_jid, config)
        except Exception:
            pass
        await bob_muc.join_muc_wait(room_jid, "bob", maxwait=8)
        await charlie_muc.join_muc_wait(room_jid, "charlie", maxwait=8)
        await asyncio.sleep(0.5)

        bob.clear_received()
        charlie.clear_received()

        secret = f"private-{int(time.time())}"
        alice.send_message(mto=f"{room_jid}/bob", mbody=secret, mtype="chat")
        await asyncio.sleep(2)

        bob_got     = any(secret in str(m["body"]) for m in bob.received_messages)
        charlie_got = any(secret in str(m["body"]) for m in charlie.received_messages)

        record("Private MUC message delivered to addressed occupant (XEP-0045 §7.13)",
               bob_got,
               f"bob msgs: {[str(m['body'])[:40] for m in bob.received_messages]}")
        record("Private MUC message NOT delivered to others (XEP-0045 §7.13)",
               not charlie_got,
               f"charlie msgs: {[str(m['body'])[:40] for m in charlie.received_messages]}")

        await alice_muc.leave_muc(room_jid, "alice")
        await bob_muc.leave_muc(room_jid, "bob")
        await charlie_muc.leave_muc(room_jid, "charlie")
    finally:
        await alice.stop()
        await bob.stop()
        await charlie.stop()


async def test_ping(host, port):
    """XEP-0199 — XMPP Ping."""
    header("slixmpp — XEP-0199 Ping")
    c = TestClient(host, port, "user1", "pass1")
    try:
        if not await c.start():
            warn("Session failed"); return
        try:
            await c["xep_0199"].ping(DOMAIN, timeout=5)
            record("Server ping succeeds (XEP-0199)", True)
        except Exception as e:
            record("Server ping succeeds (XEP-0199)", False, str(e))
    finally:
        await c.stop()


async def test_disco(host, port):
    """XEP-0030 — Service Discovery."""
    header("slixmpp — XEP-0030 Service Discovery")
    c = TestClient(host, port, "user1", "pass1")
    try:
        if not await c.start():
            warn("Session failed"); return
        disco = c["xep_0030"]

        try:
            info = await disco.get_info(DOMAIN)
            has_identity = len(info["identities"]) > 0
            has_muc_feat = any("muc" in str(f) for f in info["features"])
            record("disco#info on server returns identity (XEP-0030 §3)",
                   has_identity, str(list(info["identities"])[:2]))
            record("Server advertises MUC feature",
                   has_muc_feat, str(list(info["features"])[:5]))
        except Exception as e:
            record("disco#info on server", False, str(e))

        try:
            muc_info = await disco.get_info(MUC_SVC)
            record("disco#info on MUC service (XEP-0045 §6.2)",
                   len(muc_info["identities"]) > 0,
                   str(list(muc_info["identities"])[:2]))
        except Exception as e:
            record("disco#info on MUC service", False, str(e))

        try:
            items = await disco.get_items(DOMAIN)
            has_muc_item = any("conference" in str(item) for item in items["items"])
            record("disco#items on server lists MUC service (XEP-0030 §3.2)",
                   has_muc_item, str(list(items["items"])[:3]))
        except Exception as e:
            record("disco#items on server", False, str(e))
    finally:
        await c.stop()


async def test_version(host, port):
    """XEP-0092 — Software Version."""
    header("slixmpp — XEP-0092 Software Version")
    c = TestClient(host, port, "user1", "pass1")
    try:
        if not await c.start():
            warn("Session failed"); return
        try:
            resp = await c["xep_0092"].get_version(DOMAIN)
            record("Version query succeeds (XEP-0092)",
                   resp["software_version"]["name"] != "",
                   str(dict(resp["software_version"])))
        except Exception as e:
            record("Version query succeeds (XEP-0092)", False, str(e))
    finally:
        await c.stop()


async def test_offline_message(host, port):
    """XEP-0160 — Offline message stored and delivered on login."""
    header("slixmpp — XEP-0160 Offline Message Delivery")
    sender = TestClient(host, port, "user1", "pass1")
    try:
        if not await sender.start():
            warn("Sender login failed"); return

        body = f"offline-slixmpp-{int(time.time())}"
        bare2 = f"user2@{DOMAIN}"
        sender.send_message(mto=bare2, mbody=body, mtype="chat")
        await asyncio.sleep(1.5)
        await sender.stop()
        await asyncio.sleep(0.5)

        recvr = TestClient(host, port, "user2", "pass2")
        try:
            if not await recvr.start():
                warn("Receiver login failed"); return
            # Give the server time to deliver queued messages
            await asyncio.sleep(3)
            msg = await recvr.wait_for_message(body, timeout=5)
            record("Offline message delivered after recipient logs in (XEP-0160)",
                   msg is not None, f"looking for: {body}")
            if msg:
                # The <delay/> element is parsed by slixmpp into the 'delay' stanza attr
                has_delay = "delay" in msg or "delay" in str(msg)
                record("Delivery includes XEP-0203 <delay/> element",
                       has_delay, str(msg)[:100])
        finally:
            await recvr.stop()
    finally:
        try:
            await sender.stop()
        except Exception:
            pass


ALL_ASYNC_TESTS = [
    test_connect_and_session,
    test_roster_get,
    test_roster_update_and_subscription,
    test_direct_message,
    test_muc_join_and_chat,
    test_muc_private_message,
    test_ping,
    test_disco,
    test_version,
    test_offline_message,
]


async def run_all(host, port, test_filter):
    for test_fn in ALL_ASYNC_TESTS:
        if test_filter and test_filter.lower() not in test_fn.__name__.lower():
            continue
        try:
            await test_fn(host, port)
        except Exception as e:
            fail(f"Unhandled exception in {test_fn.__name__}: {e}")
            traceback.print_exc()
        # Brief pause between tests to let the server clear TCP state
        await asyncio.sleep(1.5)


def main():
    parser = argparse.ArgumentParser(description="slixmpp XMPP compliance suite")
    parser.add_argument("--host",   default="angelic.local")
    parser.add_argument("--port",   type=int, default=5222)
    parser.add_argument("--filter", default=None,
                        help="Only run tests whose name contains this string")
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}slixmpp XMPP Compliance Suite{Style.RESET_ALL}")
    print(f"Target: {args.host}:{args.port}")
    print(f"slixmpp version: {slixmpp.__version__}\n")

    asyncio.run(run_all(args.host, args.port, args.filter))

    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed]

    print(f"\n{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}")
    print(f" RESULTS: {Fore.GREEN}{len(passed)} passed{Style.RESET_ALL} / "
          f"{Fore.RED}{len(failed)} failed{Style.RESET_ALL} "
          f"/ {len(results)} total")
    print(f"{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}\n")

    if failed:
        print(f"{Fore.RED}FAILED:{Style.RESET_ALL}")
        for r in failed:
            print(f"  ✗ {r.name}")
            if r.detail:
                print(f"      {r.detail[:120]}")

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())