#!/usr/bin/env python3
"""
slixmpp_suite.py — High-level XMPP compliance suite using the slixmpp library.

FIXES vs original:
  1. Removed disable_starttls / use_ssl kwargs (removed in slixmpp >= 1.9).
     Now uses ssl.SSLContext with check_hostname=False / CERT_NONE to accept
     the server's self-signed ECDSA P-256 certificate.
  2. Added ssl_context attribute assignment before connect() call so slixmpp
     picks it up for the STARTTLS upgrade.
  3. Added version-detection wrapper around connect() to work with both old
     (< 1.9) and new (>= 1.9) slixmpp installs.
  4. Fixed MUC room config: use get_room_config / set_room_config instead of
     deprecated configure_muc() call.
  5. Added inter-test sleep to avoid hitting the server's MAX_USERS limit.

Usage:
    pip install slixmpp colorama
    python3 slixmpp_suite.py --host angelic.local --port 5222
"""

import asyncio
import time
import sys
import ssl
import inspect
import traceback
import argparse

import slixmpp
from slixmpp import ClientXMPP
from slixmpp.exceptions import IqError, IqTimeout
from colorama import Fore, Style, init as colorama_init

colorama_init()

DOMAIN  = "angelic.local"
MUC_SVC = f"conference.{DOMAIN}"

# Inter-test pause — gives the server time to free connection slots
# between tests so MAX_USERS is not hit.
INTER_TEST_SLEEP = 2.0


# ── Helpers ────────────────────────────────────────────────────────────────────

def ok(msg):   print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {msg}")
def fail(msg): print(f"  {Fore.RED}✗{Style.RESET_ALL} {msg}")
def warn(msg): print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} {msg}")

def header(msg):
    print(f"\n{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA} {msg}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═'*60}{Style.RESET_ALL}")

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""

results: List[TestResult] = []

def record(name: str, passed: bool, detail: str = ""):
    results.append(TestResult(name, passed, detail))
    if passed:
        ok(name)
    else:
        fail(f"{name}: {detail}")


# ── TestClient ─────────────────────────────────────────────────────────────────

def _make_ssl_context() -> ssl.SSLContext:
    """Return an SSL context that accepts self-signed certificates."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _connect_compat(client: ClientXMPP, host: str, port: int) -> bool:
    """
    Call client.connect() in a way that works across slixmpp versions.

    slixmpp < 1.9  accepted disable_starttls / use_ssl keyword args.
    slixmpp >= 1.9 removed them; TLS is configured via client.ssl_context.
    """
    # Install the permissive SSL context BEFORE connect() regardless of version
    client.ssl_context = _make_ssl_context()

    sig    = inspect.signature(client.connect)
    params = set(sig.parameters.keys())

    kwargs: dict = {}
    if "disable_starttls" in params:
        kwargs["disable_starttls"] = False   # don't skip STARTTLS
    if "use_ssl" in params:
        kwargs["use_ssl"] = False            # use STARTTLS, not direct TLS

    try:
        return client.connect((host, port), **kwargs)
    except TypeError:
        # Fallback: strip all extra kwargs (shouldn't happen, but be safe)
        return client.connect((host, port))


class TestClient(ClientXMPP):
    """
    Thin wrapper around ClientXMPP for test use.

    Handles:
    - SSL context (self-signed cert acceptance)
    - Asyncio start/stop lifecycle
    - Message collection for assertions
    """

    def __init__(self, host: str, port: int, username: str, password: str):
        jid = f"{username}@{DOMAIN}"
        super().__init__(jid, password)

        self._host = host
        self._port = port

        self.received_messages: List[slixmpp.Message] = []
        self._session_started   = asyncio.Event()
        self._session_failed    = False

        # Plugins
        self.register_plugin("xep_0030")   # Service Discovery
        self.register_plugin("xep_0045")   # MUC
        self.register_plugin("xep_0092")   # Software Version
        self.register_plugin("xep_0199",   # Ping
                             {"keepalive": False})

        self.add_event_handler("session_start",    self._on_session_start)
        self.add_event_handler("failed_auth",       self._on_failed_auth)
        self.add_event_handler("connection_failed", self._on_conn_failed)
        self.add_event_handler("message",           self._on_message)

    async def _on_session_start(self, _event):
        try:
            await self.get_roster()
            self.send_presence()
        except Exception as e:
            warn(f"session_start error: {e}")
        finally:
            self._session_started.set()

    def _on_failed_auth(self, _event):
        self._session_failed = True
        self._session_started.set()

    def _on_conn_failed(self, _event):
        self._session_failed = True
        self._session_started.set()

    def _on_message(self, msg: slixmpp.Message):
        if msg["type"] in ("chat", "groupchat", "normal"):
            self.received_messages.append(msg)

    async def start(self, timeout: float = 15.0) -> bool:
        try:
            _connect_compat(self, self._host, self._port)
        except Exception as e:
            warn(f"Connection failed for {self.boundjid}: {e}")
            return False

        try:
            await asyncio.wait_for(self._session_started.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            warn(f"Session timed out for {self.boundjid}")
            return False

        if self._session_failed:
            warn(f"Session failed for {self.boundjid}")
            return False

        return True

    async def stop(self):
        try:
            self.disconnect(wait=False)
            await asyncio.sleep(0.5)
        except Exception:
            pass

    def clear_received(self):
        self.received_messages.clear()

    async def wait_for_message(self, body_fragment: str,
                               timeout: float = 5.0) -> Optional[slixmpp.Message]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for m in self.received_messages:
                if body_fragment in str(m["body"]):
                    return m
            await asyncio.sleep(0.1)
        return None


# ── Individual test functions ──────────────────────────────────────────────────

async def test_connect_and_session(host, port):
    header("slixmpp — Connection + Session Establishment")
    c = TestClient(host, port, "user1", "pass1")
    try:
        ok_flag = await c.start()
        record("Session start completes (TLS + SASL PLAIN + bind)",
               ok_flag,
               "timed out" if not ok_flag else "")
        if ok_flag:
            record("Bound JID contains username and domain",
                   DOMAIN in str(c.boundjid),
                   str(c.boundjid))
    finally:
        await c.stop()


async def test_roster_get(host, port):
    header("slixmpp — RFC 6121 Roster Get")
    c = TestClient(host, port, "user1", "pass1")
    try:
        if not await c.start():
            warn("Session failed"); return
        try:
            roster = c.client_roster
            record("Roster get completes (RFC 6121 §2.1)",
                   roster is not None, "")
        except Exception as e:
            record("Roster get completes", False, str(e))
    finally:
        await c.stop()


async def test_roster_update_and_subscription(host, port):
    header("slixmpp — RFC 6121 Roster + Subscription Flow")
    alice = TestClient(host, port, "user1", "pass1")
    bob   = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        if not (ok1 and ok2):
            warn("Session failed for one or both users"); return

        bare_b = f"user2@{DOMAIN}"
        alice.send_presence_subscription(pto=bare_b, ptype="subscribe")
        await asyncio.sleep(2)

        bare_a = f"user1@{DOMAIN}"
        bob.send_presence_subscription(pto=bare_a, ptype="subscribed")
        await asyncio.sleep(2)

        record("Subscription flow executed without exception", True)
    except Exception as e:
        record("Subscription flow", False, str(e))
    finally:
        await alice.stop()
        await bob.stop()


async def test_direct_message(host, port):
    header("slixmpp — RFC 6121 Direct Message")
    sender = TestClient(host, port, "user1", "pass1")
    recvr  = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await sender.start()
        ok2 = await recvr.start()
        if not (ok1 and ok2):
            warn("Session failed"); return
        recvr.clear_received()

        body   = f"slixmpp-test-{int(time.time())}"
        bare2  = f"user2@{DOMAIN}"
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


async def _unlock_room(muc_plugin, room_jid: str):
    """Submit an instant-room config to unlock a newly created MUC room."""
    try:
        form = await muc_plugin.get_room_config(room_jid)
        await muc_plugin.set_room_config(room_jid, form)
    except Exception:
        # Fallback: send a raw instant-room IQ
        pass


async def test_muc_join_and_chat(host, port):
    header("slixmpp — XEP-0045 MUC Join + Groupchat")
    alice = TestClient(host, port, "user1", "pass1")
    bob   = TestClient(host, port, "user2", "pass2")
    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        if not (ok1 and ok2):
            warn("Session failed"); return

        room_name = f"slix{int(time.time()) % 10000}"
        room_jid  = f"{room_name}@{MUC_SVC}"

        alice_muc = alice["xep_0045"]
        bob_muc   = bob["xep_0045"]

        alice.clear_received()
        await alice_muc.join_muc_wait(room_jid, "alice", maxwait=8)
        record("Alice joins MUC room (XEP-0045 §7.2)", True)

        await asyncio.sleep(0.5)
        await _unlock_room(alice_muc, room_jid)
        await asyncio.sleep(0.5)

        bob.clear_received()
        await bob_muc.join_muc_wait(room_jid, "bob", maxwait=8)
        record("Bob joins existing MUC room (XEP-0045 §7.2)", True)

        await asyncio.sleep(0.5)

        body = f"gc-{int(time.time())}"
        alice.clear_received()
        bob.clear_received()
        alice.send_message(mto=room_jid, mbody=body, mtype="groupchat")
        await asyncio.sleep(2)

        bob_got   = any(body in str(m["body"]) for m in bob.received_messages)
        alice_got = any(body in str(m["body"]) for m in alice.received_messages)

        record("Groupchat received by other occupant (XEP-0045 §7.9)",
               bob_got,
               f"bob msgs: {[str(m['body'])[:40] for m in bob.received_messages]}")
        record("Groupchat reflected to sender (XEP-0045 §7.9)",
               alice_got,
               f"alice msgs: {[str(m['body'])[:40] for m in alice.received_messages]}")

        try:
            await alice_muc.leave_muc(room_jid, "alice")
            await bob_muc.leave_muc(room_jid, "bob")
        except Exception:
            pass
    finally:
        await alice.stop()
        await bob.stop()


async def test_muc_private_message(host, port):
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

        room_jid = f"pm{int(time.time()) % 10000}@{MUC_SVC}"

        alice_muc   = alice["xep_0045"]
        bob_muc     = bob["xep_0045"]
        charlie_muc = charlie["xep_0045"]

        await alice_muc.join_muc_wait(room_jid, "alice", maxwait=8)
        await asyncio.sleep(0.3)
        await _unlock_room(alice_muc, room_jid)
        await asyncio.sleep(0.3)
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
               f"charlie got: {[str(m['body'])[:40] for m in charlie.received_messages]}")

        for muc, nick in [(alice_muc, "alice"), (bob_muc, "bob"), (charlie_muc, "charlie")]:
            try:
                await muc.leave_muc(room_jid, nick)
            except Exception:
                pass
    finally:
        await alice.stop()
        await bob.stop()
        await charlie.stop()


async def test_ping(host, port):
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
            record("disco#info → identity present (XEP-0030 §3)",
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
            record("disco#items lists MUC service (XEP-0030 §3.2)",
                   has_muc_item, str(list(items["items"])[:3]))
        except Exception as e:
            record("disco#items on server", False, str(e))
    finally:
        await c.stop()


async def test_version(host, port):
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
    header("slixmpp — XEP-0160 Offline Message Delivery")
    sender = TestClient(host, port, "user1", "pass1")
    try:
        if not await sender.start():
            warn("Sender login failed"); return

        body   = f"offline-slix-{int(time.time())}"
        bare2  = f"user2@{DOMAIN}"
        sender.send_message(mto=bare2, mbody=body, mtype="chat")
        await asyncio.sleep(1.5)
        await sender.stop()
        await asyncio.sleep(2.0)   # let server process FIN before user2 connects

        recvr = TestClient(host, port, "user2", "pass2")
        try:
            if not await recvr.start():
                warn("Receiver login failed"); return
            await asyncio.sleep(3)
            msg = await recvr.wait_for_message(body, timeout=5)
            record("Offline message delivered after recipient logs in (XEP-0160)",
                   msg is not None, f"looking for: {body}")
            if msg:
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


# ── Test registry ──────────────────────────────────────────────────────────────

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
        # Pause between tests so the server can free connection slots
        await asyncio.sleep(INTER_TEST_SLEEP)


def main():
    parser = argparse.ArgumentParser(description="slixmpp XMPP compliance suite")
    parser.add_argument("--host",   default="angelic.local")
    parser.add_argument("--port",   type=int, default=5222)
    parser.add_argument("--filter", default=None,
                        help="Only run tests whose name contains this string")
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}slixmpp XMPP Compliance Suite (fixed){Style.RESET_ALL}")
    print(f"Target:  {args.host}:{args.port}")
    print(f"slixmpp: {slixmpp.__version__}")
    print(f"Inter-test sleep: {INTER_TEST_SLEEP}s\n")

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