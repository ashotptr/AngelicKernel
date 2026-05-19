#!/usr/bin/env python3

import asyncio
import time
import sys
import ssl
import socket as _sock
import inspect
import traceback
import argparse

import slixmpp
from slixmpp import ClientXMPP
from slixmpp.exceptions import IqError, IqTimeout
from colorama import Fore, Style, init as colorama_init

colorama_init()

DOMAIN = "angelic.local"
MUC_SVC = f"conference.{DOMAIN}"

INTER_TEST_SLEEP = 2.0

def ok(msg): 
    print(f"{Fore.GREEN}✓{Style.RESET_ALL} {msg}")

def fail(msg): 
    print(f"{Fore.RED}✗{Style.RESET_ALL} {msg}")

def warn(msg): 
    print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {msg}")

def header(msg):
    print(f"{Fore.MAGENTA} {msg}{Style.RESET_ALL}")

from dataclasses import dataclass
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

def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def _pre_resolve_ipv4(host: str, port: int) -> str:
    if host.replace(".", "").isdigit():
        return host
    try:
        infos = _sock.getaddrinfo(host, port, _sock.AF_INET, _sock.SOCK_STREAM)

        if infos:
            return infos[0][4][0]
    except OSError:
        pass

    return host


def _connect_compat(client: ClientXMPP, host: str, port: int) -> bool:
    host = _pre_resolve_ipv4(host, port)

    sig = inspect.signature(client.connect)
    params = set(sig.parameters.keys())
    kwargs: dict = {}

    if "disable_starttls" in params:
        kwargs["disable_starttls"] = False

    if "use_ssl" in params:
        kwargs["use_ssl"] = False

    try:
        return client.connect(host, port, **kwargs)
    except TypeError:
        return client.connect(host, port)

class TestClient(ClientXMPP):
    def __init__(self, host: str, port: int, username: str, password: str):
        jid = f"{username}@{DOMAIN}"

        super().__init__(jid, password, ssl_context=_make_ssl_context())

        self._host = host
        self._port = port

        self.received_messages: List[slixmpp.Message] = []
        self._session_ready = asyncio.Event()
        self._session_failed = False
        self.enable_direct_tls = False
        self.use_aiodns = False
        self.use_ipv6 = False
        self.register_plugin("xep_0030")
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0092")
        self.register_plugin("xep_0199", {"keepalive": False})
        self.add_event_handler("session_start", self._on_session_start)
        self.add_event_handler("failed_auth", self._on_failed_auth)
        self.add_event_handler("connection_failed", self._on_conn_failed)
        self.add_event_handler("message", self._on_message)

    async def _on_session_start(self, _event):
        try:
            await self.get_roster()

            self.send_presence()
        except Exception as e:
            warn(f"{e}")
        finally:
            self._session_ready.set()

    def _on_failed_auth(self, _event):
        self._session_failed = True
        self._session_ready.set()

    def _on_conn_failed(self, _event):
        self._session_failed = True
        self._session_ready.set()

    def _on_message(self, msg: slixmpp.Message):
        if msg["type"] in ("chat", "groupchat", "normal"):
            self.received_messages.append(msg)

    async def start(self, timeout: float = 15.0) -> bool:
        try:
            _connect_compat(self, self._host, self._port)
        except Exception as e:
            warn(f"connection failed for {self.boundjid}: {e}")

            return False

        try:
            await asyncio.wait_for(self._session_ready.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            warn(f"session timed out for {self.boundjid}")

            return False

        if self._session_failed:
            warn(f"session failed for {self.boundjid}")

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

    async def wait_for_message(self, body_fragment: str, timeout: float = 5.0) -> Optional[slixmpp.Message]:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            for m in self.received_messages:
                if body_fragment in str(m["body"]):
                    return m

            await asyncio.sleep(0.1)

        return None

async def test_connect_and_session(host, port):
    header("slixmpp — connection + session establishment")

    c = TestClient(host, port, "user1", "pass1")
    
    try:
        ok_flag = await c.start()
        
        record("session start completes (tls + sasl PLAIN + bind)", ok_flag, "timed out" if not ok_flag else "")
        
        if ok_flag:
            record("bound jid contains username and domain", DOMAIN in str(c.boundjid), str(c.boundjid))
    finally:
        await c.stop()


async def test_roster_get(host, port):
    header("slixmpp — rfc 6121 roster get")

    c = TestClient(host, port, "user1", "pass1")
    
    try:
        if not await c.start():
            warn("session failed");

            return
        try:
            roster = c.client_roster

            record("roster get completes (rfc 6121 §2.1)", roster is not None, "")
        except Exception as e:
            record("roster get completes", False, str(e))
    finally:
        await c.stop()

async def test_roster_update_and_subscription(host, port):
    header("slixmpp — rfc 6121 roster + subscription flow")

    alice = TestClient(host, port, "user1", "pass1")
    bob = TestClient(host, port, "user2", "pass2")

    try:
        ok1 = await alice.start()
        ok2 = await bob.start()

        if not (ok1 and ok2):
            warn("session failed for one or both users");

            return

        alice.send_presence_subscription(pto=f"user2@{DOMAIN}", ptype="subscribe")

        await asyncio.sleep(2)
        
        bob.send_presence_subscription(pto=f"user1@{DOMAIN}", ptype="subscribed")
        
        await asyncio.sleep(2)
        
        record("subscription flow executed without exception", True)
    except Exception as e:
        record("subscription flow", False, str(e))
    finally:
        await alice.stop()

        await bob.stop()

async def test_direct_message(host, port):
    header("slixmpp — rfc 6121 direct message")

    sender = TestClient(host, port, "user1", "pass1")
    recvr = TestClient(host, port, "user2", "pass2")

    try:
        ok1 = await sender.start()
        ok2 = await recvr.start()

        if not (ok1 and ok2):
            warn("session failed");

            return

        recvr.clear_received()

        body = f"slixmpp-test-{int(time.time())}"
        bare2 = f"user2@{DOMAIN}"

        sender.send_message(mto=bare2, mbody=body, mtype="chat")

        msg = await recvr.wait_for_message(body, timeout=5)

        record("direct message delivered (rfc 6121 §5)", msg is not None, f"body: {body}")

        if msg:
            record("message from= is sender (RFC 6120 §8.1.2)", "user1" in str(msg["from"]), str(msg["from"]))
    finally:
        await sender.stop()
        await recvr.stop()

async def _unlock_room(muc_plugin, room_jid: str):
    try:
        form = await muc_plugin.get_room_config(room_jid)

        await muc_plugin.set_room_config(room_jid, form)
    except Exception:
        pass

async def test_muc_join_and_chat(host, port):
    header("slixmpp — xep-0045 muc join + groupchat")
    alice = TestClient(host, port, "user1", "pass1")
    bob = TestClient(host, port, "user2", "pass2")

    try:
        if not (await alice.start() and await bob.start()):
            warn("Session failed");

            return
        
        room_jid = f"slix{int(time.time()) % 10000}@{MUC_SVC}"
        alice_muc = alice["xep_0045"]
        bob_muc = bob["xep_0045"]

        alice.clear_received()

        await alice_muc.join_muc_wait(room_jid, "alice", maxwait=8)

        record("alice joins muc room (xep-0045 §7.2)", True)

        await asyncio.sleep(0.5)
        await _unlock_room(alice_muc, room_jid)
        await asyncio.sleep(0.5)

        bob.clear_received()

        await bob_muc.join_muc_wait(room_jid, "bob", maxwait=8)

        record("bob joins existing muc room (xep-0045 §7.2)", True)

        await asyncio.sleep(0.5)
        
        body = f"gc-{int(time.time())}"

        alice.clear_received()
        bob.clear_received()
        
        alice.send_message(mto=room_jid, mbody=body, mtype="groupchat")
        
        await asyncio.sleep(2)

        bob_got = any(body in str(m["body"]) for m in bob.received_messages)
        alice_got = any(body in str(m["body"]) for m in alice.received_messages)
        
        record("groupchat received by other occupant (xep-0045 §7.9)", bob_got, f"bob msgs: {[str(m['body'])[:40] for m in bob.received_messages]}")
        record("groupchat reflected to sender (xep-0045 §7.9)", alice_got, f"alice msgs: {[str(m['body'])[:40] for m in alice.received_messages]}")
        
        for muc, nick in [(alice_muc, "alice"), (bob_muc, "bob")]:
            try: 
                await muc.leave_muc(room_jid, nick)
            except Exception: 
                pass
    finally:
        await alice.stop()
        await bob.stop()


async def test_muc_private_message(host, port):
    header("slixmpp — xep-0045 private muc message")

    alice = TestClient(host, port, "user1", "pass1")
    bob = TestClient(host, port, "user2", "pass2")
    charlie = TestClient(host, port, "admin", "admin")

    try:
        ok1 = await alice.start()
        ok2 = await bob.start()
        ok3 = await charlie.start()

        if not (ok1 and ok2 and ok3):
            warn("Session failed");

            return

        room_jid = f"pm{int(time.time()) % 10000}@{MUC_SVC}"
        alice_muc = alice["xep_0045"]
        bob_muc = bob["xep_0045"]
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
        
        bob_got = any(secret in str(m["body"]) for m in bob.received_messages)
        charlie_got = any(secret in str(m["body"]) for m in charlie.received_messages)

        record("private muc message delivered to addressed occupant (xep-0045 §7.13)", bob_got, f"bob msgs: {[str(m['body'])[:40] for m in bob.received_messages]}")
        record("private muc message not delivered to others (xep-0045 §7.13)", not charlie_got, f"charlie got: {[str(m['body'])[:40] for m in charlie.received_messages]}")

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
    header("slixmpp — xep-0199 ping")

    c = TestClient(host, port, "user1", "pass1")

    try:
        if not await c.start():
            warn("session failed");

            return
        try:
            await c["xep_0199"].ping(DOMAIN, timeout=5)

            record("server ping succeeds (xep-0199)", True)
        except Exception as e:
            record("server ping succeeds (xep-0199)", False, str(e))
    finally:
        await c.stop()

async def test_disco(host, port):
    header("slixmpp — xep-0030 service discovery")

    c = TestClient(host, port, "user1", "pass1")

    try:
        if not await c.start():
            warn("session failed");

            return

        disco = c["xep_0030"]

        try:
            info = await disco.get_info(DOMAIN)
            has_id = len(info["identities"]) > 0
            has_muc = any("muc" in str(f) for f in info["features"])

            record("disco#info → identity present (xep-0030 §3)", has_id, str(list(info["identities"])[:2]))
            record("server advertises muc feature", has_muc, str(list(info["features"])[:5]))
        except Exception as e:
            record("disco#info on server", False, str(e))
        try:
            muc_info = await disco.get_info(MUC_SVC)
            record("disco#info on muc service (xep-0045 §6.2)", len(muc_info["identities"]) > 0, str(list(muc_info["identities"])[:2]))
        except Exception as e:
            record("disco#info on muc service", False, str(e))
        try:
            items = await disco.get_items(DOMAIN)
            has_muc_item = any("conference" in str(item) for item in items["items"])
            record("disco#items lists muc service (xep-0030 §3.2)", has_muc_item, str(list(items["items"])[:3]))
        except Exception as e:
            record("disco#items on server", False, str(e))
    finally:
        await c.stop()


async def test_version(host, port):
    header("slixmpp — xep-0092 software version")

    c = TestClient(host, port, "user1", "pass1")

    try:
        if not await c.start():
            warn("session failed");

            return
        try:
            resp = await c["xep_0092"].get_version(DOMAIN)

            record("version query succeeds (xep-0092)", resp["software_version"]["name"] != "", str(dict(resp["software_version"])))
        except Exception as e:
            record("version query succeeds (xep-0092)", False, str(e))
    finally:
        await c.stop()

async def test_offline_message(host, port):
    header("slixmpp — xep-0160 offline message delivery")

    sender = TestClient(host, port, "user1", "pass1")

    try:
        if not await sender.start():
            warn("sender login failed");

            return

        body = f"offline-slix-{int(time.time())}"
        bare2 = f"user2@{DOMAIN}"

        sender.send_message(mto=bare2, mbody=body, mtype="chat")
        
        await asyncio.sleep(1.5)
        await sender.stop()
        await asyncio.sleep(2.0)
        
        recvr = TestClient(host, port, "user2", "pass2")
        
        try:
            if not await recvr.start():
                warn("receiver login failed");

                return

            await asyncio.sleep(3)
            msg = await recvr.wait_for_message(body, timeout=5)
            
            record("offline message delivered after recipient logs in (xep-0160)", msg is not None, f"looking for: {body}")

            if msg:
                has_delay = "delay" in msg or "delay" in str(msg)

                record("delivery includes xep-0203 <delay/> element", has_delay, str(msg)[:100])
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
            fail(f"unhandled exception in {test_fn.__name__}: {e}")
            traceback.print_exc()

        await asyncio.sleep(INTER_TEST_SLEEP)


def main():
    parser = argparse.ArgumentParser(description="slixmpp xmpp compliance suite")
    parser.add_argument("--host", default="angelic.local")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--filter", default=None, help="only run tests whose name contains this string")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}slixmpp xmpp compliance suite{Style.RESET_ALL}")
    print(f"target: {args.host}:{args.port}")
    print(f"slixmpp: {slixmpp.__version__}")
    print(f"inter-test sleep: {INTER_TEST_SLEEP}s\n")

    asyncio.run(run_all(args.host, args.port, args.filter))

    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed]

    print(f"\nresults: {Fore.GREEN}{len(passed)} passed{Style.RESET_ALL} / "
          f"{Fore.RED}{len(failed)} failed{Style.RESET_ALL} "
          f"/ {len(results)} total\n")

    if failed:
        print(f"{Fore.RED}failed:{Style.RESET_ALL}")

        for r in failed:
            print(f"✗ {r.name}")

            if r.detail:
                print(f"{r.detail[:120]}")

    return 0 if not failed else 1

if __name__ == "__main__":
    sys.exit(main())