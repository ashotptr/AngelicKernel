#!/usr/bin/env python3

import socket
import ssl
import time
import re
import sys
import json
import argparse
import traceback
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from colorama import Fore, Style, init as colorama_init

colorama_init()

DEFAULT_HOST = "angelic.local"
DEFAULT_PORT = 5222
RECV_TIMEOUT = 5.0
INTER_TEST_SLEEP = 0.5
DOMAIN = "angelic.local"


def ok(msg): 
    print(f"{Fore.GREEN}✓{Style.RESET_ALL} {msg}")

def fail(msg): 
    print(f"{Fore.RED}✗{Style.RESET_ALL} {msg}")

def warn(msg): 
    print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {msg}")

def info(msg): 
    print(f"{Fore.CYAN}·{Style.RESET_ALL} {msg}")

def header(msg):
    print(f"{Fore.MAGENTA} {msg}{Style.RESET_ALL}")

@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""

results: List[TestResult] = []

def record(name: str, passed: bool, detail: str = ""):
    results.append(TestResult(name, passed, detail))

    if passed:
        ok(f"{name}")
    else:
        fail(f"{name}: {detail}")

class RawXMPP:
    def __init__(self, host: str, port: int, timeout: float = RECV_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None
        self._ssl_sock = None
        self.tls_active = False
        self._buf = b""

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(self.timeout)

        s.connect((self.host, self.port))

        self._sock = s

    def close(self):
        try:
            if self._ssl_sock:
                self._ssl_sock.close()
            elif self._sock:
                self._sock.close()
        except Exception:
            pass

        self._sock = None
        self._ssl_sock = None

    def send(self, data: str):
        raw = data.encode("utf-8")

        if self._ssl_sock:
            self._ssl_sock.sendall(raw)
        else:
            self._sock.sendall(raw)

    def recv_bytes(self, n: int = 4096) -> bytes:
        try:
            if self._ssl_sock:
                chunk = self._ssl_sock.recv(n)
            else:
                chunk = self._sock.recv(n)
            return chunk
        except socket.timeout:
            return b""

    def recv_until(self, pattern: str, timeout: float = None) -> str:
        timeout = timeout or self.timeout
        deadline = time.time() + timeout

        while time.time() < deadline:
            chunk = self.recv_bytes()
            if chunk:
                self._buf += chunk
            try:
                text = self._buf.decode("utf-8", errors="replace")
            except Exception:
                text = ""

            if pattern in text:
                self._buf = b""

                return text

            if not chunk:
                time.sleep(0.05)

        text = self._buf.decode("utf-8", errors="replace")
        self._buf = b""

        return text

    def recv_all(self, wait: float = 1.5) -> str:
        deadline = time.time() + wait
        acc = b""

        while time.time() < deadline:
            chunk = self.recv_bytes()

            if chunk:
                acc += chunk

        self._buf = b""

        return acc.decode("utf-8", errors="replace")

    def upgrade_tls(self) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            self._ssl_sock = ctx.wrap_socket(self._sock, server_hostname=self.host)
            self.tls_active = True

            return True
        except Exception as e:
            warn(f"tls upgrade failed: {e}")

            return False

    def open_stream(self, to: str = DOMAIN):
        self.send(
            f"<?xml version='1.0'?>"
            f"<stream:stream to='{to}' "
            f"xmlns='jabber:client' "
            f"xmlns:stream='http://etherx.jabber.org/streams' "
            f"version='1.0'>"
        )

    def do_starttls(self) -> bool:
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

        resp = self.recv_until("<proceed", timeout=self.timeout)

        if "<proceed" not in resp:
            warn(f"no <proceed/> received: {resp[:200]}")

            return False

        if not self.upgrade_tls():
            return False

        self.open_stream()

        resp = self.recv_until("<stream:features", timeout=self.timeout)

        return "<mechanisms" in resp or "<bind" in resp

    def do_plain_auth(self, username: str, password: str) -> bool:
        import base64

        payload = base64.b64encode(
            f"\x00{username}\x00{password}".encode()
        ).decode()

        self.send(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            f"mechanism='PLAIN'>{payload}</auth>"
        )

        resp = self.recv_until("</success>", timeout=self.timeout)

        return "<success" in resp

    def do_bind(self) -> Optional[str]:
        self.send(
            "<iq type='set' id='bind1'>"
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
            "</iq>"
        )

        resp = self.recv_until("</iq>", timeout=self.timeout)
        m = re.search(r"<jid>([^<]+)</jid>", resp)

        return m.group(1) if m else None

    def full_login(self, username: str, password: str) -> Optional[str]:
        self.connect()

        self.open_stream()

        resp = self.recv_until("<stream:features", timeout=self.timeout)

        if "<starttls" not in resp:
            warn("no STARTTLS in features")

            return None

        if not self.do_starttls():
            return None

        if not self.do_plain_auth(username, password):
            return None

        self.open_stream()

        resp = self.recv_until("<stream:features", timeout=self.timeout)

        return self.do_bind()

def test_rfc6120_stream_open_basic(host, port):
    header("rfc 6120 §4.2 — stream opening")

    c = RawXMPP(host, port)

    try:
        c.connect()

        c.open_stream()

        resp = c.recv_until("<stream:features", timeout=RECV_TIMEOUT)

        record("stream:stream present in response", "stream:stream" in resp)
        record("stream:features present", "stream:features" in resp)
        record(f"from='{DOMAIN}' set (rfc 6120 §4.7.1)", f"from='{DOMAIN}'" in resp or f'from="{DOMAIN}"' in resp)
        record("version='1.0' set (rfc 6120 §4.7.5)", "version='1.0'" in resp or 'version="1.0"' in resp)
        record("id= attribute present (rfc 6120 §4.7.3)", "id=" in resp)
        record("STARTTLS offered in features (rfc 6120 §5)", "<starttls" in resp)
        record("STARTTLS marked required (rfc 6120 §5.3.2)", "<required" in resp)
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        c.close()

def test_rfc6120_stream_open_wrong_to(host, port):
    header("rfc 6120 §4.9.3.9 — host-unknown on wrong 'to'")

    c = RawXMPP(host, port)

    try:
        c.connect()
        c.send(
            "<?xml version='1.0'?>"
            "<stream:stream to='evil.example' "
            "xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams' "
            "version='1.0'>"
        )
        resp = c.recv_all(wait=3.0)

        record("stream error sent for wrong 'to' (RFC 6120 §4.9.3.9)", "<stream:error" in resp, f"got: {resp[:200]}")
        record("<host-unknown/> condition present", "host-unknown" in resp, f"got: {resp[:200]}")
        record("</stream:stream> sent before close", "</stream:stream>" in resp, f"got: {resp[:200]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        c.close()


def test_rfc6120_stream_close_graceful(host, port):
    header("rfc 6120 §4.4 — graceful stream close")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed, skipping test")

            return

        c.send("</stream:stream>")

        resp = c.recv_all(wait=2.0)

        record("server echoes </stream:stream> on close (RFC 6120 §4.4)", "</stream:stream>" in resp, f"got: {repr(resp[:200])}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()


def test_rfc6120_sasl_plain(host, port):
    header("rfc 6120 §6 — sasl authentication")

    c = RawXMPP(host, port)

    try:
        c.connect()
        c.open_stream()
        c.recv_until("<stream:features", timeout=RECV_TIMEOUT)

        if not c.do_starttls():
            warn("tls failed, skipping sasl test")

            return
        
        import base64
        
        bad_payload = base64.b64encode(b"\x00user1\x00WRONGPASSWORD").decode()
        
        c.send(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            f"mechanism='PLAIN'>{bad_payload}</auth>"
        )
        
        resp = c.recv_until("failure", timeout=RECV_TIMEOUT)
        
        record("bad credentials → <failure><not-authorized/> (rfc 6120 §6.5)", "not-authorized" in resp, f"got: {resp[:200]}")
        
        good_payload = base64.b64encode(b"\x00user1\x00pass1").decode()
        
        c.send(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            f"mechanism='PLAIN'>{good_payload}</auth>"
        )
        
        resp2 = c.recv_until("success", timeout=RECV_TIMEOUT)

        record("good credentials → <success/> (rfc 6120 §6.4.6)", "<success" in resp2, f"got: {resp2[:200]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()


def test_rfc6120_sasl_invalid_mechanism(host, port):
    header("rfc 6120 §6.5.7 — invalid sasl mechanism")

    c = RawXMPP(host, port)

    try:
        c.connect()

        c.open_stream()
        
        c.recv_until("<stream:features", timeout=RECV_TIMEOUT)
        
        if not c.do_starttls():
            warn("tls failed"); 
            
            return
        
        c.send(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            "mechanism='GSSAPI'>dGVzdA==</auth>"
        )
        
        resp = c.recv_all(wait=2.0)

        record("invalid mechanism → <invalid-mechanism/> (rfc 6120 §6.5.7)", "invalid-mechanism" in resp, f"got: {resp[:200]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        c.close()


def test_rfc6120_sasl_bad_base64(host, port):
    header("rfc 6120 §13.9.1 — bad base64 in sasl payload")

    c = RawXMPP(host, port)

    try:
        c.connect()

        c.open_stream()

        c.recv_until("<stream:features", timeout=RECV_TIMEOUT)

        if not c.do_starttls():
            warn("tls failed");

            return

        c.send(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            "mechanism='PLAIN'>NOT!!!VALID===BASE64!!!</auth>"
        )

        resp = c.recv_all(wait=2.0)

        record("bad base64 → <incorrect-encoding/> (rfc 6120 §13.9.1)", "incorrect-encoding" in resp, f"got: {resp[:200]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        c.close()

def test_rfc6120_resource_bind(host, port):
    header("rfc 6120 §7 — resource binding")

    c = RawXMPP(host, port)

    try:
        c.connect()

        c.open_stream()

        c.recv_until("<stream:features", timeout=RECV_TIMEOUT)

        if not c.do_starttls():
            warn("tls failed");

            return

        if not c.do_plain_auth("user1", "pass1"):
            warn("auth failed");

            return

        c.open_stream()

        resp = c.recv_until("<stream:features", timeout=RECV_TIMEOUT)
        
        record("post-auth features contain <bind> (rfc 6120 §7.2)", "bind" in resp, f"got: {resp[:200]}")
        
        jid = c.do_bind()
        
        record("Bind result contains full jid (rfc 6120 §7.7)", jid is not None and "@" in jid and "/" in jid, f"got jid: {jid}")

        if jid:
            record("bound jid domain matches server (rfc 6120 §7.7)", DOMAIN in jid)
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_rfc6120_iq_unknown_namespace(host, port):
    header("rfc 6120 §8.2.3 — unknown iq namespace → error")

    c = RawXMPP(host, port)
    
    try:
        jid = c.full_login("user1", "pass1")
        if not jid:
            warn("login failed");
            
            return

        c.send(
            "<iq type='get' id='unk1'>"
            "<query xmlns='urn:xmpp:completely-unknown'/>"
            "</iq>"
        )

        resp = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("unknown iq get → iq error response (rfc 6120 §8.2.3)", "type='error'" in resp or 'type="error"' in resp, f"got: {resp[:300]}")
        record("error contains <service-unavailable/> or <feature-not-implemented/>", "service-unavailable" in resp or "feature-not-implemented" in resp, f"got: {resp[:300]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        c.close()

def test_rfc6120_stream_error_invalid_namespace(host, port):
    header("rfc 6120 §4.9.3.10 — invalid-namespace")

    c = RawXMPP(host, port)

    try:
        c.connect()

        c.send(
            "<?xml version='1.0'?>"
            "<stream:stream to='angelic.local' "
            "xmlns='jabber:WRONG' "
            "xmlns:stream='http://etherx.jabber.org/streams' "
            "version='1.0'>"
        )

        resp = c.recv_all(wait=2.5)
        record("wrong xmlns → stream error (rfc 6120 §4.9.3.10)", "stream:error" in resp or "invalid-namespace" in resp, f"got: {repr(resp[:200])}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_rfc6121_roster_get(host, port):
    header("rfc 6121 §2.1 — roster management")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("Login failed");

            return
        
        c.send(
            "<iq type='get' id='rget1'>"
            "<query xmlns='jabber:iq:roster'/>"
            "</iq>"
        )
        
        resp = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("roster get → iq result (rfc 6121 §2.1.4)", "type='result'" in resp or 'type="result"' in resp, f"got: {resp[:300]}")
        record("roster result contains <query xmlns='jabber:iq:roster'>", "jabber:iq:roster" in resp, f"got: {resp[:300]}")
        
        c.send(
            "<iq type='get' id='rget2'>"
            "<query xmlns='jabber:iq:roster' ver=''/>"
            "</iq>"
        )

        resp2 = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("roster get with ver= → result contains ver= (rfc 6121 §2.6)", "ver=" in resp2, f"got: {resp2[:300]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_rfc6121_roster_set_and_push(host, port):
    header("rfc 6121 §2.1.5/6 — roster set + push")

    c = RawXMPP(host, port)
    
    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed");
            
            return

        c.send(
            "<iq type='set' id='rset1'>"
            "<query xmlns='jabber:iq:roster'>"
            "<item jid='user2@angelic.local' name='User Two'/>"
            "</query>"
            "</iq>"
        )

        resp = c.recv_until("</iq>", timeout=RECV_TIMEOUT)
        
        record("roster set → iq result (rfc 6121 §2.1.5)", "type='result'" in resp or 'type="result"' in resp, f"got: {resp[:300]}")
        
        c.send(
            "<iq type='get' id='rget3'>"
            "<query xmlns='jabber:iq:roster'/>"
            "</iq>"
        )
        
        resp2 = c.recv_until("</iq>", timeout=RECV_TIMEOUT)
        
        record("roster get after set returns stored item", "user2@angelic.local" in resp2, f"got: {resp2[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_rfc6121_initial_presence(host, port):
    header("rfc 6121 §4.2 — initial presence")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed");
            
            return

        c.send("<presence/>")

        resp = c.recv_all(wait=2.0)

        record("initial presence elicits at least one <presence> stanza", "<presence" in resp, f"got: {resp[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_rfc6121_presence_show_forwarded(host, port):
    header("rfc 6121 §4.6 — presence content forwarding")

    sender = RawXMPP(host, port)

    recvr = RawXMPP(host, port)

    try:
        jid1 = sender.full_login("user1", "pass1")
        jid2 = recvr.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed for one or both users");

            return

        recvr.send("<presence/>")
        
        recvr.recv_all(wait=1)

        sender.send(
            "<presence>"
            "<show>away</show>"
            "<status>In a meeting</status>"
            "<priority>5</priority>"
            "</presence>"
        )

        resp = recvr.recv_all(wait=2.5)

        record("<show>away</show> forwarded verbatim (rfc 6121 §4.6)", "<show>away</show>" in resp, f"got: {resp[:400]}")
        record("<status>in a meeting</status> forwarded verbatim", "in a meeting" in resp, f"got: {resp[:400]}")
        record("<priority>5</priority> forwarded verbatim", "<priority>5</priority>" in resp, f"got: {resp[:400]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        sender.close()

        recvr.close()


def test_rfc6121_direct_message(host, port):
    header("rfc 6121 §5 — message delivery")

    sender = RawXMPP(host, port)
    recvr = RawXMPP(host, port)

    try:
        jid1 = sender.full_login("user1", "pass1")
        jid2 = recvr.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed");
            
            return

        recvr.send("<presence/>")

        recvr.recv_all(wait=1)
        
        sender.send("<presence/>")
        
        sender.recv_all(wait=1)
        
        body = "hello from test harness"
        bare2 = jid2.split("/")[0]
        
        sender.send(
            f"<message to='{bare2}' type='chat' id='msg1'>"
            f"<body>{body}</body>"
            f"</message>"
        )

        resp = recvr.recv_all(wait=2.5)

        record("direct message delivered to recipient (rfc 6121 §5)", body in resp, f"got: {resp[:400]}")
        record("message from= is sender's jid (rfc 6120 §8.1.2)", jid1.split("/")[0] in resp, f"got: {resp[:400]}")
    except Exception as e:
        fail(f"Exception: {e}")
    finally:
        sender.close()

        recvr.close()


def test_rfc6121_offline_message(host, port):
    header("xep-0160 — offline message storage + delivery")

    sender = RawXMPP(host, port)
    recvr = RawXMPP(host, port)

    try:
        jid1 = sender.full_login("user1", "pass1")

        if not jid1:
            warn("sender login failed");

            return

        target_bare = f"user2@{DOMAIN}"
        body = f"offline-test-{int(time.time())}"

        sender.send("<presence/>")

        sender.recv_all(wait=1)

        sender.send(
            f"<message to='{target_bare}' type='chat' id='off1'>"
            f"<body>{body}</body>"
            f"</message>"
        )

        sender.recv_all(wait=1)

        sender.close()

        time.sleep(2.0)

        jid2 = recvr.full_login("user2", "pass2")

        if not jid2:
            warn("receiver login failed");

            return

        recvr.send("<presence/>")

        resp = recvr.recv_all(wait=4.0)

        record("offline message delivered after receiver comes online (xep-0160)", body in resp, f"got: {resp[:600]}")
        record("delivery includes xep-0203 <delay/> element", "delay" in resp, f"got: {resp[:600]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        sender.close()

        recvr.close()


def test_rfc6121_subscription_flow(host, port):
    header("rfc 6121 §3 — presence subscription")

    alice = RawXMPP(host, port)
    bob = RawXMPP(host, port)

    try:
        jid_a = alice.full_login("user1", "pass1")
        jid_b = bob.full_login("user2", "pass2")

        if not jid_a or not jid_b:
            warn("login failed");
            
            return

        alice.send("<presence/>");
        
        alice.recv_all(wait=1)
        
        bob.send("<presence/>");
        
        bob.recv_all(wait=1)
        
        bare_b = jid_b.split("/")[0]
        bare_a = jid_a.split("/")[0]
        
        alice.send(f"<presence to='{bare_b}' type='subscribe'/>")
        
        resp_b = bob.recv_all(wait=2.5)
        
        record("subscribe forwarded to recipient (rfc 6121 §3.1.3)", "type='subscribe'" in resp_b or 'type="subscribe"' in resp_b, f"got: {resp_b[:400]}")
        
        bob.send(f"<presence to='{bare_a}' type='subscribed'/>")
        
        resp_a = alice.recv_all(wait=2.5)
        
        record("subscribed forwarded back to requester (rfc 6121 §3.1.3)", "type='subscribed'" in resp_a or 'type="subscribed"' in resp_a, f"got: {resp_a[:400]}")
        
        alice.send(
            "<iq type='get' id='rchk1'>"
            "<query xmlns='jabber:iq:roster'/>"
            "</iq>"
        )

        resp_roster = alice.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("after subscription, roster shows subscription='to' (rfc 6121 §3.1)", "subscription='to'" in resp_roster or 'subscription="to"' in resp_roster, f"got: {resp_roster[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        alice.close()

        bob.close()


def _muc_join_and_unlock(c: RawXMPP, room: str, nick: str, creator: bool = False) -> bool:
    c.send(
        f"<presence to='{room}/{nick}'>"
        f"<x xmlns='http://jabber.org/protocol/muc'/>"
        f"</presence>"
    )

    resp = c.recv_all(wait=2.0)

    if "110" not in resp:
        return False

    if creator:
        c.send(
            f"<iq type='set' to='{room}' id='cfg{nick}'>"
            f"<query xmlns='http://jabber.org/protocol/muc#owner'>"
            f"<x xmlns='jabber:x:data' type='submit'>"
            f"<field var='FORM_TYPE'>"
            f"<value>http://jabber.org/protocol/muc#roomconfig</value>"
            f"</field>"
            f"</x></query></iq>"
        )

        c.recv_all(wait=1.0)

    return True


def test_xep0045_room_create_join(host, port):
    header("xep-0045 §7.2 / §10.1 — muc room create + join")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed");

            return

        c.send("<presence/>");
        
        c.recv_all(wait=1)
        
        room = f"testroom@conference.{DOMAIN}"
        
        c.send(
            f"<presence to='{room}/alice'>"
            f"<x xmlns='http://jabber.org/protocol/muc'/>"
            f"</presence>"
        )

        resp = c.recv_all(wait=2.5)

        record("join room → self-presence received (xep-0045 §7.2.2)", f"from='{room}/alice'" in resp or f'from="{room}/alice"' in resp, f"got: {resp[:400]}")
        record("self-presence contains status code 110 (xep-0045 §7.2.2)", "110" in resp, f"got: {resp[:400]}")
        record("new room creator gets status code 201 (xep-0045 §10.1)", "201" in resp, f"got: {resp[:400]}")
        record("creator gets affiliation='owner' (xep-0045 §10.1)", "affiliation='owner'" in resp or 'affiliation="owner"' in resp, f"got: {resp[:400]}")
        record("room subject sent after join (xep-0045 §7.2.15)", "<subject>" in resp, f"got: {resp[:400]}")
        
        c.send(
            f"<iq type='set' to='{room}' id='conf1'>"
            f"<query xmlns='http://jabber.org/protocol/muc#owner'>"
            f"<x xmlns='jabber:x:data' type='submit'>"
            f"<field var='FORM_TYPE'>"
            f"<value>http://jabber.org/protocol/muc#roomconfig</value>"
            f"</field></x></query></iq>"
        )
        
        resp2 = c.recv_until("</iq>", timeout=RECV_TIMEOUT)
        
        record("config submit → iq result (xep-0045 §10.1.2)", "type='result'" in resp2 or 'type="result"' in resp2, f"got: {resp2[:200]}")
        
        c.send(f"<presence to='{room}/alice' type='unavailable'/>")
        
        resp3 = c.recv_all(wait=2.0)
        
        record("leaving room → unavailable presence received (xep-0045 §7.14)", "type='unavailable'" in resp3 or 'type="unavailable"' in resp3, f"got: {resp3[:300]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

def test_xep0045_nick_conflict(host, port):
    header("xep-0045 §7.2.8 — nick conflict")

    c1 = RawXMPP(host, port)
    c2 = RawXMPP(host, port)

    try:
        jid1 = c1.full_login("user1", "pass1")
        jid2 = c2.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed");

            return

        c1.send("<presence/>");
        
        c1.recv_all(wait=1)
        
        c2.send("<presence/>");
        
        c2.recv_all(wait=1)
        
        room = f"conflictroom@conference.{DOMAIN}"
        
        _muc_join_and_unlock(c1, room, "shared", creator=True)
        
        c2.send(
            f"<presence to='{room}/shared'>"
            f"<x xmlns='http://jabber.org/protocol/muc'/>"
            f"</presence>"
        )

        resp2 = c2.recv_all(wait=2.0)
        
        record("nick conflict → <presence type='error'> (xep-0045 §7.2.8)", "type='error'" in resp2 or 'type="error"' in resp2, f"got: {resp2[:300]}")
        record("error contains <conflict/> (xep-0045 §7.2.8)", "<conflict" in resp2, f"got: {resp2[:300]}")
        
        c1.send(f"<presence to='{room}/shared' type='unavailable'/>")
        
        c1.recv_all(wait=1)
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c1.close();
        c2.close()

def test_xep0045_groupchat_message(host, port):
    header("xep-0045 §7.9 — groupchat message broadcast")

    c1 = RawXMPP(host, port)
    c2 = RawXMPP(host, port)
    
    try:
        jid1 = c1.full_login("user1", "pass1")
        jid2 = c2.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed");

            return

        c1.send("<presence/>");

        c1.recv_all(wait=1)

        c2.send("<presence/>");

        c2.recv_all(wait=1)

        room = f"chatroom@conference.{DOMAIN}"

        _muc_join_and_unlock(c1, room, "alice", creator=True)
        _muc_join_and_unlock(c2, room, "bob")

        body = f"hello-gc-{int(time.time())}"
        
        c1.send(
            f"<message to='{room}' type='groupchat' id='gc1'>"
            f"<body>{body}</body></message>"
        )

        resp1 = c1.recv_all(wait=2.5)
        resp2 = c2.recv_all(wait=2.5)

        record("groupchat message reflected to sender (xep-0045 §7.9)", body in resp1, f"sender got: {resp1[:400]}")
        record("groupchat message delivered to other occupant (xep-0045 §7.9)", body in resp2, f"other got: {resp2[:400]}")
        record("message from= is room/nick (xep-0045 §7.9)", f"{room}/alice" in resp2 or f"{room}/alice" in resp1, f"got: {resp2[:400]}")
        
        c1.send(f"<presence to='{room}/alice' type='unavailable'/>");
        
        c1.recv_all(wait=1)
        
        c2.send(f"<presence to='{room}/bob' type='unavailable'/>");
        
        c2.recv_all(wait=1)
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c1.close(); c2.close()

def test_xep0045_private_message(host, port):
    header("xep-0045 §7.13 — private muc message")

    c1 = RawXMPP(host, port)
    c2 = RawXMPP(host, port)
    c3 = RawXMPP(host, port)

    room = f"privroom@conference.{DOMAIN}"

    try:
        jid1 = c1.full_login("user1", "pass1")
        jid2 = c2.full_login("user2", "pass2")
        jid3 = c3.full_login("admin", "admin")

        if not (jid1 and jid2 and jid3):
            warn("Login failed");

            return
        for cx in (c1, c2, c3):
            cx.send("<presence/>");

            cx.recv_all(wait=0.5)

        _muc_join_and_unlock(c1, room, "alice", creator=True)
        _muc_join_and_unlock(c2, room, "bob")
        _muc_join_and_unlock(c3, room, "charlie")
        
        secret = f"private-{int(time.time())}"
        
        c1.send(
            f"<message to='{room}/bob' type='chat' id='pm1'>"
            f"<body>{secret}</body></message>"
        )
        
        resp2 = c2.recv_all(wait=2.5)
        resp3 = c3.recv_all(wait=2.5)
        
        record("private message delivered to addressed occupant (xep-0045 §7.13)", secret in resp2, f"bob got: {resp2[:400]}")
        record("private message not delivered to other occupants (xep-0045 §7.13)", secret not in resp3, f"charlie got: {resp3[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        for cx, nick in [(c1, "alice"), (c2, "bob"), (c3, "charlie")]:
            try:
                cx.send(f"<presence to='{room}/{nick}' type='unavailable'/>")

                cx.recv_all(wait=0.5)
            except Exception:
                pass

        c1.close();
        c2.close();
        c3.close()

def test_xep0045_nick_change(host, port):
    header("xep-0045 §7.6 — nick change")

    c1 = RawXMPP(host, port)
    c2 = RawXMPP(host, port)
    room = f"nickroom@conference.{DOMAIN}"
    
    try:
        jid1 = c1.full_login("user1", "pass1")
        jid2 = c2.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed");

            return

        c1.send("<presence/>");
        
        c1.recv_all(wait=0.5)
        
        c2.send("<presence/>");
        
        c2.recv_all(wait=0.5)
        
        _muc_join_and_unlock(c1, room, "alice", creator=True)
        _muc_join_and_unlock(c2, room, "bob")
        
        c1.send(
            f"<presence to='{room}/alice2'>"
            f"<x xmlns='http://jabber.org/protocol/muc'/>"
            f"</presence>"
        )

        resp1 = c1.recv_all(wait=2.5)
        resp2 = c2.recv_all(wait=2.5)

        record("nick change → unavailable from old nick (xep-0045 §7.6)", "type='unavailable'" in resp1 or "type='unavailable'" in resp2, f"got: {(resp1+resp2)[:400]}")
        record("nick change → status code 303 (xep-0045 §7.6)", "303" in resp1 or "303" in resp2, f"got: {(resp1+resp2)[:400]}")
        record("nick change → presence from new nick sent", f"{room}/alice2" in resp1 or f"{room}/alice2" in resp2, f"got: {(resp1+resp2)[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        for cx, nick in [(c1, "alice2"), (c2, "bob")]:
            try:
                cx.send(f"<presence to='{room}/{nick}' type='unavailable'/>")

                cx.recv_all(wait=0.5)
            except Exception:
                pass

        c1.close();
        c2.close()


def test_xep0045_occupant_presence_update(host, port):
    header("xep-0045 §7.16 — in-room presence update")

    c1 = RawXMPP(host, port)
    c2 = RawXMPP(host, port)
    
    room = f"statusroom@conference.{DOMAIN}"
    
    try:
        jid1 = c1.full_login("user1", "pass1")
        jid2 = c2.full_login("user2", "pass2")

        if not jid1 or not jid2:
            warn("login failed");

            return

        c1.send("<presence/>");
        
        c1.recv_all(wait=0.5)
        
        c2.send("<presence/>");
        
        c2.recv_all(wait=0.5)
        
        _muc_join_and_unlock(c1, room, "alice", creator=True)
        _muc_join_and_unlock(c2, room, "bob")
        
        c1.send(
            f"<presence to='{room}/alice'>"
            f"<show>away</show>"
            f"<status>Be right back</status>"
            f"</presence>"
        )
        
        resp2 = c2.recv_all(wait=2.5)
        
        record("in-room presence update relayed to other occupants (xep-0045 §7.16)", "<show>away</show>" in resp2 or "away" in resp2, f"bob got: {resp2[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        for cx, nick in [(c1, "alice"), (c2, "bob")]:
            try:
                cx.send(f"<presence to='{room}/{nick}' type='unavailable'/>")

                cx.recv_all(wait=0.5)
            except Exception:
                pass

        c1.close();
        c2.close()


def test_disco_info_server(host, port):
    header("xep-0030 — service discovery (disco#info)")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed");

            return
        
        c.send(
            f"<iq type='get' to='{DOMAIN}' id='disco1'>"
            f"<query xmlns='http://jabber.org/protocol/disco#info'/>"
            f"</iq>"
        )

        resp = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("disco#info → IQ result (XEP-0030 §3)", "type='result'" in resp or 'type="result"' in resp, f"got: {resp[:400]}")
        record("disco#info → <identity> present", "<identity" in resp, f"got: {resp[:400]}")
        record("disco#info → muc feature advertised", "jabber.org/protocol/muc" in resp, f"got: {resp[:400]}")

        c.send(
            f"<iq type='get' to='{DOMAIN}' id='disco2'>"
            f"<query xmlns='http://jabber.org/protocol/disco#items'/>"
            f"</iq>"
        )

        resp2 = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("disco#items on server returns muc service (xep-0030 §3.2)", "conference" in resp2, f"got: {resp2[:400]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()


def test_ping(host, port):
    header("xep-0199 — xmpp ping")

    c = RawXMPP(host, port)

    try:
        jid = c.full_login("user1", "pass1")

        if not jid:
            warn("login failed");

            return

        c.send(
            f"<iq type='get' to='{DOMAIN}' id='ping1'>"
            f"<ping xmlns='urn:ietf:params:xml:ns:xmpp-ping'/>"
            f"</iq>"
        )

        resp = c.recv_until("</iq>", timeout=RECV_TIMEOUT)

        record("ping → iq result (xep-0199)", "type='result'" in resp or 'type="result"' in resp, f"got: {resp[:200]}")
    except Exception as e:
        fail(f"exception: {e}")
    finally:
        c.close()

ALL_TESTS = [
    test_rfc6120_stream_open_basic,
    test_rfc6120_stream_open_wrong_to,
    test_rfc6120_stream_close_graceful,
    test_rfc6120_sasl_plain,
    test_rfc6120_sasl_invalid_mechanism,
    test_rfc6120_sasl_bad_base64,
    test_rfc6120_resource_bind,
    test_rfc6120_iq_unknown_namespace,
    test_rfc6120_stream_error_invalid_namespace,
    test_rfc6121_roster_get,
    test_rfc6121_roster_set_and_push,
    test_rfc6121_initial_presence,
    test_rfc6121_presence_show_forwarded,
    test_rfc6121_direct_message,
    test_rfc6121_offline_message,
    test_rfc6121_subscription_flow,
    test_xep0045_room_create_join,
    test_xep0045_nick_conflict,
    test_xep0045_groupchat_message,
    test_xep0045_private_message,
    test_xep0045_nick_change,
    test_xep0045_occupant_presence_update,
    test_disco_info_server,
    test_ping,
]

def main():
    global RECV_TIMEOUT, INTER_TEST_SLEEP

    parser = argparse.ArgumentParser(
        description="xmpp protocol compliance test harness"
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--filter", default=None, help="only run tests whose name contains this string")
    parser.add_argument("--inter-test-sleep", type=float, default=INTER_TEST_SLEEP, dest="inter_test_sleep", help=f"pause between tests (default: {INTER_TEST_SLEEP}s)")
    parser.add_argument("--recv-timeout", type=float, default=RECV_TIMEOUT, dest="recv_timeout", help=f"per-recv timeout (default: {RECV_TIMEOUT}s)")
    parser.add_argument("--json", default=None, help="write results to json file for graph generation")
    args = parser.parse_args()

    RECV_TIMEOUT = args.recv_timeout
    INTER_TEST_SLEEP = args.inter_test_sleep

    print(f"\n{Fore.CYAN}xmpp compliance test harness{Style.RESET_ALL}")
    print(f"target: {args.host}:{args.port}")
    print(f"recv timeout: {RECV_TIMEOUT}s")
    print(f"inter-test sleep: {INTER_TEST_SLEEP}s\n")

    for test_fn in ALL_TESTS:
        if args.filter and args.filter.lower() not in test_fn.__name__.lower():
            continue
        try:
            test_fn(args.host, args.port)
        except Exception as e:
            fail(f"unhandled exception in {test_fn.__name__}: {e}")

            traceback.print_exc()

        time.sleep(INTER_TEST_SLEEP)

    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed]

    print(f"results: {Fore.GREEN}{len(passed)} passed{Style.RESET_ALL} / "
          f"{Fore.RED}{len(failed)} failed{Style.RESET_ALL} "
          f"/ {len(results)} total")

    if failed:
        print(f"{Fore.RED}failed tests:{Style.RESET_ALL}")

        for r in failed:
            print(f"✗ {r.name}")

            if r.detail:
                print(f"{r.detail[:120]}")

    if args.json:
        data = {
            "passed": len(passed),
            "failed": len(failed),
            "total": len(results),
            "results": [
                {"name": r.name, "passed": r.passed, "detail": r.detail}
                for r in results
            ]
        }

        import os as _os

        _os.makedirs(_os.path.dirname(_os.path.abspath(args.json)), exist_ok=True)
        
        with open(args.json, "w") as f:
            json.dump(data, f, indent=2)
        
        print(f"\njson results written to: {args.json}")

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())