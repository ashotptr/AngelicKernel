#!/usr/bin/env python3
"""
proto_trace.py — Shows exactly what AngelicKernel sends at each step.
Focuses on what happens AFTER bind, which is where slixmpp gets stuck.

Run: python3 proto_trace.py --host angelic.local --port 5222
"""
import socket, ssl, base64, time, argparse

DOMAIN = "angelic.local"

def recv_all(sock, wait=1.5):
    sock.settimeout(0.2)
    buf = b""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk:
                buf += chunk
        except socket.timeout:
            if buf:
                break
    return buf.decode("utf-8", errors="replace")

def send(sock, data, label):
    print(f"\n>>> SEND [{label}]")
    print(f"    {data[:200]}")
    sock.sendall(data.encode() if isinstance(data, str) else data)

def recv(sock, label, wait=2.0):
    data = recv_all(sock, wait)
    print(f"\n<<< RECV [{label}]")
    print(f"    {data[:400]}")
    return data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="angelic.local")
    parser.add_argument("--port", type=int, default=5222)
    args = parser.parse_args()

    print(f"Protocol trace for {args.host}:{args.port}\n")
    print("="*60)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))

    # Step 1: plain stream open
    send(s, f"<?xml version='1.0'?><stream:stream to='{DOMAIN}' "
            f"xmlns='jabber:client' "
            f"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
         "plain stream open")
    recv(s, "server stream + features")

    # Step 2: STARTTLS
    send(s, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", "STARTTLS")
    recv(s, "proceed")

    # Step 3: TLS upgrade
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(s, server_hostname=args.host)
    print("\n[TLS handshake complete]")

    # Step 4: TLS stream open
    send(tls, f"<?xml version='1.0'?><stream:stream to='{DOMAIN}' "
              f"xmlns='jabber:client' "
              f"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
         "TLS stream open")
    recv(tls, "post-TLS features (should contain SASL)")

    # Step 5: SASL PLAIN
    payload = base64.b64encode(b"\x00user1\x00pass1").decode()
    send(tls, f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
              f"mechanism='PLAIN'>{payload}</auth>", "SASL PLAIN")
    recv(tls, "SASL result")

    # Step 6: post-SASL stream open
    send(tls, f"<?xml version='1.0'?><stream:stream to='{DOMAIN}' "
              f"xmlns='jabber:client' "
              f"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
         "post-SASL stream open")
    post_sasl = recv(tls, "post-SASL features (should contain <bind>)")

    print("\n" + "="*60)
    print("ANALYSIS: post-SASL features")
    if "<bind" in post_sasl:
        print("  ✓ <bind> advertised")
    else:
        print("  ✗ <bind> NOT found — server bug")
    if "<session" in post_sasl:
        print("  ⚠ <session> advertised — slixmpp WILL send a session IQ and wait for response")
        print("    If server ignores the session IQ, slixmpp hangs for 60s (IQ timeout)")
    else:
        print("  ✓ <session> NOT advertised — slixmpp skips session IQ, fires session_start immediately")

    # Step 7: bind
    send(tls, "<iq type='set' id='bind1'>"
              "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
              "</iq>", "resource bind")
    recv(tls, "bind result (should contain full JID)")

    # Step 8: session IQ — exactly what slixmpp sends
    print("\n" + "="*60)
    print("CRITICAL TEST: Sending session IQ (what slixmpp sends after bind)")
    send(tls, "<iq type='set' id='session_1'>"
              "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
              "</iq>", "session IQ")
    resp = recv(tls, "session IQ response (wait 3s)", wait=3.0)

    print("\n" + "="*60)
    print("SESSION IQ RESULT:")
    if "result" in resp and "session_1" in resp:
        print("  ✓ Server responded to session IQ correctly")
        print("    slixmpp should NOT be hanging on this")
    elif "error" in resp:
        print("  ✗ Server sent IQ error — slixmpp will handle this and proceed")
    elif resp.strip() == "":
        print("  ✗ Server sent NOTHING — slixmpp waits 60s for this response then times out")
        print("    FIX: either server must respond, or we tell slixmpp not to send session IQ")
    else:
        print(f"  ? Unexpected response: {resp[:200]}")

    # Step 9: roster IQ (what _on_session_start does)
    print("\n" + "="*60)
    print("Also testing: roster IQ (what get_roster() sends)")
    send(tls, "<iq type='get' id='roster1'>"
              "<query xmlns='jabber:iq:roster'/>"
              "</iq>", "roster IQ")
    roster_resp = recv(tls, "roster response", wait=3.0)
    if "result" in roster_resp:
        print("  ✓ Roster IQ responds fine")
    else:
        print(f"  ? Response: {roster_resp[:200]}")

    tls.close()

if __name__ == "__main__":
    main()
