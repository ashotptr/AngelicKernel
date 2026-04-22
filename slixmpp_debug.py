#!/usr/bin/env python3
"""
slixmpp_debug.py — Traces exactly what events slixmpp fires and when.
Run this and share the output. It will show us exactly where it gets stuck.

    python3 slixmpp_debug.py --host angelic.local --port 5222
"""
import asyncio, ssl, inspect, time, argparse
import slixmpp
from slixmpp import ClientXMPP

DOMAIN = "angelic.local"

def _make_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

class DebugClient(ClientXMPP):
    def __init__(self, host, port, user, pw):
        super().__init__(f"{user}@{DOMAIN}", pw)
        self._host = host
        self._port = port
        self._done = asyncio.Event()
        self._t0 = time.monotonic()

        def ms():
            return f"{(time.monotonic()-self._t0)*1000:.0f}ms"

        # Hook EVERY slixmpp event by wrapping event()
        _orig_event = self.event
        def _traced_event(name, data=None, *args, **kwargs):
            print(f"  [{ms()}] slixmpp fires event: '{name}'")
            return _orig_event(name, data, *args, **kwargs)
        self.event = _traced_event

        # Also hook our own handlers explicitly
        def h(name):
            def _h(ev):
                print(f"  [{ms()}] >>> OUR HANDLER for '{name}' called")
                self._done.set()
            return _h

        async def h_session(ev):
            print(f"  [{ms()}] >>> OUR session_start handler called")
            try:
                print(f"  [{ms()}]     calling get_roster()...")
                await self.get_roster()
                print(f"  [{ms()}]     get_roster() returned")
                self.send_presence()
                print(f"  [{ms()}]     send_presence() done")
            except Exception as e:
                print(f"  [{ms()}]     ERROR in session_start: {e}")
            finally:
                print(f"  [{ms()}]     setting _done event")
                self._done.set()

        self.add_event_handler("session_start",    h_session)
        self.add_event_handler("failed_auth",      h("failed_auth"))
        self.add_event_handler("connection_failed", h("connection_failed"))
        self.add_event_handler("disconnected",     h("disconnected"))

    async def run(self, timeout=90.0):
        self._t0 = time.monotonic()
        def ms():
            return f"{(time.monotonic()-self._t0)*1000:.0f}ms"

        print(f"  [0ms] Installing ssl_context")
        self.ssl_context = _make_ssl_ctx()

        print(f"  [0ms] Calling connect()...")
        sig = inspect.signature(self.connect)
        params = set(sig.parameters.keys())
        kwargs = {}
        if "use_srv" in params:
            kwargs["use_srv"] = False
            print(f"  [0ms]   use_srv=False (skipping SRV DNS lookup)")
        else:
            print(f"  [0ms]   WARNING: connect() has no use_srv param — SRV lookup will run")

        ret = self.connect((self._host, self._port), **kwargs)
        print(f"  [{ms()}] connect() returned: {ret!r}")

        print(f"  [{ms()}] Waiting for _done event (timeout={timeout}s)...")
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
            print(f"  [{ms()}] _done was set!")
        except asyncio.TimeoutError:
            print(f"  [{ms()}] TIMED OUT after {timeout}s — no event fired")
            print()
            print("DIAGNOSIS: slixmpp connected but no event fired within timeout.")
            print("Possible causes:")
            print("  1. SRV DNS lookup is hanging (would appear above as no output for >1s)")
            print("  2. server is not responding to something slixmpp sends after bind")
            print("  3. slixmpp internal state machine is waiting for a stanza")
            return

        try:
            self.disconnect(wait=False)
        except Exception:
            pass

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="angelic.local")
    parser.add_argument("--port", type=int, default=5222)
    args = parser.parse_args()

    print(f"\nslixmpp debug tracer")
    print(f"slixmpp version: {slixmpp.__version__}")
    print(f"Target: {args.host}:{args.port}\n")

    c = DebugClient(args.host, args.port, "user1", "pass1")
    await c.run(timeout=90)

if __name__ == "__main__":
    asyncio.run(main())
