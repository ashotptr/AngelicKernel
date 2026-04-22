#!/usr/bin/env python3
"""
dns_timing.py — Compares how long different DNS paths take for angelic.local.
Run: python3 dns_timing.py
"""
import asyncio, socket, time

HOST = "angelic.local"

async def main():
    print(f"Testing DNS resolution for: {HOST}\n")

    # 1. socket.getaddrinfo — synchronous, uses system NSS (mDNS-aware)
    t = time.monotonic()
    try:
        result = socket.getaddrinfo(HOST, 5222, socket.AF_INET)
        ip = result[0][4][0]
        print(f"[1] socket.getaddrinfo():       {(time.monotonic()-t)*1000:.0f} ms  → {ip}")
    except Exception as e:
        print(f"[1] socket.getaddrinfo():       {(time.monotonic()-t)*1000:.0f} ms  → FAILED: {e}")
        ip = None

    # 2. asyncio loop.getaddrinfo — async, runs socket.getaddrinfo in thread pool
    loop = asyncio.get_event_loop()
    t = time.monotonic()
    try:
        result = await loop.getaddrinfo(HOST, 5222, family=socket.AF_INET)
        ip2 = result[0][4][0]
        print(f"[2] loop.getaddrinfo():         {(time.monotonic()-t)*1000:.0f} ms  → {ip2}")
    except Exception as e:
        print(f"[2] loop.getaddrinfo():         {(time.monotonic()-t)*1000:.0f} ms  → FAILED: {e}")

    # 3. Connect to IP directly (skip DNS entirely)
    if ip:
        t = time.monotonic()
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, 5222))
            s.close()
            print(f"[3] TCP connect to IP {ip}:  {(time.monotonic()-t)*1000:.0f} ms  → OK")
        except Exception as e:
            print(f"[3] TCP connect to IP:          {(time.monotonic()-t)*1000:.0f} ms  → FAILED: {e}")

    print()
    print("If [2] is much slower than [1], that is the slixmpp bottleneck.")
    print("If both are fast, the problem is elsewhere in slixmpp's session setup.")

asyncio.run(main())
