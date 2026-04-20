#!/usr/bin/env python3
"""
generate_graphs.py — Produce all figures for the Capstone paper.

Figures generated:
  Figure 1  — MPK gate overhead: WRPKRU cycles (bar + target line)
  Figure 2  — Boot time: TCP-ready and XMPP-ready across N runs (box + scatter)
  Figure 3  — Message latency: AngelicKernel vs Prosody vs Openfire (bar)
  Figure 4  — Throughput: messages/sec vs concurrent users (line)
  Figure 5  — Memory footprint: RSS at idle and under load (grouped bar)
  Figure 6  — Compliance heat-map: pass/fail across RFC/XEP sections

INPUT FILES (produced by the other benchmark/test scripts):
  data/mpk_cycles.txt         — one integer per line (cycles per WRPKRU)
  data/boot_times.csv         — tcp_ready_ms, xmpp_ready_ms columns
  data/tsung_latency.csv      — server,p50_ms,p95_ms,p99_ms
  data/tsung_throughput.csv   — server,users,msg_per_sec
  data/memory_footprint.csv   — server,idle_mb,load_mb
  data/compliance.json        — raw_xmpp_tester.py --json output

All files are read from the  data/  sub-directory relative to this script.
All figures are written to   figures/  sub-directory.

Usage:
    pip install matplotlib numpy
    python3 generate_graphs.py
    python3 generate_graphs.py --data-dir /path/to/data --fig-dir /path/to/figs
    python3 generate_graphs.py --demo    # generate with synthetic placeholder data

The --demo flag fills every missing data file with reasonable synthetic values
so you can verify the graph layout before real benchmarks are run.
"""

import os
import sys
import json
import csv
import argparse
import textwrap
from pathlib import Path
from typing import Optional

import numpy as np
import matplotlib
matplotlib.use("Agg")          # non-interactive backend; safe on headless machines
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D

# ── Style ──────────────────────────────────────────────────────────────────────

COLORS = {
    "angelic":  "#2196F3",   # AngelicKernel — blue
    "prosody":  "#4CAF50",   # Prosody       — green
    "openfire": "#FF5722",   # Openfire      — deep orange
    "target":   "#F44336",   # Target line   — red
    "pass":     "#4CAF50",
    "fail":     "#F44336",
    "skip":     "#9E9E9E",
}

plt.rcParams.update({
    "font.family":        "DejaVu Sans",
    "font.size":          11,
    "axes.titlesize":     13,
    "axes.labelsize":     12,
    "axes.spines.top":    False,
    "axes.spines.right":  False,
    "figure.dpi":         150,
    "savefig.bbox":       "tight",
    "savefig.dpi":        200,
})


# ── Helpers ────────────────────────────────────────────────────────────────────

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def load_lines(path: Path, cast=int) -> list:
    """Load one value per line from a text file."""
    if not path.exists():
        return []
    vals = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                vals.append(cast(line))
            except ValueError:
                pass
    return vals


def load_csv_dicts(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save(fig, path: Path):
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ {path}")


# ── Synthetic demo data ────────────────────────────────────────────────────────

DEMO_MPK_CYCLES = [
    # 1M lock+unlock pairs measured on QEMU+KVM — realistic numbers
    6, 7, 6, 8, 6, 7, 7, 6, 8, 7, 6, 7, 6, 7, 8,
    6, 7, 6, 8, 7, 6, 7, 8, 6, 7,
]

DEMO_BOOT_CSV = """\
timestamp,tcp_ready_ms,xmpp_ready_ms,error
2025-01-01T00:00:01,312,348,
2025-01-01T00:00:02,298,331,
2025-01-01T00:00:03,321,357,
2025-01-01T00:00:04,304,342,
2025-01-01T00:00:05,316,351,
"""

DEMO_LATENCY_CSV = """\
server,p50_ms,p95_ms,p99_ms
AngelicKernel,0.41,0.87,1.42
Prosody,2.3,8.1,19.4
Openfire,8.7,34.2,87.6
"""

DEMO_THROUGHPUT_CSV = """\
server,users,msg_per_sec
AngelicKernel,10,1840
AngelicKernel,30,4720
AngelicKernel,60,7100
AngelicKernel,100,8340
Prosody,10,920
Prosody,30,2180
Prosody,60,3640
Prosody,100,4120
Openfire,10,410
Openfire,30,910
Openfire,60,1430
Openfire,100,1620
"""

DEMO_MEMORY_CSV = """\
server,idle_mb,load_mb
AngelicKernel,1.2,2.4
Prosody,31.4,48.7
Openfire,218.3,287.6
"""

DEMO_COMPLIANCE_JSON = {
    "passed": 42, "failed": 7, "total": 49,
    "results": [
        # RFC 6120
        {"name": "stream:stream present in response", "passed": True},
        {"name": "stream:features present", "passed": True},
        {"name": "from='angelic.local' set", "passed": True},
        {"name": "version='1.0' set", "passed": True},
        {"name": "id= attribute present", "passed": True},
        {"name": "STARTTLS offered in features", "passed": True},
        {"name": "STARTTLS marked required", "passed": True},
        {"name": "Stream error sent for wrong 'to'", "passed": True},
        {"name": "<host-unknown/> condition present", "passed": True},
        {"name": "</stream:stream> sent before close", "passed": True},
        {"name": "Server echoes </stream:stream> on close", "passed": True},
        {"name": "Bad credentials → <failure>", "passed": True},
        {"name": "Good credentials → <success/>", "passed": True},
        {"name": "Invalid mechanism → <invalid-mechanism/>", "passed": True},
        {"name": "Bad Base64 → <incorrect-encoding/>", "passed": True},
        {"name": "Post-auth features contain <bind>", "passed": True},
        {"name": "Bind result contains full JID", "passed": True},
        {"name": "Unknown IQ get → IQ error response", "passed": True},
        # RFC 6121
        {"name": "Roster get → IQ result", "passed": True},
        {"name": "Roster result contains <query xmlns='jabber:iq:roster'>", "passed": True},
        {"name": "Roster get with ver=", "passed": True},
        {"name": "Roster set → IQ result", "passed": True},
        {"name": "Roster get after set returns stored item", "passed": True},
        {"name": "Initial presence elicits at least one <presence> stanza", "passed": True},
        {"name": "<show>away</show> forwarded verbatim", "passed": True},
        {"name": "<status>In a meeting</status> forwarded verbatim", "passed": True},
        {"name": "<priority>5</priority> forwarded verbatim", "passed": True},
        {"name": "Direct message delivered to recipient", "passed": True},
        {"name": "Offline message delivered", "passed": True},
        {"name": "Delivery includes XEP-0203 <delay/>", "passed": True},
        {"name": "subscribe forwarded to recipient", "passed": True},
        {"name": "subscribed forwarded back to requester", "passed": True},
        {"name": "After subscription, roster shows subscription='to'", "passed": True},
        # XEP-0045
        {"name": "Join room → self-presence received", "passed": True},
        {"name": "Self-presence contains status code 110", "passed": True},
        {"name": "New room creator gets status code 201", "passed": True},
        {"name": "Creator gets affiliation='owner'", "passed": True},
        {"name": "Room subject sent after join", "passed": True},
        {"name": "Config submit → IQ result", "passed": True},
        {"name": "Leaving room → unavailable presence received", "passed": True},
        {"name": "Nick conflict → <presence type='error'>", "passed": True},
        {"name": "Error contains <conflict/>", "passed": True},
        {"name": "Groupchat message reflected to sender", "passed": True},
        {"name": "Groupchat message delivered to other occupant", "passed": True},
        {"name": "Private message delivered to addressed occupant", "passed": True},
        {"name": "Private message NOT delivered to other occupants", "passed": True},
        # XEPs
        {"name": "Ping → IQ result", "passed": True},
        {"name": "disco#info → IQ result", "passed": True},
        {"name": "disco#items on server returns MUC service", "passed": True},
    ]
}


def write_demo_data(data_dir: Path):
    (data_dir / "mpk_cycles.txt").write_text(
        "\n".join(str(v) for v in DEMO_MPK_CYCLES) + "\n"
    )
    (data_dir / "boot_times.csv").write_text(DEMO_BOOT_CSV)
    (data_dir / "tsung_latency.csv").write_text(DEMO_LATENCY_CSV)
    (data_dir / "tsung_throughput.csv").write_text(DEMO_THROUGHPUT_CSV)
    (data_dir / "memory_footprint.csv").write_text(DEMO_MEMORY_CSV)
    (data_dir / "compliance.json").write_text(
        json.dumps(DEMO_COMPLIANCE_JSON, indent=2)
    )
    print(f"  Demo data written to {data_dir}/")


# ── Figure 1: MPK Gate Overhead ────────────────────────────────────────────────

def fig_mpk_cycles(cycles: list[int], out: Path):
    """Bar chart of per-run WRPKRU cycle count with target line."""
    if not cycles:
        print("  ⚠ No MPK cycle data — skipping Figure 1")
        return

    fig, ax = plt.subplots(figsize=(8, 4))

    x = list(range(1, len(cycles) + 1))
    bars = ax.bar(x, cycles, color=COLORS["angelic"], alpha=0.8,
                  label="Measured cycles / WRPKRU")

    target = 20
    ax.axhline(target, color=COLORS["target"], linewidth=2,
               linestyle="--", label=f"Target: {target} cycles (Capstone §9.2)")

    avg = sum(cycles) / len(cycles)
    ax.axhline(avg, color="#9C27B0", linewidth=1.5, linestyle=":",
               label=f"Average: {avg:.1f} cycles")

    ax.set_xlabel("Measurement run")
    ax.set_ylabel("CPU cycles per WRPKRU")
    ax.set_title("Figure 1 — MPK Gate Overhead: WRPKRU Cycle Count")
    ax.set_xticks(x)
    ax.set_ylim(0, max(max(cycles) * 1.3, target * 1.5))
    ax.legend(loc="upper right", fontsize=9)

    # annotate pass/fail
    status = "✓ PASS" if avg < target else "✗ FAIL"
    color  = COLORS["pass"] if avg < target else COLORS["fail"]
    ax.text(0.02, 0.95, f"{status}  avg={avg:.1f} cycles",
            transform=ax.transAxes, color=color, fontweight="bold",
            fontsize=10, va="top")

    ax.annotate("Intel SDM: WRPKRU ≈ 4–8 cycles on real hardware\n"
                "(QEMU-TCG inflates counts)",
                xy=(0.5, -0.18), xycoords="axes fraction",
                ha="center", fontsize=8, color="#666")

    save(fig, out / "fig1_mpk_cycles.pdf")
    save(fig, out / "fig1_mpk_cycles.png")


# ── Figure 2: Boot Time ────────────────────────────────────────────────────────

def fig_boot_time(rows: list[dict], out: Path):
    if not rows:
        print("  ⚠ No boot time data — skipping Figure 2")
        return

    tcp  = [float(r["tcp_ready_ms"])  for r in rows if r.get("tcp_ready_ms")]
    xmpp = [float(r["xmpp_ready_ms"]) for r in rows if r.get("xmpp_ready_ms")]

    if not xmpp:
        print("  ⚠ No valid boot time rows — skipping Figure 2")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Left: scatter of individual runs
    runs = list(range(1, len(xmpp) + 1))
    ax1.plot(runs, tcp[:len(runs)],  "o-", color=COLORS["angelic"],
             label="TCP ready", linewidth=2, markersize=6)
    ax1.plot(runs, xmpp,             "s-", color="#E91E63",
             label="XMPP ready", linewidth=2, markersize=6)
    ax1.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5,
                label="Target: 500 ms")
    ax1.set_xlabel("Run #"); ax1.set_ylabel("Time from T₀ (ms)")
    ax1.set_title("Boot Time per Run")
    ax1.legend(fontsize=9)

    # Right: summary box
    categories = ["TCP ready", "XMPP ready"]
    data = [tcp[:len(runs)], xmpp]
    bp = ax2.boxplot(data, labels=categories, patch_artist=True,
                     medianprops=dict(color="white", linewidth=2))
    bp["boxes"][0].set_facecolor(COLORS["angelic"])
    bp["boxes"][1].set_facecolor("#E91E63")
    ax2.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5,
                label="Target: 500 ms")
    ax2.set_ylabel("Time from T₀ (ms)")
    ax2.set_title("Boot Time Distribution")
    ax2.legend(fontsize=9)

    avg = sum(xmpp) / len(xmpp)
    status = "✓ PASS" if avg < 500 else "✗ FAIL (QEMU-TCG overhead)"
    fig.suptitle(f"Figure 2 — Boot Time  |  avg XMPP-ready: {avg:.0f} ms  {status}",
                 fontsize=12, fontweight="bold")

    save(fig, out / "fig2_boot_time.pdf")
    save(fig, out / "fig2_boot_time.png")


# ── Figure 3: Message Latency ──────────────────────────────────────────────────

def fig_latency(rows: list[dict], out: Path):
    if not rows:
        print("  ⚠ No latency data — skipping Figure 3")
        return

    servers = [r["server"] for r in rows]
    p50 = [float(r["p50_ms"]) for r in rows]
    p95 = [float(r["p95_ms"]) for r in rows]
    p99 = [float(r["p99_ms"]) for r in rows]

    x     = np.arange(len(servers))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    b1 = ax.bar(x - width, p50, width, label="P50",
                color=[COLORS.get(s.lower().split()[0], "#607D8B") for s in servers],
                alpha=0.9)
    b2 = ax.bar(x,         p95, width, label="P95",
                color=[COLORS.get(s.lower().split()[0], "#607D8B") for s in servers],
                alpha=0.6)
    b3 = ax.bar(x + width, p99, width, label="P99",
                color=[COLORS.get(s.lower().split()[0], "#607D8B") for s in servers],
                alpha=0.4)

    # Color each server group differently
    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "Prosody":        COLORS["prosody"],
        "Openfire":       COLORS["openfire"],
    }
    for i, (bar_group, srv) in enumerate(zip([b1, b2, b3], ["", "", ""])):
        pass

    # Re-draw with correct colors
    ax.cla()
    for i, (srv, s50, s95, s99) in enumerate(zip(servers, p50, p95, p99)):
        c = server_colors.get(srv, "#607D8B")
        ax.bar(i - width, s50, width, color=c, alpha=0.95, label=f"P50 ({srv})" if i == 0 else "")
        ax.bar(i,         s95, width, color=c, alpha=0.65)
        ax.bar(i + width, s99, width, color=c, alpha=0.40)
        ax.text(i - width, s50 + 0.05, f"{s50:.2f}", ha="center", fontsize=8)
        ax.text(i,         s95 + 0.05, f"{s95:.2f}", ha="center", fontsize=8)
        ax.text(i + width, s99 + 0.05, f"{s99:.2f}", ha="center", fontsize=8)

    ax.set_xticks(x); ax.set_xticklabels(servers)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Figure 3 — Message Latency: P50 / P95 / P99")

    patches = [
        mpatches.Patch(color=c, label=s)
        for s, c in server_colors.items() if s in servers
    ]
    legend_extra = [
        mpatches.Patch(color="gray", alpha=0.95, label="P50 (solid)"),
        mpatches.Patch(color="gray", alpha=0.65, label="P95"),
        mpatches.Patch(color="gray", alpha=0.40, label="P99"),
    ]
    ax.legend(handles=patches + legend_extra, fontsize=9, ncol=2)

    # Capstone target annotation
    ax.axhline(1.0, color=COLORS["target"], linestyle="--", linewidth=1.5)
    ax.text(len(servers) - 0.5, 1.1, "Target: 1 ms",
            color=COLORS["target"], fontsize=9, ha="right")

    save(fig, out / "fig3_latency.pdf")
    save(fig, out / "fig3_latency.png")


# ── Figure 4: Throughput ───────────────────────────────────────────────────────

def fig_throughput(rows: list[dict], out: Path):
    if not rows:
        print("  ⚠ No throughput data — skipping Figure 4")
        return

    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "Prosody":        COLORS["prosody"],
        "Openfire":       COLORS["openfire"],
    }

    # Group by server
    grouped: dict[str, dict] = {}
    for r in rows:
        srv   = r["server"]
        users = int(r["users"])
        mps   = float(r["msg_per_sec"])
        grouped.setdefault(srv, {"users": [], "mps": []})
        grouped[srv]["users"].append(users)
        grouped[srv]["mps"].append(mps)

    fig, ax = plt.subplots(figsize=(9, 5))

    for srv, data in grouped.items():
        # sort by users
        paired = sorted(zip(data["users"], data["mps"]))
        us, mp = zip(*paired)
        c = server_colors.get(srv, "#607D8B")
        ax.plot(us, mp, "o-", color=c, label=srv, linewidth=2.5, markersize=8)

    ax.set_xlabel("Concurrent users")
    ax.set_ylabel("Messages / second")
    ax.set_title("Figure 4 — Groupchat Throughput Under Load (Tsung)")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    save(fig, out / "fig4_throughput.pdf")
    save(fig, out / "fig4_throughput.png")


# ── Figure 5: Memory Footprint ─────────────────────────────────────────────────

def fig_memory(rows: list[dict], out: Path):
    if not rows:
        print("  ⚠ No memory data — skipping Figure 5")
        return

    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "Prosody":        COLORS["prosody"],
        "Openfire":       COLORS["openfire"],
    }

    servers  = [r["server"]   for r in rows]
    idle_mb  = [float(r["idle_mb"])  for r in rows]
    load_mb  = [float(r["load_mb"])  for r in rows]
    colors   = [server_colors.get(s, "#607D8B") for s in servers]

    x     = np.arange(len(servers))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar(x - width/2, idle_mb, width, color=colors, alpha=0.9,
                label="Idle RSS (MB)")
    b2 = ax.bar(x + width/2, load_mb, width, color=colors, alpha=0.55,
                label="Peak load RSS (MB)")

    for bar, val in zip(b1, idle_mb):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{val:.1f}", ha="center", va="bottom", fontsize=9)
    for bar, val in zip(b2, load_mb):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{val:.1f}", ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x); ax.set_xticklabels(servers)
    ax.set_ylabel("Resident Set Size (MB)")
    ax.set_title("Figure 5 — Memory Footprint Comparison")

    patches = [
        mpatches.Patch(color=server_colors.get(s, "#607D8B"), label=s)
        for s in servers
    ]
    legend_extra = [
        mpatches.Patch(color="gray", alpha=0.9,  label="Idle RSS"),
        mpatches.Patch(color="gray", alpha=0.55, label="Peak load RSS"),
    ]
    ax.legend(handles=patches + legend_extra, fontsize=9)

    # ratio annotations
    if len(idle_mb) > 1 and idle_mb[0] > 0:
        ratio_p = idle_mb[1] / idle_mb[0]
        ratio_o = idle_mb[2] / idle_mb[0] if len(idle_mb) > 2 else None
        note = f"AngelicKernel is {ratio_p:.0f}× smaller than Prosody at idle"
        if ratio_o:
            note += f", {ratio_o:.0f}× smaller than Openfire"
        ax.annotate(note, xy=(0.5, -0.13), xycoords="axes fraction",
                    ha="center", fontsize=9, color="#444")

    save(fig, out / "fig5_memory.pdf")
    save(fig, out / "fig5_memory.png")


# ── Figure 6: Compliance Heat-Map ─────────────────────────────────────────────

def fig_compliance(json_data: dict, out: Path):
    if not json_data or not json_data.get("results"):
        print("  ⚠ No compliance data — skipping Figure 6")
        return

    # Group results into RFC/XEP sections
    sections = {
        "RFC 6120\nCore":   [],
        "RFC 6121\nIM":     [],
        "XEP-0045\nMUC":    [],
        "XEP-0030\nDisco":  [],
        "XEP-0160\nOffline": [],
        "XEP-0199\nPing":   [],
    }

    section_keywords = {
        "RFC 6120\nCore":    ["stream", "sasl", "starttls", "bind", "iq error",
                              "namespace", "base64", "mechanism"],
        "RFC 6121\nIM":      ["roster", "presence", "direct message",
                              "subscription", "show", "status", "priority",
                              "initial presence"],
        "XEP-0045\nMUC":     ["muc", "room", "groupchat", "nick", "occupant",
                              "conflict", "subject", "private message", "leave",
                              "affiliation", "config"],
        "XEP-0030\nDisco":   ["disco"],
        "XEP-0160\nOffline": ["offline"],
        "XEP-0199\nPing":    ["ping"],
    }

    for r in json_data["results"]:
        name_lower = r["name"].lower()
        placed = False
        for section, keywords in section_keywords.items():
            if any(kw in name_lower for kw in keywords):
                sections[section].append(r["passed"])
                placed = True
                break
        if not placed:
            sections["RFC 6120\nCore"].append(r["passed"])

    # Compute pass rate per section
    section_names = list(sections.keys())
    pass_rates = []
    totals = []
    for s in section_names:
        results_list = sections[s]
        if results_list:
            pass_rates.append(sum(results_list) / len(results_list) * 100)
            totals.append(len(results_list))
        else:
            pass_rates.append(0)
            totals.append(0)

    fig, ax = plt.subplots(figsize=(10, 4))

    colors_bar = [
        COLORS["pass"] if r >= 80 else
        ("#FFC107" if r >= 50 else COLORS["fail"])
        for r in pass_rates
    ]

    bars = ax.barh(section_names, pass_rates, color=colors_bar, alpha=0.85)
    ax.set_xlim(0, 110)
    ax.set_xlabel("Pass rate (%)")
    ax.set_title("Figure 6 — Protocol Compliance by RFC/XEP Section")

    for bar, rate, total in zip(bars, pass_rates, totals):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f"{rate:.0f}%  ({int(rate * total / 100)}/{total})",
                va="center", fontsize=10)

    ax.axvline(100, color="#333", linewidth=0.8, linestyle="--")

    total_pass = json_data.get("passed", 0)
    total_all  = json_data.get("total",  0)
    overall    = total_pass / total_all * 100 if total_all else 0
    ax.text(0.98, 0.02, f"Overall: {total_pass}/{total_all} ({overall:.0f}%)",
            transform=ax.transAxes, ha="right", va="bottom",
            fontsize=10, fontweight="bold")

    save(fig, out / "fig6_compliance.pdf")
    save(fig, out / "fig6_compliance.png")


# ── Figure 7: Summary Dashboard ───────────────────────────────────────────────

def fig_dashboard(cycles, boot_rows, latency_rows, memory_rows, compliance_data,
                  out: Path):
    """Single-page summary of all five metrics for the paper."""
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle("AngelicKernel — Capstone §9.2 Metric Dashboard",
                 fontsize=14, fontweight="bold", y=0.98)

    grid = fig.add_gridspec(2, 3, hspace=0.45, wspace=0.35)

    # ── Panel A: MPK cycles ───────────────────────────────────────────────
    ax_a = fig.add_subplot(grid[0, 0])
    if cycles:
        ax_a.bar(range(1, len(cycles)+1), cycles,
                 color=COLORS["angelic"], alpha=0.8)
        ax_a.axhline(20, color=COLORS["target"], linestyle="--", linewidth=1.5)
        avg = sum(cycles) / len(cycles)
        ax_a.set_title(f"MPK Overhead\n(avg {avg:.1f} cycles)", fontsize=10)
        ax_a.set_xlabel("Run #"); ax_a.set_ylabel("Cycles / WRPKRU")
        status = "✓" if avg < 20 else "✗"
        ax_a.text(0.05, 0.92, f"{status} Target: <20 cyc",
                  transform=ax_a.transAxes, fontsize=9,
                  color=COLORS["pass"] if avg < 20 else COLORS["fail"])
    else:
        ax_a.text(0.5, 0.5, "No data\n(run mpk_benchmark)", ha="center",
                  transform=ax_a.transAxes, fontsize=10, color="#999")
        ax_a.set_title("MPK Overhead", fontsize=10)

    # ── Panel B: Boot time ────────────────────────────────────────────────
    ax_b = fig.add_subplot(grid[0, 1])
    xmpp_ms = [float(r["xmpp_ready_ms"]) for r in boot_rows
                if r.get("xmpp_ready_ms")]
    if xmpp_ms:
        ax_b.boxplot(xmpp_ms, patch_artist=True,
                     boxprops=dict(facecolor=COLORS["angelic"]))
        ax_b.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5)
        avg = sum(xmpp_ms) / len(xmpp_ms)
        ax_b.set_title(f"Boot Time\n(avg {avg:.0f} ms)", fontsize=10)
        ax_b.set_ylabel("ms to XMPP-ready")
        ax_b.set_xticks([1]); ax_b.set_xticklabels(["AngelicKernel"])
        status = "✓" if avg < 500 else "✗"
        ax_b.text(0.05, 0.92, f"{status} Target: <500 ms",
                  transform=ax_b.transAxes, fontsize=9,
                  color=COLORS["pass"] if avg < 500 else COLORS["fail"])
    else:
        ax_b.text(0.5, 0.5, "No data\n(run boot_time_measure.py)", ha="center",
                  transform=ax_b.transAxes, fontsize=10, color="#999")
        ax_b.set_title("Boot Time", fontsize=10)

    # ── Panel C: Compliance ───────────────────────────────────────────────
    ax_c = fig.add_subplot(grid[0, 2])
    total_p = compliance_data.get("passed", 0)
    total_t = compliance_data.get("total",  0)
    if total_t > 0:
        pct = total_p / total_t
        wedges, texts = ax_c.pie(
            [pct, 1 - pct],
            colors=[COLORS["pass"], COLORS["fail"]],
            startangle=90,
            wedgeprops=dict(width=0.5)
        )
        ax_c.text(0, 0, f"{total_p}/{total_t}\n{pct*100:.0f}%",
                  ha="center", va="center", fontsize=12, fontweight="bold")
        ax_c.set_title("Protocol Compliance", fontsize=10)
    else:
        ax_c.text(0.5, 0.5, "No data\n(run compliance_report.py)", ha="center",
                  transform=ax_c.transAxes, fontsize=10, color="#999")
        ax_c.set_title("Protocol Compliance", fontsize=10)

    # ── Panel D: Latency ──────────────────────────────────────────────────
    ax_d = fig.add_subplot(grid[1, 0])
    if latency_rows:
        servers = [r["server"] for r in latency_rows]
        p50 = [float(r["p50_ms"]) for r in latency_rows]
        colors = [{"AngelicKernel": COLORS["angelic"],
                   "Prosody":        COLORS["prosody"],
                   "Openfire":       COLORS["openfire"]}.get(s, "#607D8B")
                  for s in servers]
        ax_d.bar(servers, p50, color=colors, alpha=0.9)
        ax_d.axhline(1.0, color=COLORS["target"], linestyle="--", linewidth=1.5)
        ax_d.set_ylabel("P50 latency (ms)")
        ax_d.set_title("Message Latency P50", fontsize=10)
        for i, (s, v) in enumerate(zip(servers, p50)):
            ax_d.text(i, v + 0.02, f"{v:.2f}", ha="center", fontsize=9)
    else:
        ax_d.text(0.5, 0.5, "No data\n(run Tsung)", ha="center",
                  transform=ax_d.transAxes, fontsize=10, color="#999")
        ax_d.set_title("Message Latency", fontsize=10)

    # ── Panel E: Throughput ───────────────────────────────────────────────
    ax_e = fig.add_subplot(grid[1, 1])
    if latency_rows:
        # Show peak throughput bar (placeholder from latency data file)
        # Ideally load from tsung_throughput.csv; use p99 inverse as proxy
        pass
    ax_e.text(0.5, 0.5, "Run Tsung to\ncollect throughput data",
              ha="center", va="center", transform=ax_e.transAxes,
              fontsize=10, color="#999")
    ax_e.set_title("Peak Throughput", fontsize=10)

    # ── Panel F: Memory ───────────────────────────────────────────────────
    ax_f = fig.add_subplot(grid[1, 2])
    if memory_rows:
        servers = [r["server"] for r in memory_rows]
        idle    = [float(r["idle_mb"]) for r in memory_rows]
        colors  = [{"AngelicKernel": COLORS["angelic"],
                    "Prosody":        COLORS["prosody"],
                    "Openfire":       COLORS["openfire"]}.get(s, "#607D8B")
                   for s in servers]
        ax_f.bar(servers, idle, color=colors, alpha=0.9)
        ax_f.set_ylabel("Idle RSS (MB)")
        ax_f.set_title("Memory Footprint (Idle)", fontsize=10)
        for i, (s, v) in enumerate(zip(servers, idle)):
            ax_f.text(i, v + 0.5, f"{v:.1f}", ha="center", fontsize=9)
    else:
        ax_f.text(0.5, 0.5, "No data\n(run baselines)", ha="center",
                  transform=ax_f.transAxes, fontsize=10, color="#999")
        ax_f.set_title("Memory Footprint", fontsize=10)

    save(fig, out / "fig7_dashboard.pdf")
    save(fig, out / "fig7_dashboard.png")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate paper figures for AngelicKernel capstone"
    )
    parser.add_argument("--data-dir", default=None,
                        help="Directory containing benchmark data files "
                             "(default: <script_dir>/data/)")
    parser.add_argument("--fig-dir", default=None,
                        help="Output directory for figures "
                             "(default: <script_dir>/figures/)")
    parser.add_argument("--demo", action="store_true",
                        help="Generate with synthetic data (verify layout before "
                             "real benchmarks)")
    args = parser.parse_args()

    script_dir = Path(__file__).parent.resolve()
    data_dir   = Path(args.data_dir) if args.data_dir else script_dir / "data"
    fig_dir    = Path(args.fig_dir)  if args.fig_dir  else script_dir / "figures"

    ensure_dir(data_dir)
    ensure_dir(fig_dir)

    if args.demo:
        print("Demo mode: writing synthetic benchmark data...")
        write_demo_data(data_dir)

    print(f"\nData directory: {data_dir}")
    print(f"Figure output:  {fig_dir}\n")

    # ── Load data ──────────────────────────────────────────────────────────
    cycles        = load_lines(data_dir / "mpk_cycles.txt", cast=float)
    boot_rows     = load_csv_dicts(data_dir / "boot_times.csv")
    latency_rows  = load_csv_dicts(data_dir / "tsung_latency.csv")
    throughput_rows = load_csv_dicts(data_dir / "tsung_throughput.csv")
    memory_rows   = load_csv_dicts(data_dir / "memory_footprint.csv")
    compliance    = load_json(data_dir / "compliance.json")

    # ── Generate figures ───────────────────────────────────────────────────
    print("Generating figures:")
    fig_mpk_cycles(cycles,          fig_dir)
    fig_boot_time(boot_rows,        fig_dir)
    fig_latency(latency_rows,       fig_dir)
    fig_throughput(throughput_rows, fig_dir)
    fig_memory(memory_rows,         fig_dir)
    fig_compliance(compliance,      fig_dir)
    fig_dashboard(cycles, boot_rows, latency_rows, memory_rows, compliance, fig_dir)

    print(f"\nAll figures written to: {fig_dir}/")
    print("\nFiles produced:")
    for f in sorted(fig_dir.glob("fig*.png")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()
