#!/usr/bin/env python3

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
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D

COLORS = {
    "angelic": "#2196F3",
    "prosody": "#4CAF50",
    "openfire": "#FF5722",
    "target": "#F44336",
    "pass": "#4CAF50",
    "fail": "#F44336",
    "skip": "#9E9E9E",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
    "savefig.bbox": "tight",
    "savefig.dpi": 200,
})


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def safe_float(val, fallback=float("nan")):
    try:
        return float(val)
    except (ValueError, TypeError):
        return fallback


def load_lines(path: Path, cast=int) -> list:
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

    print(f"✓ {path}")


DEMO_MPK_CYCLES = [
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
prosody,2.3,8.1,19.4
openfire,8.7,34.2,87.6
"""

DEMO_THROUGHPUT_CSV = """\
server,users,msg_per_sec
AngelicKernel,10,1840
AngelicKernel,30,4720
AngelicKernel,60,7100
AngelicKernel,100,8340
prosody,10,920
prosody,30,2180
prosody,60,3640
prosody,100,4120
openfire,10,410
openfire,30,910
openfire,60,1430
openfire,100,1620
"""

DEMO_MEMORY_CSV = """\
server,idle_mb,load_mb
AngelicKernel,1.2,2.4
prosody,31.4,48.7
openfire,218.3,287.6
"""

DEMO_COMPLIANCE_JSON = {
    "passed": 42, "failed": 7, "total": 49,
    "results": [
        {"name": "stream:stream present in response", "passed": True},
        {"name": "stream:features present", "passed": True},
        {"name": "from='angelic.local' set", "passed": True},
        {"name": "version='1.0' set", "passed": True},
        {"name": "id= attribute present", "passed": True},
        {"name": "STARTTLS offered in features", "passed": True},
        {"name": "STARTTLS marked required", "passed": True},
        {"name": "stream error sent for wrong 'to'", "passed": True},
        {"name": "<host-unknown/> condition present", "passed": True},
        {"name": "</stream:stream> sent before close", "passed": True},
        {"name": "server echoes </stream:stream> on close", "passed": True},
        {"name": "bad credentials → <failure>", "passed": True},
        {"name": "good credentials → <success/>", "passed": True},
        {"name": "invalid mechanism → <invalid-mechanism/>", "passed": True},
        {"name": "bad Base64 → <incorrect-encoding/>", "passed": True},
        {"name": "post-auth features contain <bind>", "passed": True},
        {"name": "bind result contains full jid", "passed": True},
        {"name": "unknown iq get → iq error response", "passed": True},
        {"name": "roster get → iq result", "passed": True},
        {"name": "roster result contains <query xmlns='jabber:iq:roster'>", "passed": True},
        {"name": "roster get with ver=", "passed": True},
        {"name": "roster set → iq result", "passed": True},
        {"name": "roster get after set returns stored item", "passed": True},
        {"name": "initial presence elicits at least one <presence> stanza", "passed": True},
        {"name": "<show>away</show> forwarded verbatim", "passed": True},
        {"name": "<status>In a meeting</status> forwarded verbatim", "passed": True},
        {"name": "<priority>5</priority> forwarded verbatim", "passed": True},
        {"name": "direct message delivered to recipient", "passed": True},
        {"name": "offline message delivered", "passed": True},
        {"name": "delivery includes xep-0203 <delay/>", "passed": True},
        {"name": "subscribe forwarded to recipient", "passed": True},
        {"name": "subscribed forwarded back to requester", "passed": True},
        {"name": "after subscription, roster shows subscription='to'", "passed": True},
        {"name": "join room → self-presence received", "passed": True},
        {"name": "self-presence contains status code 110", "passed": True},
        {"name": "new room creator gets status code 201", "passed": True},
        {"name": "creator gets affiliation='owner'", "passed": True},
        {"name": "room subject sent after join", "passed": True},
        {"name": "config submit → iq result", "passed": True},
        {"name": "leaving room → unavailable presence received", "passed": True},
        {"name": "nick conflict → <presence type='error'>", "passed": True},
        {"name": "error contains <conflict/>", "passed": True},
        {"name": "groupchat message reflected to sender", "passed": True},
        {"name": "groupchat message delivered to other occupant", "passed": True},
        {"name": "private message delivered to addressed occupant", "passed": True},
        {"name": "private message not delivered to other occupants", "passed": True},
        {"name": "ping → iq result", "passed": True},
        {"name": "disco#info → iq result", "passed": True},
        {"name": "disco#items on server returns muc service", "passed": True},
    ]
}


def write_demo_data(data_dir: Path):
    (data_dir / "mpk_cycles.txt").write_text("\n".join(str(v) for v in DEMO_MPK_CYCLES) + "\n")
    (data_dir / "boot_times.csv").write_text(DEMO_BOOT_CSV)
    (data_dir / "tsung_latency.csv").write_text(DEMO_LATENCY_CSV)
    (data_dir / "tsung_throughput.csv").write_text(DEMO_THROUGHPUT_CSV)
    (data_dir / "memory_footprint.csv").write_text(DEMO_MEMORY_CSV)
    (data_dir / "compliance.json").write_text(json.dumps(DEMO_COMPLIANCE_JSON, indent=2))

    print(f"demo data written to {data_dir}/")


def fig_mpk_cycles(cycles: list[int], out: Path):
    if not cycles:
        print("⚠ no mpk cycle data, skipping figure 1")

        return

    fig, ax = plt.subplots(figsize=(8, 4))

    x = list(range(1, len(cycles) + 1))
    bars = ax.bar(x, cycles, color=COLORS["angelic"], alpha=0.8, label="measured cycles / wrpkru")

    target = 20
    ax.axhline(target, color=COLORS["target"], linewidth=2, linestyle="--", label=f"target: {target} cycles")

    avg = sum(cycles) / len(cycles)
    ax.axhline(avg, color="#9C27B0", linewidth=1.5, linestyle=":", label=f"average: {avg:.1f} cycles")

    ax.set_xlabel("measurement run")
    ax.set_ylabel("cpu cycles per wrpkru")

    ax.set_title("figure 1, mpk gate overhead: wrpkru cycle count")

    ax.set_xticks(x)
    ax.set_ylim(0, max(max(cycles) * 1.3, target * 1.5))

    ax.legend(loc="upper right", fontsize=9)

    status = "✓ pass" if avg < target else "✗ fail"
    color = COLORS["pass"] if avg < target else COLORS["fail"]
    ax.text(0.02, 0.95, f"{status} avg={avg:.1f} cycles", transform=ax.transAxes, color=color, fontweight="bold", fontsize=10, va="top")

    ax.annotate("intel sdm: wrpkru = 4–8 cycles\n"
                "(qemu-tcg inflates counts)",
                xy=(0.5, -0.18), xycoords="axes fraction",
                ha="center", fontsize=8, color="#666")

    save(fig, out / "fig1_mpk_cycles.pdf")
    save(fig, out / "fig1_mpk_cycles.png")


def fig_boot_time(rows: list[dict], out: Path):
    if not rows:
        print("⚠ no boot time data, skipping figure 2")

        return

    tcp = [safe_float(r["tcp_ready_ms"]) for r in rows if r.get("tcp_ready_ms")]
    xmpp = [safe_float(r["xmpp_ready_ms"]) for r in rows if r.get("xmpp_ready_ms")]

    tcp = [v for v in tcp if not np.isnan(v)]
    xmpp = [v for v in xmpp if not np.isnan(v)]

    if not xmpp:
        print("⚠ no valid boot time rows, skipping figure 2")

        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    runs = list(range(1, len(xmpp) + 1))

    ax1.plot(runs, tcp[:len(runs)], "o-", color=COLORS["angelic"], label="tcp ready", linewidth=2, markersize=6)
    ax1.plot(runs, xmpp, "s-", color="#E91E63", label="xmpp ready", linewidth=2, markersize=6)

    ax1.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5, label="target: 500 ms")

    ax1.set_xlabel("run #")
    ax1.set_ylabel("time from t₀ (ms)")
    ax1.set_title("boot time per run")

    ax1.legend(fontsize=9)

    categories = ["tcp ready", "xmpp ready"]
    data = [tcp[:len(runs)], xmpp]
    bp = ax2.boxplot(data, tick_labels=categories, patch_artist=True, medianprops=dict(color="white", linewidth=2))
    bp["boxes"][0].set_facecolor(COLORS["angelic"])
    bp["boxes"][1].set_facecolor("#E91E63")

    ax2.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5, label="target: 500 ms")
    ax2.set_ylabel("time from t₀ (ms)")
    ax2.set_title("boot time distribution")
    ax2.legend(fontsize=9)

    avg = sum(xmpp) / len(xmpp)
    status = "✓ pass" if avg < 500 else "✗ fail (qemu-tcg overhead)"
    fig.suptitle(f"figure 2 — boot Time | avg xmpp-ready: {avg:.0f} ms {status}", fontsize=12, fontweight="bold")

    save(fig, out / "fig2_boot_time.pdf")
    save(fig, out / "fig2_boot_time.png")


def fig_latency(rows: list[dict], out: Path):
    if not rows:
        print("⚠ no latency data, skipping figure 3")

        return

    servers = [r["server"] for r in rows]
    p50 = [safe_float(r["p50_ms"]) for r in rows]
    p95 = [safe_float(r["p95_ms"]) for r in rows]
    p99 = [safe_float(r["p99_ms"]) for r in rows]

    x = np.arange(len(servers))
    width = 0.25

    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "prosody": COLORS["prosody"],
        "openfire": COLORS["openfire"],
    }

    fig, ax = plt.subplots(figsize=(9, 5))

    for i, (srv, s50, s95, s99) in enumerate(zip(servers, p50, p95, p99)):
        c = server_colors.get(srv, "#607D8B")
        ax.bar(i - width, s50, width, color=c, alpha=0.95)
        ax.bar(i, s95, width, color=c, alpha=0.65)
        ax.bar(i + width, s99, width, color=c, alpha=0.40)

        if not np.isnan(s50):
            ax.text(i - width, s50 + 0.05, f"{s50:.2f}", ha="center", fontsize=8)
        if not np.isnan(s95):
            ax.text(i, s95 + 0.05, f"{s95:.2f}", ha="center", fontsize=8)
        if not np.isnan(s99):
            ax.text(i + width, s99 + 0.05, f"{s99:.2f}", ha="center", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(servers)
    ax.set_ylabel("latency (ms)")
    ax.set_title("figure 3 — message latency: p50 / p95 / p99")

    patches = [
        mpatches.Patch(color=c, label=s)
        for s, c in server_colors.items() if s in servers
    ]
    legend_extra = [
        mpatches.Patch(color="gray", alpha=0.95, label="p50 (solid)"),
        mpatches.Patch(color="gray", alpha=0.65, label="p95"),
        mpatches.Patch(color="gray", alpha=0.40, label="p99"),
    ]
    ax.legend(handles=patches + legend_extra, fontsize=9, ncol=2)

    ax.axhline(1.0, color=COLORS["target"], linestyle="--", linewidth=1.5)

    ax.text(len(servers) - 0.5, 1.1, "Target: 1 ms", color=COLORS["target"], fontsize=9, ha="right")

    save(fig, out / "fig3_latency.pdf")
    save(fig, out / "fig3_latency.png")


def fig_throughput(rows: list[dict], out: Path):
    if not rows:
        print("⚠ no throughput data, skipping figure 4")

        return

    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "prosody": COLORS["prosody"],
        "openfire": COLORS["openfire"],
    }

    grouped: dict[str, dict] = {}

    for r in rows:
        srv = r["server"]
        users = safe_float(r["users"])
        mps = safe_float(r["msg_per_sec"])

        if np.isnan(users) or np.isnan(mps):
            continue

        grouped.setdefault(srv, {"users": [], "mps": []})
        grouped[srv]["users"].append(int(users))
        grouped[srv]["mps"].append(mps)

    fig, ax = plt.subplots(figsize=(9, 5))

    for srv, data in grouped.items():
        paired = sorted(zip(data["users"], data["mps"]))
        us, mp = zip(*paired)
        c = server_colors.get(srv, "#607D8B")

        ax.plot(us, mp, "o-", color=c, label=srv, linewidth=2.5, markersize=8)

    ax.set_xlabel("concurrent users")
    ax.set_ylabel("messages / second")
    ax.set_title("figure 4 — groupchat throughput under load (tsung)")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    save(fig, out / "fig4_throughput.pdf")
    save(fig, out / "fig4_throughput.png")


def fig_memory(rows: list[dict], out: Path):
    if not rows:
        print("⚠ no memory data, skipping figure 5")

        return

    server_colors = {
        "AngelicKernel": COLORS["angelic"],
        "prosody": COLORS["prosody"],
        "openfire": COLORS["openfire"],
    }

    servers = [r["server"] for r in rows]
    idle_mb = [safe_float(r["idle_mb"]) for r in rows]
    load_mb = [safe_float(r["load_mb"]) for r in rows]
    colors = [server_colors.get(s, "#607D8B") for s in servers]

    x = np.arange(len(servers))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar(x - width/2, idle_mb, width, color=colors, alpha=0.9, label="idle rss (mb)")
    b2 = ax.bar(x + width/2, load_mb, width, color=colors, alpha=0.55, label="peak load rss (mb)")

    for bar, val in zip(b1, idle_mb):
        if not np.isnan(val):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{val:.1f}", ha="center", va="bottom", fontsize=9)

    for bar, val in zip(b2, load_mb):
        if not np.isnan(val):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{val:.1f}", ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(servers)
    ax.set_ylabel("resident set size (mb)")
    ax.set_title("figure 5, memory footprint comparison")

    patches = [
        mpatches.Patch(color=server_colors.get(s, "#607D8B"), label=s)
        for s in servers
    ]
    legend_extra = [
        mpatches.Patch(color="gray", alpha=0.9, label="idle rss"),
        mpatches.Patch(color="gray", alpha=0.55, label="peak load rss"),
    ]
    ax.legend(handles=patches + legend_extra, fontsize=9)

    valid_idle = [v for v in idle_mb if not np.isnan(v)]
    if len(valid_idle) > 1 and valid_idle[0] > 0:
        ratio_p = valid_idle[1] / valid_idle[0]
        ratio_o = valid_idle[2] / valid_idle[0] if len(valid_idle) > 2 else None
        note = f"AngelicKernel is {ratio_p:.0f}× smaller than prosody at idle"

        if ratio_o:
            note += f", {ratio_o:.0f}× smaller than openfire"

        ax.annotate(note, xy=(0.5, -0.13), xycoords="axes fraction", ha="center", fontsize=9, color="#444")

    save(fig, out / "fig5_memory.pdf")
    save(fig, out / "fig5_memory.png")


def fig_compliance(json_data: dict, out: Path):
    if not json_data or not json_data.get("results"):
        print("⚠ no compliance data, skipping figure 6")

        return

    sections = {
        "rfc 6120\ncore": [],
        "rfc 6121\nim": [],
        "xep-0045\nmuc": [],
        "xep-0030\ndisco": [],
        "xep-0160\noffline": [],
        "xep-0199\nping": [],
    }

    section_keywords = {
        "rfc 6120\ncore": ["stream", "sasl", "starttls", "bind", "iq error", "namespace", "base64", "mechanism"],
        "rfc 6121\nim": ["roster", "presence", "direct message", "subscription", "show", "status", "priority", "initial presence"],
        "xep-0045\nmuc": ["muc", "room", "groupchat", "nick", "occupant", "conflict", "subject", "private message", "leave", "affiliation", "config"],
        "xep-0030\ndisco": ["disco"],
        "xep-0160\noffline": ["offline"],
        "xep-0199\nping": ["ping"],
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
            sections["rfc 6120\ncore"].append(r["passed"])

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
    ax.set_xlabel("pass rate (%)")
    ax.set_title("figure 6, protocol compliance by rfc/xep section")

    for bar, rate, total in zip(bars, pass_rates, totals):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f"{rate:.0f}% ({int(rate * total / 100)}/{total})",
                va="center", fontsize=10)

    ax.axvline(100, color="#333", linewidth=0.8, linestyle="--")

    total_pass = json_data.get("passed", 0)
    total_all = json_data.get("total", 0)
    overall = total_pass / total_all * 100 if total_all else 0

    ax.text(0.98, 0.02, f"overall: {total_pass}/{total_all} ({overall:.0f}%)",
            transform=ax.transAxes, ha="right", va="bottom", fontsize=10, fontweight="bold")

    save(fig, out / "fig6_compliance.pdf")
    save(fig, out / "fig6_compliance.png")


def fig_dashboard(cycles, boot_rows, latency_rows, memory_rows, compliance_data, out: Path):
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle("AngelicKernel metric dashboard", fontsize=14, fontweight="bold", y=0.98)

    grid = fig.add_gridspec(2, 3, hspace=0.45, wspace=0.35)

    ax_a = fig.add_subplot(grid[0, 0])

    if cycles:
        ax_a.bar(range(1, len(cycles)+1), cycles, color=COLORS["angelic"], alpha=0.8)

        ax_a.axhline(20, color=COLORS["target"], linestyle="--", linewidth=1.5)

        avg = sum(cycles) / len(cycles)

        ax_a.set_title(f"mpk overhead\n(avg {avg:.1f} cycles)", fontsize=10)
        ax_a.set_xlabel("run #")
        ax_a.set_ylabel("cycles / wrpkru")

        status = "✓" if avg < 20 else "✗"

        ax_a.text(0.05, 0.92, f"{status} target: <20 cyc", transform=ax_a.transAxes, fontsize=9,
                  color=COLORS["pass"] if avg < 20 else COLORS["fail"])
    else:
        ax_a.text(0.5, 0.5, "no data\n(run mpk_benchmark)", ha="center", transform=ax_a.transAxes, fontsize=10, color="#999")

        ax_a.set_title("mpk overhead", fontsize=10)

    ax_b = fig.add_subplot(grid[0, 1])
    xmpp_ms = [safe_float(r["xmpp_ready_ms"]) for r in boot_rows if r.get("xmpp_ready_ms")]
    xmpp_ms = [v for v in xmpp_ms if not np.isnan(v)]

    if xmpp_ms:
        ax_b.boxplot(xmpp_ms, patch_artist=True, boxprops=dict(facecolor=COLORS["angelic"]))

        ax_b.axhline(500, color=COLORS["target"], linestyle="--", linewidth=1.5)

        avg = sum(xmpp_ms) / len(xmpp_ms)

        ax_b.set_title(f"boot time\n(avg {avg:.0f} ms)", fontsize=10)
        ax_b.set_ylabel("ms to xmpp-ready")
        ax_b.set_xticks([1])
        ax_b.set_xticklabels(["AngelicKernel"])

        status = "✓" if avg < 500 else "✗"

        ax_b.text(0.05, 0.92, f"{status} target: <500 ms", transform=ax_b.transAxes, fontsize=9,
                  color=COLORS["pass"] if avg < 500 else COLORS["fail"])
    else:
        ax_b.text(0.5, 0.5, "no data\n(run boot_time_measure.py)", ha="center", transform=ax_b.transAxes, fontsize=10, color="#999")

        ax_b.set_title("Boot Time", fontsize=10)

    ax_c = fig.add_subplot(grid[0, 2])
    total_p = compliance_data.get("passed", 0)
    total_t = compliance_data.get("total", 0)

    if total_t > 0:
        pct = total_p / total_t

        wedges, texts = ax_c.pie(
            [pct, 1 - pct],
            colors=[COLORS["pass"], COLORS["fail"]],
            startangle=90,
            wedgeprops=dict(width=0.5)
        )

        ax_c.text(0, 0, f"{total_p}/{total_t}\n{pct*100:.0f}%", ha="center", va="center", fontsize=12, fontweight="bold")

        ax_c.set_title("protocol compliance", fontsize=10)
    else:
        ax_c.text(0.5, 0.5, "no data\n(run compliance_report.py)", ha="center", transform=ax_c.transAxes, fontsize=10, color="#999")

        ax_c.set_title("protocol compliance", fontsize=10)

    ax_d = fig.add_subplot(grid[1, 0])

    if latency_rows:
        servers = [r["server"] for r in latency_rows]
        p50 = [safe_float(r["p50_ms"]) for r in latency_rows]
        colors = [{"AngelicKernel": COLORS["angelic"],
                   "prosody": COLORS["prosody"],
                   "openfire": COLORS["openfire"]}.get(s, "#607D8B")
                  for s in servers]

        ax_d.bar(servers, p50, color=colors, alpha=0.9)

        ax_d.axhline(1.0, color=COLORS["target"], linestyle="--", linewidth=1.5)

        ax_d.set_ylabel("p50 latency (ms)")

        ax_d.set_title("message latency p50", fontsize=10)

        for i, (s, v) in enumerate(zip(servers, p50)):
            if not np.isnan(v):
                ax_d.text(i, v + 0.02, f"{v:.2f}", ha="center", fontsize=9)
    else:
        ax_d.text(0.5, 0.5, "no data\n(run tsung)", ha="center", transform=ax_d.transAxes, fontsize=10, color="#999")
        ax_d.set_title("message latency", fontsize=10)

    ax_e = fig.add_subplot(grid[1, 1])
    ax_e.text(0.5, 0.5, "run tsung to\ncollect throughput data", ha="center", va="center",
              transform=ax_e.transAxes, fontsize=10, color="#999")
    ax_e.set_title("peak throughput", fontsize=10)

    ax_f = fig.add_subplot(grid[1, 2])

    if memory_rows:
        servers = [r["server"] for r in memory_rows]
        idle = [safe_float(r["idle_mb"]) for r in memory_rows]
        colors = [{"AngelicKernel": COLORS["angelic"],
                   "prosody": COLORS["prosody"],
                   "openfire": COLORS["openfire"]}.get(s, "#607D8B")
                  for s in servers]

        ax_f.bar(servers, idle, color=colors, alpha=0.9)

        ax_f.set_ylabel("idle rss (mb)")

        ax_f.set_title("memory footprint (idle)", fontsize=10)

        for i, (s, v) in enumerate(zip(servers, idle)):
            if not np.isnan(v):
                ax_f.text(i, v + 0.5, f"{v:.1f}", ha="center", fontsize=9)
    else:
        ax_f.text(0.5, 0.5, "no data\n(run baselines)", ha="center", transform=ax_f.transAxes, fontsize=10, color="#999")

        ax_f.set_title("memory footprint", fontsize=10)

    save(fig, out / "fig7_dashboard.pdf")
    save(fig, out / "fig7_dashboard.png")


def main():
    parser = argparse.ArgumentParser(
        description="generate paper figures for AngelicKernel"
    )
    parser.add_argument("--data-dir", default=None, help="directory containing benchmark data files (default: <script_dir>/data/)")
    parser.add_argument("--fig-dir", default=None, help="output directory for figures (default: <script_dir>/figures/)")
    parser.add_argument("--demo", action="store_true", help="generate with synthetic data")
    args = parser.parse_args()

    script_dir = Path(__file__).parent.resolve()
    data_dir = Path(args.data_dir) if args.data_dir else script_dir / "data"
    fig_dir = Path(args.fig_dir) if args.fig_dir else script_dir / "figures"

    ensure_dir(data_dir)
    ensure_dir(fig_dir)

    if args.demo:
        print("demo mode: writing synthetic benchmark data")

        write_demo_data(data_dir)

    print(f"\ndata directory: {data_dir}")
    print(f"figure output: {fig_dir}\n")

    cycles = load_lines(data_dir / "mpk_cycles.txt", cast=float)
    boot_rows = load_csv_dicts(data_dir / "boot_times.csv")
    latency_rows = load_csv_dicts(data_dir / "tsung_latency.csv")
    throughput_rows = load_csv_dicts(data_dir / "tsung_throughput.csv")
    memory_rows = load_csv_dicts(data_dir / "memory_footprint.csv")
    compliance = load_json(data_dir / "compliance.json")

    print("generating figures:")

    fig_mpk_cycles(cycles, fig_dir)
    fig_boot_time(boot_rows, fig_dir)
    fig_latency(latency_rows, fig_dir)
    fig_throughput(throughput_rows, fig_dir)
    fig_memory(memory_rows, fig_dir)
    fig_compliance(compliance, fig_dir)
    fig_dashboard(cycles, boot_rows, latency_rows, memory_rows, compliance, fig_dir)

    print(f"\nall figures written to: {fig_dir}/")
    print("\nfiles produced:")

    for f in sorted(fig_dir.glob("fig*.png")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()