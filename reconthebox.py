#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reconthebox.py — HackTheBox Initial Reconnaissance Automation
Author  : x0xx0x0x
Version : 2.0
Usage   : python3 reconthebox.py -t <TARGET_IP> [-n <LAB_NAME>]
"""

import argparse
import ftplib
import ipaddress
import json
import os
import random
import re
import select
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════════
#  THEME & CONSOLE
# ═══════════════════════════════════════════════════════════════════════════════

HTB_THEME = Theme(
    {
        "htb.green":   "bold bright_green",
        "htb.red":     "bold bright_red",
        "htb.yellow":  "bold yellow",
        "htb.cyan":    "bold cyan",
        "htb.magenta": "bold magenta",
        "htb.blue":    "bold bright_blue",
        "htb.dim":     "dim white",
        "htb.ghost":   "dim green",
        "htb.win":     "bold white on dark_red",
        "htb.linux":   "bold white on dark_blue",
        "htb.section": "bold bright_cyan",
        "htb.found":   "bold bright_green on dark_green",
        "htb.crit":    "bold bright_red on dark_red",
        "htb.warn":    "bold yellow on dark_orange3",
    }
)

console = Console(theme=HTB_THEME, highlight=False)  # width=None → auto-adapts to terminal

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0"

SECLISTS_BASE = os.path.expanduser("~/seclists")

WORDLISTS: dict[str, list[str]] = {
    "dirs": [
        f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-medium.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-directories.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "vhosts": [
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-110000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    ],
    "files": [
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-files.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    ],
}

REQUIRED_TOOLS = ["nmap"]
OPTIONAL_TOOLS = [
    "ffuf", "dirsearch", "gobuster", "whatweb",
    "searchsploit", "netexec", "smbclient",
    "rpcclient", "ldapsearch", "showmount", "curl",
]

NMAP_TIMEOUT  = 900
FUZZ_TIMEOUT  = 900
FAST_TIMEOUT  = 30
HTTP_TIMEOUT  = 12

WEB_PORTS_SET = {"80", "443", "8080", "8443", "8000", "8888", "8008", "3000", "5000"}
WEB_PORTS_INT = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000}
COMMON_EXT    = "php,html,txt,asp,aspx,jsp,json,xml,bak,old,zip,conf,config"

HTB_DIR    = Path.home() / "htb"
HOSTS_FILE = Path("/etc/hosts")
IMPACKET   = Path.home() / "hacktools" / "impacket" / "examples"

# ═══════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ReconState:
    """Central state object passed through all phases."""
    target:         str
    workdir:        Path
    lab:            str            = "unknown"
    started_at:     datetime       = field(default_factory=datetime.now)
    os_guess:       Optional[str]  = None
    ttl:            Optional[int]  = None
    ports:          list[str]      = field(default_factory=list)
    services:       list[dict]     = field(default_factory=list)
    domains:        list[str]      = field(default_factory=list)
    vhosts:         list[str]      = field(default_factory=list)
    directories:    list[dict]     = field(default_factory=list)
    fingerprints:   list[dict]     = field(default_factory=list)
    exploits:       dict           = field(default_factory=dict)
    quick_wins:     list[dict]     = field(default_factory=list)
    notes:          list[str]      = field(default_factory=list)
    nmap_raw:       str            = ""
    spider_links:   list[str]      = field(default_factory=list)
    # Custom wordlists (set from CLI args)
    wl_dirs:        Optional[str]  = None
    wl_vhosts:      Optional[str]  = None

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER_ART = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ████████╗██╗  ██╗███████╗ ██████╗  ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ ╚══██╔══╝██║  ██║██╔════╝ ██╔══██╗██╔═══██╗╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ███████║█████╗   ██████╔╝██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║   ██╔══██║██╔══╝   ██╔══██╗██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║   ██║  ██║███████╗ ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝"""

TAGLINES = [
    "[ enumerate everything. trust nothing. ]",
    "[ every port tells a story — read them all ]",
    "[ recon is not a phase. recon is a mindset. ]",
    "[ the box won't pwn itself... yet ]",
    "[ map the attack surface. own the narrative. ]",
    "[ flags don't find themselves ]",
    "[ methodical chaos. controlled enumeration. ]",
    "[ find the crack. widen it. own the box. ]",
]


def print_banner(state: Optional["ReconState"] = None) -> None:
    tagline = random.choice(TAGLINES)

    art = Text()
    lines = BANNER_ART.strip("\n").split("\n")
    # Gradient: bright → dim green
    colors = [
        "bright_green", "bright_green", "green",
        "green", "dark_green", "dark_green",
        "bright_cyan", "cyan", "cyan",
        "dark_cyan", "dark_cyan", "dark_cyan",
    ]
    for i, line in enumerate(lines):
        art.append(line + "\n", style=colors[min(i, len(colors) - 1)])

    art.append(f"\n  {tagline}\n", style="dim green")
    art.append(f"                                v{VERSION}  ·  author: x0xx0x0x\n",
               style="dim cyan")

    panels = [Panel(art, border_style="green", padding=(0, 1))]

    if state:
        grid = Table.grid(padding=(0, 3))
        grid.add_column(style="dim green", width=12)
        grid.add_column(style="bold bright_green")
        grid.add_row("TARGET",  state.target)
        grid.add_row("LAB",     state.lab)
        grid.add_row("WORKDIR", str(state.workdir))
        grid.add_row("STARTED", state.started_at.strftime("%Y-%m-%d  %H:%M:%S"))
        panels.append(Panel(grid, title="[dim green]◈ SESSION[/]",
                            border_style="dark_green", padding=(0, 2)))

    top = Table.grid()
    for p in panels:
        top.add_row(p)
    console.print(top)
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[htb.section] {title} [/]", style="dark_green", characters="─"))


def ok(msg: str)   -> None: console.print(f"  [htb.green]✔[/]  {msg}")
def warn(msg: str) -> None: console.print(f"  [htb.yellow]⚠[/]  {msg}")
def err(msg: str)  -> None: console.print(f"  [htb.red]✘[/]  {msg}")
def info(msg: str) -> None: console.print(f"  [htb.dim]·[/]  [dim]{msg}[/]")


def crit(msg: str) -> None:
    console.print(Panel(f"[htb.crit]  ⚡  {msg}  [/]", border_style="red"))


def elapsed(since: datetime) -> str:
    secs = int((datetime.now() - since).total_seconds())
    return f"{secs // 60}m{secs % 60:02d}s"


def resolve_wordlist(category: str) -> Optional[str]:
    for path in WORDLISTS.get(category, []):
        if os.path.isfile(path):
            return path
    warn(f"No wordlist found for '{category}'.")
    return None


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def random_hex(length: int = 8) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))

# ═══════════════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def check_dependencies() -> dict[str, bool]:
    section("DEPENDENCY CHECK")
    table = Table(box=box.SIMPLE_HEAD, show_header=True, border_style="dark_green")
    table.add_column("Tool",   style="bold white",   width=16)
    table.add_column("Status", justify="center",     width=16)
    table.add_column("Path",   style="dim")

    available: dict[str, bool] = {}
    missing_required: list[str] = []

    for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        path = shutil.which(tool)
        required = tool in REQUIRED_TOOLS
        available[tool] = bool(path)
        if path:
            table.add_row(tool, "[htb.green]✔  FOUND[/]", path)
        else:
            status = "[htb.red]✘  MISSING[/]" if required else "[htb.yellow]⚠  OPTIONAL[/]"
            table.add_row(tool, status, "—")
            if required:
                missing_required.append(tool)

    console.print(table)

    # Wordlist status
    wl_table = Table(box=box.SIMPLE_HEAD, show_header=True, border_style="dark_green",
                     title="[dim green]Wordlists[/]")
    wl_table.add_column("Category", style="bold white", width=12)
    wl_table.add_column("Status",   justify="center",   width=14)
    wl_table.add_column("Path",     style="dim")
    for cat in ("dirs", "vhosts", "files"):
        wl = resolve_wordlist(cat)
        if wl:
            wl_table.add_row(cat, "[htb.green]✔  FOUND[/]", wl)
        else:
            wl_table.add_row(cat, "[htb.yellow]⚠  MISSING[/]", "~/seclists/… not found")
    console.print(wl_table)

    if missing_required:
        err(f"FATAL — missing required tools: {', '.join(missing_required)}")
        sys.exit(1)

    return available

# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE SUBPROCESS STREAMING
# ═══════════════════════════════════════════════════════════════════════════════

def _wordlist_size(wordlist_path: str) -> int:
    """Count lines in wordlist for progress tracking."""
    try:
        with open(wordlist_path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def stream_process(
    cmd: list[str],
    label: str,
    timeout: int = FUZZ_TIMEOUT,
    line_filter=None,
    line_handler=None,
    verbose: bool = False,
    cwd: Optional[str] = None,
    wordlist_path: Optional[str] = None,
) -> str:
    """
    Run a subprocess and stream output line-by-line with live progress.
    - Shows the FULL command being executed
    - If wordlist_path provided, shows progress (lines tested / total)
    - line_filter(line) -> bool : print matching lines in real time
    - line_handler(line)        : called for every line (for parsing)
    Returns full captured output.
    """
    all_output: list[str] = []

    # Count wordlist for progress
    total_lines = _wordlist_size(wordlist_path) if wordlist_path else 0
    lines_seen  = 0

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="htb.green"),
        TextColumn("[htb.cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,  # Disappear when finished to keep output clean
        expand=True,
    ) as progress:
        cmd_str = " ".join(cmd)
        # Shorten command string so it fits on one line nicely
        short_cmd = cmd_str if len(cmd_str) < 80 else cmd_str[:77] + "..."
        task_id = progress.add_task(
            f"{label} [dim]→ {short_cmd}[/]",
            total=None,
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd,
            )

            start = time.time()
            for raw_line in proc.stdout:  # type: ignore[union-attr]
                if time.time() - start > timeout:
                    proc.kill()
                    warn(f"Timeout ({timeout}s) — killing process.")
                    break
                line = raw_line.rstrip()
                if line:
                    all_output.append(line)
                    lines_seen += 1
                    if line_handler:
                        line_handler(line)
                    # We no longer print raw lines to keep the terminal clean
                    
                    # Advance progress bar
                    if total_lines > 0:
                        progress.update(task_id, completed=min(lines_seen, total_lines))
                    else:
                        progress.advance(task_id)

            proc.wait()

        except FileNotFoundError:
            err(f"Command not found: {cmd[0]}")
        except Exception as exc:
            err(f"Process error: {exc}")

    return "\n".join(all_output)


def run_cmd(
    cmd: list[str],
    timeout: int = FAST_TIMEOUT,
    cwd: Optional[str] = None,
    input_data: Optional[str] = None,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=input_data,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        warn(f"Timeout ({timeout}s): {' '.join(cmd[:4])}…")
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -1, "", f"NOT_FOUND:{cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)

# ═══════════════════════════════════════════════════════════════════════════════
#  /etc/hosts MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

def hosts_has_entry(domain: str) -> bool:
    try:
        content = HOSTS_FILE.read_text()
        return bool(re.search(rf'\b{re.escape(domain)}\b', content))
    except Exception:
        return False


def add_hosts_entry(ip: str, domain: str) -> None:
    if hosts_has_entry(domain):
        info(f"/etc/hosts — {domain} already present.")
        return
    entry = f"{ip}\t{domain}\n"
    console.print(f"  [htb.warn]⚠[/]  Adding to /etc/hosts: {entry.strip()}  (requires sudo)")
    try:
        # Use shell=True so the pipe is handled by shell, leaving tty free for sudo password prompt
        cmd = f"echo '{entry.strip()}' | sudo tee -a /etc/hosts > /dev/null"
        proc = subprocess.run(cmd, shell=True)
        if proc.returncode == 0:
            ok(f"/etc/hosts ← {entry.strip()}")
        else:
            err(f"Failed to add entry to /etc/hosts (return code: {proc.returncode})")
    except Exception as exc:
        err(f"/etc/hosts update error: {exc}")

# ═══════════════════════════════════════════════════════════════════════════════
#  OS DETECTION BY TTL
# ═══════════════════════════════════════════════════════════════════════════════

def detect_os_by_ttl(state: ReconState) -> None:
    section("OS DETECTION  ·  TTL ANALYSIS")
    rc, out, _ = run_cmd(["ping", "-c", "3", "-W", "1", state.target], timeout=15)
    if rc != 0:
        warn("Host did not respond to ping (ICMP may be filtered).")
        return

    ttls = [int(m) for m in re.findall(r"ttl[=\s](\d+)", out, re.IGNORECASE)]
    if not ttls:
        warn("Could not parse TTL from ping output.")
        return

    ttl = ttls[0]
    state.ttl = ttl

    if ttl <= 64:
        os_guess, badge, style = "Linux / Unix", "🐧 LINUX",   "htb.linux"
    elif ttl <= 128:
        os_guess, badge, style = "Windows",      "🪟 WINDOWS", "htb.win"
    else:
        os_guess, badge, style = "Unknown",      "? UNKNOWN",  "htb.yellow"

    state.os_guess = os_guess

    grid = Table.grid(padding=(0, 4))
    grid.add_column(style="dim green")
    grid.add_column(style="bold bright_green")
    grid.add_row("TTL value",    str(ttl))
    grid.add_row("Packets recv", str(len(ttls)))
    grid.add_row("OS (guess)",   os_guess)

    console.print(Panel(
        grid,
        title=f"[{style}]  {badge}  [/]",
        border_style="green",
        padding=(0, 2),
    ))

# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP — TWO-PHASE LIVE STREAMING SCAN
# ═══════════════════════════════════════════════════════════════════════════════

_PORT_RE = re.compile(
    r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$', re.MULTILINE
)


def _nmap_line_filter(line: str) -> bool:
    """Show lines that contain port discoveries or important nmap info."""
    return bool(re.search(
        r'\d+/(tcp|udp)|open|filtered|Host is up|Discovered|PORT|SERVICE|VERSION',
        line, re.IGNORECASE
    ))


def nmap_fast_scan(state: ReconState, no_udp: bool = False) -> list[str]:
    section("NMAP  ·  PHASE 1 — FAST FULL-PORT SWEEP")
    out_base = str(state.workdir / "nmap_allports")
    cmd = [
        "nmap", "-T4", "-p-", "--min-rate", "5000",
        "--open",
        "-oN", out_base + ".nmap",
        state.target,
    ]

    captured: list[str] = []

    def handle(line: str) -> None:
        captured.append(line)

    output = stream_process(
        cmd,
        label=f"nmap fast sweep on {state.target}",
        timeout=NMAP_TIMEOUT,
        line_filter=_nmap_line_filter,
        line_handler=handle,
    )

    ports = re.findall(r"(\d+)/tcp\s+open", output)
    if ports:
        ok(f"Open TCP ports: [htb.green]{', '.join(ports)}[/]")
    else:
        warn("No open TCP ports found in fast scan.")
    return ports


def nmap_service_scan(state: ReconState, ports: list[str]) -> str:
    if not ports:
        return ""
    port_str = ",".join(ports)
    section(f"NMAP  ·  PHASE 2 — SERVICE & VERSION SCAN  (-p{port_str[:60]}{'…' if len(port_str) > 60 else ''})")
    out_base = str(state.workdir / "nmap_services")
    cmd = [
        "nmap", "-sCV", f"-p{port_str}",
        "-oN", out_base + ".nmap",
        state.target,
    ]

    output = stream_process(
        cmd,
        label=f"nmap service scan on {state.target}",
        timeout=NMAP_TIMEOUT,
        line_filter=_nmap_line_filter,
    )
    return output


def nmap_udp_scan(state: ReconState) -> str:
    section("NMAP  ·  PHASE 3 — UDP TOP-100")
    cmd = [
        "nmap", "-sU", "--top-ports", "100", "--open",
        "-T4", "--min-rate", "2000",
        state.target,
    ]
    output = stream_process(
        cmd,
        label=f"nmap UDP scan on {state.target}",
        timeout=300,
        line_filter=_nmap_line_filter,
    )
    return output


def parse_services(nmap_out: str) -> list[dict]:
    services = []
    for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", nmap_out):
        port, svc, ver = m.groups()
        services.append({"port": port, "service": svc.strip(), "version": ver.strip()})
    return services


def extract_domains_from_nmap(nmap_out: str) -> list[str]:
    domains: set[str] = set()
    patterns = [
        r"commonName=([a-zA-Z0-9\-\.]+\.htb)",
        r"Location:\s*https?://([a-zA-Z0-9\-\.]+\.htb)",
        r"Redirect[^:]*:\s*https?://([a-zA-Z0-9\-\.]+\.htb)",
        r"http-title[^:]*:\s*[^\n]*?([a-zA-Z0-9\-]+\.htb)",
        r"DNS:([a-zA-Z0-9\-\.]+\.htb)",
        r"Subject Alternative Name[^:]*:.*?([a-zA-Z0-9\-\.]+\.htb)",
    ]
    for p in patterns:
        for m in re.finditer(p, nmap_out, re.IGNORECASE):
            domains.add(m.group(1).lower().strip("."))
    return list(domains)


def run_nmap(state: ReconState, no_udp: bool = False) -> None:
    t0 = datetime.now()

    ports = nmap_fast_scan(state, no_udp=no_udp)
    raw   = nmap_service_scan(state, ports)

    state.ports    = ports
    state.nmap_raw = raw
    state.services = parse_services(raw)

    # UDP scan
    if not no_udp:
        udp_out = nmap_udp_scan(state)
        for m in _PORT_RE.finditer(udp_out):
            port, proto, svc, ver = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
            if proto == "udp":
                state.services.append({"port": f"{port}/udp", "service": svc, "version": ver})
    else:
        info("UDP scan skipped (--no-udp).")

    # Extract domains embedded in nmap output
    for d in extract_domains_from_nmap(raw):
        if d not in state.domains:
            state.domains.append(d)

    # Display services table
    if state.services:
        t = Table(
            title=f"[dim green]Services — {elapsed(t0)}[/]",
            box=box.ROUNDED, border_style="dark_green",
        )
        t.add_column("Port",    style="htb.cyan",  width=10)
        t.add_column("Service", style="bold white", width=14)
        t.add_column("Version", style="dim white")
        t.add_column("Notes",   style="htb.yellow")
        for svc in state.services:
            notes = ""
            if any(k in svc["version"].lower() for k in ["cve", "vuln", "exploit"]):
                notes = "⚡ vuln script hit"
            t.add_row(svc["port"], svc["service"], svc["version"], notes)
        console.print(t)
    else:
        warn("No services detected after nmap scan.")

# ═══════════════════════════════════════════════════════════════════════════════
#  WEB SERVICE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_web_ports(state: ReconState) -> list[dict]:
    """Return list of {port_str, port_int, scheme} for all web ports."""
    results = []
    port_strs = set(state.ports)
    seen_ports = set()
    for svc in state.services:
        port_str = svc["port"].split("/")[0]
        try:
            port_int = int(port_str)
        except ValueError:
            continue
        svc_name = svc["service"].lower()
        is_web = (
            port_str in WEB_PORTS_SET
            or port_int in WEB_PORTS_INT
            or "http" in svc_name
            or "ssl" in svc_name
        )
        if is_web and port_int not in seen_ports:
            seen_ports.add(port_int)
            scheme = "https" if ("ssl" in svc_name or port_int in {443, 8443}) else "http"
            results.append({"port": port_int, "port_str": port_str, "scheme": scheme})
    # Also catch plain port strings not in services
    for p_str in port_strs:
        try:
            p_int = int(p_str)
        except ValueError:
            continue
        if p_int in WEB_PORTS_INT and p_int not in seen_ports:
            seen_ports.add(p_int)
            scheme = "https" if p_int in {443, 8443} else "http"
            results.append({"port": p_int, "port_str": p_str, "scheme": scheme})
    return sorted(results, key=lambda x: x["port"])


def make_url(scheme: str, host: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"

# ═══════════════════════════════════════════════════════════════════════════════
#  WEB FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_nextjs(url: str, html: str, headers: dict) -> dict:
    """
    Deep-scan a URL for Next.js fingerprints.

    Returns a dict with keys:
      detected  (bool)  – True if Next.js was found
      version   (str)   – semver string if determinable, else ""
      build_id  (str)   – buildId extracted from __NEXT_DATA__ if present
      router    (str)   – "pages" | "app" | "unknown"
      indicators (list) – human-readable detection evidence
      cves      (list)  – applicable CVE strings with descriptions
    """
    result: dict = {
        "detected":   False,
        "version":    "",
        "build_id":   "",
        "router":     "unknown",
        "indicators": [],
        "cves":        [],
    }
    indicators = result["indicators"]
    base = url.rstrip("/")

    # ── 1. Header-based signals ───────────────────────────────────────────────
    xpb = headers.get("x-powered-by", "").lower()
    if "next" in xpb:
        result["detected"] = True
        indicators.append(f"X-Powered-By: {headers.get('x-powered-by', '')}")

    for h in ("x-nextjs-redirect", "x-nextjs-cache",
              "x-middleware-rewrite", "x-middleware-next",
              "x-middleware-set-cookie", "next-action"):
        if headers.get(h):
            result["detected"] = True
            indicators.append(f"header:{h}: {headers[h][:60]}")

    # ── 2. HTML source patterns ───────────────────────────────────────────────
    if "__NEXT_DATA__" in html:
        result["detected"] = True
        result["router"]   = "pages"
        indicators.append("__NEXT_DATA__ JSON block (Pages Router)")
        # Try to extract buildId from __NEXT_DATA__
        bd_m = re.search(r'"buildId"\s*:\s*"([^"]{4,80})"', html)
        if bd_m:
            result["build_id"] = bd_m.group(1)
            indicators.append(f"buildId: {result['build_id']}")

    if "/_next/static/" in html or "/_next/image" in html:
        result["detected"] = True
        indicators.append("/_next/ asset paths in HTML")

    if "/_next/static/chunks/app/" in html or "__NEXT_APP__" in html:
        result["router"] = "app"
        indicators.append("App Router detected (/_next/static/chunks/app/)")

    # ── 3. Active probing of well-known Next.js endpoints ────────────────────
    probe_endpoints = [
        ("/_next/static/",                 "/_next/static/ accessible"),
        ("/_next/static/chunks/main.js",   "main.js chunk reachable"),
        ("/_next/image",                   "/_next/image optimiser reachable"),
    ]
    for path, label in probe_endpoints:
        try:
            r = requests.head(base + path, timeout=5, verify=False,
                              allow_redirects=False)
            if r.status_code < 400:
                result["detected"] = True
                indicators.append(label)
        except Exception:
            pass

    # ── 4. Version extraction (multiple strategies) ───────────────────────────
    #
    # Strategy A: exposed package.json
    if not result["version"]:
        for path in ("/package.json", "/.next/package.json"):
            try:
                r = requests.get(base + path, timeout=5, verify=False)
                if r.status_code == 200 and '"next"' in r.text:
                    ver_m = re.search(r'"next"\s*:\s*"[~^]?([0-9]+\.[0-9]+[^"]*?)"', r.text)
                    if ver_m:
                        result["version"] = ver_m.group(1)
                        indicators.append(f"version from package.json: {result['version']}")
                        break
            except Exception:
                pass

    # Strategy B: version string in main JS chunk
    # Next.js embeds version in `/_next/static/chunks/main.js` or framework.js
    if not result["version"]:
        for chunk in ("/_next/static/chunks/main.js",
                      "/_next/static/chunks/framework.js",
                      "/_next/static/chunks/polyfills.js"):
            try:
                r = requests.get(base + chunk, timeout=8, verify=False)
                if r.status_code == 200:
                    # Pattern: "next":"15.0.3" or next/dist version strings
                    vm = re.search(
                        r'"next"\s*:\s*"([0-9]+\.[0-9]+\.[0-9][^"]{0,20})"',
                        r.text
                    )
                    if not vm:
                        # Alternate: version=15.0.3 or NEXT_VERSION="15.0.3"
                        vm = re.search(
                            r'(?:NEXT_VERSION|nextVersion|"version")\s*[=:]\s*["\']([0-9]+\.[0-9]+\.[0-9][^"\']{0,15})["\']',
                            r.text
                        )
                    if vm:
                        result["version"] = vm.group(1)
                        indicators.append(f"version from {chunk.split('/')[-1]}: {result['version']}")
                        break
            except Exception:
                pass

    # Strategy C: _buildManifest.js from buildId (buildId must be known)
    if not result["version"] and result["build_id"]:
        manifest_path = f"/_next/static/{result['build_id']}/_buildManifest.js"
        try:
            r = requests.get(base + manifest_path, timeout=5, verify=False)
            if r.status_code == 200:
                # Extract version from manifest comments or embedded strings
                vm = re.search(r'"next"\s*:\s*"([0-9]+\.[0-9]+\.[^"]+)"', r.text)
                if vm:
                    result["version"] = vm.group(1)
                    indicators.append(f"version from _buildManifest: {result['version']}")
        except Exception:
            pass

    # Strategy D: version in HTML meta generator or hidden comment
    if not result["version"]:
        vm = re.search(r'next[/ @v]+([0-9]+\.[0-9]+\.[0-9][^"\' <>]{0,15})', html, re.I)
        if vm:
            candidate = vm.group(1).strip(".,;")
            if re.match(r'^[0-9]+\.[0-9]+', candidate):
                result["version"] = candidate
                indicators.append(f"version from HTML pattern: {result['version']}")

    # Check for App Router chunks directory (Next.js 13+).
    # Only trust the HTTP probe when the HTML does NOT already contain
    # __NEXT_DATA__ (which is a definitive Pages Router signal and takes
    # precedence over a speculative HTTP probe).
    if "__NEXT_DATA__" not in html:
        try:
            r = requests.head(base + "/_next/static/chunks/app/", timeout=5,
                              verify=False, allow_redirects=False)
            if r.status_code == 200:
                result["router"] = "app"
                indicators.append("App Router chunks directory present (Next.js 13+)")
        except Exception:
            pass

    if not result["detected"]:
        return result

    # ── 5. CVE applicability (version-gated) ──────────────────────────────────
    ver_str = result["version"]
    router  = result["router"]
    cves    = result["cves"]

    # Parse semver for version-gating.
    # major.minor.patch  →  (major, minor, patch) as ints
    # Returns None if version is unknown.
    def _parse_ver(v: str):
        m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?', v)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

    parsed = _parse_ver(ver_str) if ver_str else None
    major  = parsed[0] if parsed else None

    # ── CVE-2025-55182 [CVSS:10.0 RCE] ───────────────────────────────────────
    # RSC Flight protocol insecure deserialization (Next.js 15.x / 16.x)
    # Requires App Router + Server Actions, but even without router confirmation
    # any Next.js 15.x / 16.x installation should be flagged because:
    #   – Most Next.js 15+ apps use App Router by default
    #   – The CVE affects even "hybrid" apps that partially use RSC
    # Fixed in: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7
    rce_applies = False
    if router == "app":
        rce_applies = True       # confirmed App Router — definite risk
    elif major is not None and major >= 15:
        rce_applies = True       # version ≥ 15 — very likely App Router
    elif major is None:
        # Version unknown: flag as possible if we detected Next.js at all
        # (conservative — better to over-report than miss an RCE)
        rce_applies = True

    if rce_applies:
        router_note = (
            "App Router + Server Actions confirmed"
            if router == "app"
            else f"Next.js {ver_str or 'unknown'} — check if App Router is used"
        )
        cves.append(
            f"CVE-2025-55182 [CVSS:10.0 RCE] — "
            f"RSC Flight protocol insecure deserialization; "
            f"affects 15.x/16.x | {router_note}"
        )

    # ── CVE-2025-29927 [CVSS:9.1 AUTH-BYPASS] ────────────────────────────────
    # x-middleware-subrequest header bypass
    # Affects: 11.1.4–12.3.4, 13.0–13.5.8, 14.0–14.2.24, 15.0–15.2.2
    # Fixed: 12.3.5, 13.5.9, 14.2.25, 15.2.3   (EDB-ID 52124)
    bypass_applies = False
    if parsed is None:
        bypass_applies = True    # version unknown → assume vulnerable
    else:
        maj, min_, pat = parsed
        if maj == 11 and (min_, pat) >= (1, 4):
            bypass_applies = True
        elif maj == 12 and (min_, pat) <= (3, 4):
            bypass_applies = True
        elif maj == 13 and (min_, pat) <= (5, 8):
            bypass_applies = True
        elif maj == 14 and (
            min_ < 2 or (min_ == 2 and pat <= 24)
        ):
            bypass_applies = True
        elif maj == 15 and (
            min_ < 2 or (min_ == 2 and pat <= 2)
        ):
            bypass_applies = True   # 15.0.x, 15.1.x, 15.2.0–15.2.2

    if bypass_applies:
        cves.append(
            "CVE-2025-29927 [CVSS:9.1 AUTH-BYPASS] — "
            "x-middleware-subrequest header bypass; "
            f"affects 11.1.4–15.2.2 | EDB-ID 52124"
            + (f" | version {ver_str} is in range" if ver_str else "")
        )

    # ── CVE-2024-51479 [CVSS:7.5 AUTH-BYPASS] ────────────────────────────────
    # i18n routing bypass — affects 9.5.5–14.2.14, fixed in 14.2.15
    i18n_applies = False
    if parsed is None:
        i18n_applies = True
    else:
        maj, min_, pat = parsed
        if maj <= 13:
            i18n_applies = True
        elif maj == 14 and (min_ < 2 or (min_ == 2 and pat <= 14)):
            i18n_applies = True
        # Next.js 15.x is NOT affected

    if i18n_applies:
        cves.append(
            "CVE-2024-51479 [CVSS:7.5 AUTH-BYPASS] — "
            "i18n routing bypass; affects 9.5.5–14.2.14"
            + (f" | version {ver_str} is in range" if ver_str else "")
        )

    # ── CVE-2020-5284 [PATH-TRAVERSAL] ───────────────────────────────────────
    # Access .next build artifacts — affects < 9.3.2
    if parsed:
        maj, min_, pat = parsed
        if maj < 9 or (maj == 9 and min_ < 3) or (maj == 9 and min_ == 3 and pat < 2):
            cves.append(
                "CVE-2020-5284 [PATH-TRAVERSAL] — "
                "access .next build artifacts; affects < 9.3.2"
            )

    return result


def fingerprint_web(url: str, workdir: Optional[Path] = None) -> dict:
    fp: dict = {"url": url}

    # whatweb
    if shutil.which("whatweb"):
        rc, out, _ = run_cmd(["whatweb", "--color=never", "-a", "3", url], timeout=45)
        fp["whatweb"] = out.strip()

    # Direct HTTP inspection
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True)
        fp["status"]       = resp.status_code
        fp["server"]       = resp.headers.get("Server", "")
        fp["x_powered_by"] = resp.headers.get("X-Powered-By", "")
        fp["content_type"] = resp.headers.get("Content-Type", "")
        fp["x_generator"]  = resp.headers.get("X-Generator", "")
        fp["cookies"]      = {c.name: c.value for c in resp.cookies}
        fp["final_url"]    = resp.url
        title_m            = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
        fp["title"]        = title_m.group(1).strip() if title_m else ""
        html_body          = resp.text

        # ── Extract version for Wing FTP Server ───────────────────────────────
        if "Wing FTP Server" in fp["server"]:
            try:
                r2 = requests.get(url.rstrip("/") + "/login.html", timeout=HTTP_TIMEOUT, verify=False)
                ver_m = re.search(r'Wing FTP Server v([0-9\.]+)', r2.text, re.I)
                if ver_m:
                    fp["server"] = f"Wing FTP Server/{ver_m.group(1)}"
            except Exception:
                pass

        # ── Comprehensive Tech Detection (Wappalyzer-like) ────────────────────
        hints = []
        srv_header = fp["server"].lower()
        xpb_header = fp["x_powered_by"].lower()
        xgen_header = fp["x_generator"].lower()
        headers_combined = f"{srv_header} {xpb_header} {xgen_header}"

        # 1. Servers
        if "nginx" in srv_header:
            m = re.search(r"nginx/([\d\.]+)", fp["server"], re.I)
            hints.append(f"Nginx {m.group(1)}" if m else "Nginx")
        elif "apache" in srv_header:
            m = re.search(r"apache/([\d\.]+)", fp["server"], re.I)
            hints.append(f"Apache {m.group(1)}" if m else "Apache")
        if "tomcat" in srv_header or "tomcat" in xpb_header:
            m = re.search(r"tomcat/([\d\.]+)", fp["server"] + fp["x_powered_by"], re.I)
            hints.append(f"Apache Tomcat {m.group(1)}" if m else "Apache Tomcat")

        # 2. Languages / Runtimes
        if "php" in headers_combined or any("PHPSESSID" in c for c in fp["cookies"]):
            m = re.search(r"php/([\d\.]+)", fp.get("x_powered_by", "") + fp.get("server", ""), re.I)
            hints.append(f"PHP {m.group(1)}" if m else "PHP")
        if "node.js" in headers_combined or "nodejs" in headers_combined:
            hints.append("Node.js")
        if "asp.net" in headers_combined or any("ASP.NET" in c for c in fp["cookies"]):
            m = re.search(r"asp\.net(?:/([\d\.]+))?", fp.get("x_powered_by", ""), re.I)
            hints.append(f"ASP.NET {m.group(1)}" if m and m.group(1) else "ASP.NET")
        if "python" in srv_header:
            m = re.search(r"python/([\d\.]+)", fp["server"], re.I)
            hints.append(f"Python {m.group(1)}" if m else "Python")

        # 3. CMS & Portals (WordPress, Liferay)
        if "wp-content" in html_body or "wp-includes" in html_body or "wordpress" in headers_combined:
            m = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)"', html_body, re.I)
            hints.append(f"WordPress {m.group(1)}" if m else "WordPress")
            
        if "liferay" in headers_combined or "Liferay" in html_body or "liferay-theme" in html_body:
            m = re.search(r'Liferay (?:Portal |Digital Experience Platform )?([\d\.]+ \w+ \w+ \([^)]+\))', html_body, re.I)
            if not m:
                m = re.search(r'Liferay (?:Portal |Digital Experience Platform )?([\d\.]+)', html_body, re.I)
            hints.append(f"Liferay {m.group(1)}" if m else "Liferay")

        # 4. Web Frameworks (Express, Django, Rails, Laravel)
        if "express" in headers_combined:
            hints.append("Express")
        if "django" in headers_combined:
            hints.append("Django")
        if "rails" in headers_combined:
            hints.append("Ruby on Rails")
        if "laravel" in headers_combined or any("laravel" in c.lower() for c in fp["cookies"]):
            hints.append("Laravel")

        # 5. Frontend Frameworks (React, Vue, Angular)
        if 'data-reactroot' in html_body or '_reactRootContainer' in html_body or 'react-dom' in html_body:
            hints.append("React")
        if 'ng-app' in html_body or 'ng-version=' in html_body:
            m = re.search(r'ng-version="([\d\.]+)"', html_body)
            hints.append(f"Angular {m.group(1)}" if m else "Angular")
        if 'data-v-' in html_body or 'Vue' in fp.get("x_powered_by", ""):
            hints.append("Vue.js")

        # ── Next.js deep detection ────────────────────────────────────────────
        all_headers = {k.lower(): v for k, v in resp.headers.items()}
        nxt = _detect_nextjs(url, html_body, all_headers)
        fp["nextjs"] = nxt
        if nxt["detected"]:
            label = "Next.js"
            if nxt["version"]:
                label += f" {nxt['version']}"
            if nxt["router"] != "unknown":
                label += f" ({nxt['router']} router)"
            if label not in hints:
                hints.append(label)

        # Deduplicate while preserving order and filter empty strings
        fp["tech_hints"] = []
        for h in hints:
            if h and h not in fp["tech_hints"]:
                fp["tech_hints"].append(h)

        parsed = urlparse(resp.url)
        orig   = urlparse(url)
        if parsed.netloc and parsed.netloc != orig.netloc:
            fp["redirect_domain"] = parsed.netloc

    except requests.exceptions.ConnectionError:
        fp["error"] = "Connection refused"
    except Exception as exc:
        fp["error"] = str(exc)

    return fp


def display_fingerprint(fp: dict) -> None:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim green", width=18)
    t.add_column(style="white")

    fields = [
        ("URL",          fp.get("url")),
        ("Title",        fp.get("title")),
        ("Status",       fp.get("status")),
        ("Server",       fp.get("server")),
        ("X-Powered-By", fp.get("x_powered_by")),
        ("X-Generator",  fp.get("x_generator")),
        ("Cookies",      ", ".join(fp.get("cookies", {}).keys()) or None),
        ("Tech Hints",   ", ".join(fp.get("tech_hints", [])) or None),
        ("Redirect",     fp.get("redirect_domain")),
    ]
    for label, val in fields:
        if val:
            t.add_row(label, str(val))
    if fp.get("whatweb"):
        excerpt = fp["whatweb"][:240]
        t.add_row("WhatWeb", excerpt)

    # ── Next.js specific block ────────────────────────────────────────────────
    nxt = fp.get("nextjs", {})
    if nxt.get("detected"):
        nxt_parts = []
        if nxt.get("version"):  nxt_parts.append(f"v{nxt['version']}")
        if nxt.get("router") != "unknown": nxt_parts.append(f"{nxt['router']} router")
        if nxt.get("build_id"): nxt_parts.append(f"buildId={nxt['build_id'][:20]}…")
        nxt_summary = "Next.js" + (" | " + " | ".join(nxt_parts) if nxt_parts else "")
        t.add_row("[bold bright_green]Framework[/]", f"[bold bright_green]{nxt_summary}[/]")

        for ind in nxt["indicators"][:6]:
            t.add_row("", f"[dim]↳ {ind}[/]")

        for cve in nxt.get("cves", []):
            severity = "htb.red" if "RCE" in cve or "CVSS:9" in cve or "CVSS:10" in cve else "htb.yellow"
            t.add_row("[bold red]CVE Alert[/]", f"[{severity}]{cve}[/]")

    if fp.get("error"):
        t.add_row("Error", f"[htb.red]{fp['error']}[/]")

    console.print(Panel(t, title=f"[htb.section]fingerprint → {fp['url']}[/]",
                        border_style="blue", padding=(0, 1)))

# ═══════════════════════════════════════════════════════════════════════════════
#  PASSIVE SPIDER — LIVE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

_LINK_RE = re.compile(
    r'(?:href|src|action|data-url)=["\']([^"\'#?]{3,200})["\']',
    re.IGNORECASE,
)


def passive_spider(url: str, state: ReconState) -> list[str]:
    section(f"PASSIVE SPIDER  ·  {url}")
    links: set[str] = set()

    with Progress(
        SpinnerColumn(spinner_name="dots", style="htb.cyan"),
        TextColumn("[htb.dim]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        t = progress.add_task(f"fetching {url}", total=None)

        try:
            from urllib.parse import urlparse
            base_netloc = urlparse(url).netloc
            resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True)
            body = resp.text

            def process_href(href: str):
                href = href.strip()
                if href.startswith("mailto:") or href.startswith("javascript:") or href == "#":
                    return
                if href.startswith("http"):
                    # Check if it belongs to the target domain or IP
                    if state.target in href or base_netloc in href or "htb" in href:
                        links.add(href.split("?")[0].rstrip("/"))
                else:
                    # Relative link
                    clean = href.split("?")[0].rstrip("/")
                    if clean and clean != "/":
                        links.add(clean)

            def _extract_crawled_versions(text: str, current_url: str):
                versions = []
                # Next.js
                vm = re.search(r'(?:NEXT_VERSION|nextVersion|"version"|"next")\s*[=:]\s*["\']([0-9]+\.[0-9]+\.[0-9][^"\' <>]{0,15})["\']', text)
                if vm: versions.append(f"Next.js {vm.group(1)}")
                # React
                rm = re.search(r'React\s*v?([0-9]+\.[0-9]+\.[0-9][^"\' <>]{0,10})', text, re.I)
                if rm: versions.append(f"React {rm.group(1)}")
                # Vue
                vum = re.search(r'Vue\.js v?([0-9]+\.[0-9]+\.[0-9][^"\' <>]{0,10})', text, re.I)
                if vum: versions.append(f"Vue.js {vum.group(1)}")

                if versions:
                    for fp in state.fingerprints:
                        if fp.get("url", "").rstrip("/") == current_url.rstrip("/"):
                            for v in versions:
                                if v not in fp.setdefault("tech_hints", []):
                                    fp["tech_hints"].append(v)
                                if "Next.js" in v:
                                    nxt = fp.get("nextjs", {})
                                    nxt["detected"] = True
                                    if not nxt.get("version"):
                                        nxt["version"] = v.split()[-1]
                                        nxt.setdefault("indicators", []).append("version extracted during passive spidering")
                                    fp["nextjs"] = nxt

            # Extract from main body
            _extract_crawled_versions(body, url)

            # Depth-0: root
            for m in _LINK_RE.finditer(body):
                process_href(m.group(1))

            # Depth-1: follow relative links that look like pages
            rel_links = [h for h in links if h.startswith("/")]
            # Prioritize JS files for framework version extraction
            js_links = [h for h in rel_links if h.endswith(".js")]
            other_links = [h for h in rel_links if not h.endswith(".js")]
            depth1_targets = (js_links + other_links)[:25]

            for path in depth1_targets:
                sub_url = url.rstrip("/") + path
                try:
                    progress.update(t, description=f"spidering {path[:60]}")
                    r2 = requests.get(sub_url, timeout=8, verify=False, allow_redirects=True)
                    _extract_crawled_versions(r2.text, url)
                    for m in _LINK_RE.finditer(r2.text):
                        process_href(m.group(1))
                except Exception:
                    pass

        except Exception as exc:
            err(f"Spider error: {exc}")

    sorted_links = sorted(links)
    if sorted_links:
        ok(f"Found {len(sorted_links)} unique path(s):")
        for lnk in sorted_links[:40]:
            if lnk.startswith("http"):
                full_lnk = lnk
            else:
                full_lnk = f"{url.rstrip('/')}/{lnk.lstrip('/')}"
            console.print(f"    [htb.green]→[/]  {full_lnk}")
        state.spider_links.extend(sorted_links)
    else:
        info("No internal links extracted.")

    return sorted_links

# ═══════════════════════════════════════════════════════════════════════════════
#  FFUF SMART DYNAMIC FILTER  (probe → detect noise → rerun with filters)
# ═══════════════════════════════════════════════════════════════════════════════


def _strip_ffuf_flags(cmd: list[str], *flags: str) -> list[str]:
    """Return a copy of *cmd* with the given flags (and their values) removed."""
    result: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue
        if tok in flags:
            skip_next = True  # also drop the value that follows
            continue
        result.append(tok)
    return result


def _run_ffuf_smart_filter(
    cmd_base: list[str],
    probe_limit: int = 30,
    threshold: float = 0.6,
) -> tuple[list[str], list[str]]:
    """
    Run ffuf with automatic false-positive filtering.

    Strategy
    --------
    Phase 1 — Silent probe
        Execute ffuf invisibly using ``-json`` (newline-delimited JSON to stdout)
        so every hit is a parseable JSON object containing ``length`` (size) and
        ``words``.  After collecting ``probe_limit`` hits the probe is killed.

    Phase 2 — Noise detection
        Count occurrences of each (size, words) value.  Any value that appears
        in ≥ ``threshold`` of the sample is considered the baseline noise for
        that web server (e.g. a catch-all 404 page with a fixed size).  The
        corresponding ``-fs`` / ``-fw`` filters are built.

    Phase 3 — Filtered live scan
        Re-run ffuf **without** ``-s``/``-json``, with the derived filters
        applied.  ffuf’s banner, progress bar, and coloured hits are displayed
        directly to the terminal so the user sees only real results.

    Returns
    -------
    (filter_sizes, filter_words)
        String representations of the filter values that were applied
        (empty lists if none were needed).
    """
    # ── Phase 1: silent probe ─────────────────────────────────────────────────
    #
    # Build probe command:
    #  - strip any -o/-of that point to the caller’s output file (we don’t want
    #    the probe to overwrite it)
    #  - strip any existing -fs/-fw/-fc filters (clean baseline measurement)
    #  - add ``-json`` so every hit is emitted as a JSON object on stdout
    #  - add ``-s`` to suppress the progress bar / banner
    #  - add ``-maxtime-job 60`` as a safety cap so the probe can’t run forever
    #
    probe_cmd = _strip_ffuf_flags(
        cmd_base,
        "-o", "-of",    # separate output file; probe doesn’t need one
        "-fs", "-fw", "-fc", "-fl",  # strip caller-supplied filters
    )
    # Remove flags that don’t take a value (positional-style)
    probe_cmd = [t for t in probe_cmd if t not in ("-s", "-c", "-json")]
    probe_cmd += ["-s", "-json", "-maxtime-job", "60", "-noninteractive"]

    info("[dim]► Probe scan: sampling responses to detect false-positive baseline…[/]")

    probe_sizes: list[int] = []
    probe_words: list[int] = []
    probe_lines_seen = 0

    try:
        proc = subprocess.Popen(
            probe_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        # ffuf -json emits one JSON object per line for every matched result.
        # Example line:
        #   {"input":{...},"position":1,"status":200,"length":4242,"words":312,
        #    "lines":80,"content-type":"text/html","redirectlocation":"",
        #    "url":"http://...","duration":123456,"scraper":{},"resultfile":"",
        #    "host":"sub.domain.htb"}
        while True:
            if proc.stdout is None:
                break
            rlist, _, _ = select.select([proc.stdout], [], [], 1.0)
            if rlist:
                raw = proc.stdout.readline()
                if not raw:          # EOF
                    break
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    size  = obj.get("length", obj.get("size", -1))
                    words = obj.get("words", -1)
                    if size >= 0 and words >= 0:
                        probe_sizes.append(int(size))
                        probe_words.append(int(words))
                        probe_lines_seen += 1
                        if probe_lines_seen >= probe_limit:
                            break
                except json.JSONDecodeError:
                    pass  # non-JSON line (e.g. ffuf informational messages)
            else:
                if proc.poll() is not None:
                    break

        # Kill the probe — we have enough data (or it finished naturally)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    except KeyboardInterrupt:
        warn("Caught keyboard interrupt during probe scan.")
        return [], []
    except Exception as exc:
        warn(f"[dim]Probe scan error: {exc}[/]")
        return [], []

    # ── Phase 2: noise analysis ────────────────────────────────────────────────
    filter_sizes: list[str] = []
    filter_words: list[str] = []

    if probe_lines_seen == 0:
        info("[dim]  No hits during probe — no auto-filter applied.[/]")
    else:
        sample = probe_lines_seen
        size_counter = Counter(probe_sizes)
        word_counter = Counter(probe_words)

        # A value is "noisy" if it accounts for ≥ threshold of the sample
        noisy_sizes = [
            str(v) for v, cnt in size_counter.most_common()
            if cnt / sample >= threshold
        ]
        noisy_words = [
            str(v) for v, cnt in word_counter.most_common()
            if cnt / sample >= threshold
        ]

        if noisy_sizes or noisy_words:
            parts: list[str] = []
            if noisy_sizes:
                filter_sizes = noisy_sizes
                parts.append(f"-fs {','.join(noisy_sizes)}")
            if noisy_words:
                filter_words = noisy_words
                parts.append(f"-fw {','.join(noisy_words)}")
            info(
                f"[bold yellow]⚠ Auto-filter:[/] "
                + ", ".join(parts)
                + f"  [dim](detected from {sample}/{probe_limit} probe hits)[/]"
            )
        else:
            info(
                f"[dim]  Probe collected {sample} hits — "
                "no dominant noise pattern found, no extra filters applied.[/]"
            )

    # ── Phase 3: filtered live scan ────────────────────────────────────────────
    final_cmd = [t for t in cmd_base if t not in ("-s", "-json")]
    final_cmd += ["-s"]  # Make silent to prevent raw output clutter

    if filter_sizes:
        final_cmd += ["-fs", ",".join(filter_sizes)]
    if filter_words:
        final_cmd += ["-fw", ",".join(filter_words)]

    try:
        stream_process(
            final_cmd,
            label="ffuf vhost fuzzing",
            timeout=FUZZ_TIMEOUT
        )
    except KeyboardInterrupt:
        warn("Caught keyboard interrupt (Ctrl-C) during ffuf.")
    except Exception as exc:
        err(f"ffuf error: {exc}")

    return filter_sizes, filter_words


# ═══════════════════════════════════════════════════════════════════════════════
#  DIRECTORY FUZZING — LIVE OUTPUT (ffuf → dirsearch → gobuster)
# ═══════════════════════════════════════════════════════════════════════════════

def fuzz_directories(url: str, state: ReconState, extensions: str = COMMON_EXT) -> list[dict]:
    section(f"DIRECTORY & FILE FUZZING  ·  {url}")
    # Use custom wordlist from state if provided, else fallback to default
    wordlist = state.wl_dirs or resolve_wordlist("dirs")
    if not wordlist:
        return []

    info(f"Wordlist: {wordlist}")
    info(f"Extensions: {extensions}")

    results: list[dict] = []
    out_json = state.workdir / f"fuzz_dirs_{random_hex(4)}.json"

    # ── dirsearch (preferred as requested by user) ─────────────────────────
    if shutil.which("dirsearch"):
        info("Tool: dirsearch (default wordlist)")
        out_csv = state.workdir / f"dirsearch_{random_hex(4)}.csv"
        cmd = [
            "dirsearch",
            "-u", url,
            "-e", extensions,
            "--format=csv",
            f"--output={out_csv}",
            "-t", "50",
            "-q",
            "-i", "200,204,301,302,307,401,405"
        ]

        try:
            env = os.environ.copy()
            env["PYTHONWARNINGS"] = "ignore"
            cmd_str = " ".join(cmd)
            short_cmd = cmd_str if len(cmd_str) < 80 else cmd_str[:77] + "..."
            with console.status(f"[htb.cyan]dirsearch scanning...[/] [dim]→ {short_cmd}[/]", spinner="dots2"):
                subprocess.call(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except KeyboardInterrupt:
            warn("Caught keyboard interrupt (Ctrl-C) during dirsearch.")
        except Exception as exc:
            err(f"dirsearch error: {exc}")

        if out_csv.exists():
            try:
                for line in out_csv.read_text().splitlines()[1:]:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        sc_csv, path_csv = parts[0].strip(), parts[1].strip()
                        if sc_csv.isdigit():
                            rurl = url.rstrip("/") + path_csv
                            if not any(r["url"] == rurl for r in results):
                                results.append({"url": rurl, "status": int(sc_csv), "size": 0})
            except Exception as e:
                err(f"Error parsing dirsearch CSV: {e}")
                
    # ── gobuster fallback ───────────────────────────────────────────────────
    elif shutil.which("gobuster"):
        info("Tool: gobuster (dirsearch not found)")
        out_txt = state.workdir / f"gobuster_{random_hex(4)}.txt"
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-x", extensions,
            "-t", "50",
            "-o", str(out_txt),
            "-q",
        ]
        
        try:
            cmd_str = " ".join(cmd)
            short_cmd = cmd_str if len(cmd_str) < 80 else cmd_str[:77] + "..."
            with console.status(f"[htb.cyan]gobuster scanning...[/] [dim]→ {short_cmd}[/]", spinner="dots2"):
                subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except KeyboardInterrupt:
            warn("Caught keyboard interrupt (Ctrl-C) during gobuster.")
        except Exception as exc:
            err(f"gobuster error: {exc}")

        if out_txt.exists():
            gb_re = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)")
            try:
                for line in out_txt.read_text().splitlines():
                    m = gb_re.search(line)
                    if m:
                        path, status = m.groups()
                        full_url = url.rstrip("/") + path
                        if not any(r["url"] == full_url for r in results):
                            results.append({"url": full_url, "status": int(status), "size": 0})
            except Exception as e:
                err(f"Error parsing gobuster output: {e}")
    else:
        err("No fuzzing tool found (dirsearch / gobuster). Install at least one.")
        return []

    # Display summary table
    if results:
        t = Table(
            title=f"[dim green]{len(results)} path(s) found[/]",
            box=box.SIMPLE_HEAD, border_style="dark_green",
        )
        t.add_column("Status", style="htb.cyan",  width=8,  justify="right")
        t.add_column("Size",   style="dim",        width=8,  justify="right")
        t.add_column("URL",    style="htb.green")
        for r in sorted(results, key=lambda x: x["status"]):
            sc = r["status"]
            color = "htb.yellow" if sc in (301, 302, 307) else \
                    "htb.red"    if sc in (401, 403)       else "htb.green"
            t.add_row(
                f"[{color}]{r['status']}[/]",
                str(r.get("size", "")),
                r["url"],
            )
        console.print(t)
    else:
        info("No directories/files found.")

    state.directories.extend(results)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
#  VHOST FUZZING — SMART MULTI-FILTER STRATEGY + LIVE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════


def fuzz_vhosts_smart(
    state: ReconState,
    domain: str,
    proto: str,
    port: int,
) -> list[str]:
    """
    Vhost discovery using gobuster vhost (as requested by user).
    """
    section(f"VHOST FUZZING  ·  {domain}  [{proto}:{port}]")

    # Use custom wordlist from CLI if provided
    wordlist = state.wl_vhosts or resolve_wordlist("vhosts")
    if not wordlist:
        return []
    if not shutil.which("ffuf"):
        warn("ffuf not found — skipping vhost fuzzing.")
        return []

    wl_lines = _wordlist_size(wordlist)
    info(f"Domain: [bold]{domain}[/]  |  Wordlist: {wordlist}  ({wl_lines:,} entries)")
    info("Tool: ffuf vhost")

    found_set: set[str] = set()
    out_json = str(state.workdir / f"ffuf_vhosts_{port}.json")
    if os.path.exists(out_json):
        os.remove(out_json)
        
    url = make_url(proto, state.target, port).rstrip("/")
        
    # Base command without -s so the final filtered scan shows live output
    cmd_base = [
        "ffuf", "-c",
        "-u", url,
        "-w", wordlist,
        "-H", f"Host:FUZZ.{domain}",
        "-mc", "200,301,302,307,401,403",
        "-o", out_json,
        "-of", "json",
    ]

    # Run smart filter: probe silently, detect noise, rerun with filters applied
    _run_ffuf_smart_filter(cmd_base)

    # Parse JSON output for results
    if os.path.exists(out_json):
        try:
            with open(out_json, "r") as f:
                data = json.load(f)
                for res in data.get("results", []):
                    # Primary: FUZZ keyword value (what was actually fuzzed)
                    inputs = res.get("input", {})
                    sub = inputs.get("FUZZ", "").strip()
                    # Fallback: parse the 'host' field if FUZZ is not present
                    if not sub:
                        host_field = res.get("host", "")
                        sub = host_field.split(".")[0] if host_field else ""
                    if not sub:
                        continue
                    vhost = f"{sub}.{domain}"
                    if vhost not in found_set:
                        found_set.add(vhost)
                        ok(
                            f"FFUF VHOST FOUND: [bold white]{vhost}[/]"
                            f"  [dim][{res.get('status')} | "
                            f"size:{res.get('length','?')} | "
                            f"words:{res.get('words','?')}][/]"
                        )
        except Exception as e:
            err(f"Error parsing ffuf JSON: {e}")

    found_list = list(dict.fromkeys(found_set))[:10]  # deduplicate, cap 10

    if found_list:
        t = Table(
            title=f"[dim green]{len(found_list)} vhost(s) confirmed[/]",
            box=box.SIMPLE_HEAD, border_style="dark_green",
        )
        t.add_column("VHost",  style="htb.green")
        t.add_column("Action", style="htb.cyan")
        for v in found_list:
            t.add_row(v, "→ /etc/hosts + fingerprint + dir fuzz")
        console.print(t)
    else:
        info("No vhosts discovered.")

    return found_list

# ═══════════════════════════════════════════════════════════════════════════════
#  SSL CERTIFICATE HOSTNAME EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def inspect_ssl(target: str, port: str = "443") -> list[str]:
    domains: list[str] = []
    rc, out, _ = run_cmd(
        ["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target],
        timeout=15, input_data="",
    )
    if rc != 0:
        return domains
    for m in re.finditer(r"CN\s*=\s*([a-zA-Z0-9\-\.]+\.htb)", out, re.I):
        d = m.group(1).lstrip("*.").lower()
        if d not in domains:
            domains.append(d)
    rc2, out2, _ = run_cmd(
        ["openssl", "s_client", "-connect", f"{target}:{port}",
         "-servername", target, "-showcerts"],
        timeout=15, input_data="",
    )
    for m in re.finditer(r"DNS:([a-zA-Z0-9\-\.]+\.htb)", out2, re.I):
        d = m.group(1).lstrip("*.").lower()
        if d not in domains:
            domains.append(d)
    return domains

# ═══════════════════════════════════════════════════════════════════════════════
#  PROTOCOL ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def enum_ftp(target: str, port: int, state: ReconState) -> None:
    section(f"FTP ENUMERATION  ·  port {port}")
    result: dict = {"service": "FTP", "anonymous": False, "listing": [], "port": str(port)}

    # Try ftplib anonymous login
    try:
        ftp = ftplib.FTP(timeout=10)
        ftp.connect(target, port, timeout=10)
        banner = ftp.getwelcome()
        result["banner"] = banner
        info(f"Banner: {banner[:100]}")
        ftp.login("anonymous", "anonymous@")
        result["anonymous"] = True
        listing: list[str] = []
        ftp.retrlines("LIST", listing.append)
        result["listing"] = listing
        ftp.quit()
    except ftplib.error_perm as e:
        result["error"] = f"Auth denied: {e}"
    except Exception as e:
        result["error"] = str(e)

    state.quick_wins.append(result)

    if result.get("anonymous"):
        crit("FTP ANONYMOUS LOGIN — SUCCESSFUL!")
        if result.get("listing"):
            t = Table(box=box.MINIMAL, border_style="green",
                      title="[htb.green]FTP root listing[/]")
            t.add_column("Entry")
            for line in result["listing"][:20]:
                t.add_row(line)
            console.print(t)
    else:
        info(f"FTP anonymous: denied.  {result.get('error','')}")

    # nmap ftp scripts as fallback info
    if shutil.which("nmap"):
        info("Running nmap ftp-anon script…")
        rc, out, _ = run_cmd(
            ["nmap", "-sV", f"-p{port}", "--script", "ftp-anon,ftp-syst",
             state.target], timeout=60,
        )
        for line in out.splitlines():
            if "anon" in line.lower() or "ftp" in line.lower():
                console.print(f"    [dim]{line.strip()}[/]")


def enum_smb(target: str, port: int, state: ReconState) -> None:
    section(f"SMB ENUMERATION  ·  port {port}")
    result: dict = {"service": "SMB", "shares": [], "ports": str(port)}

    # netexec / smbclient
    if shutil.which("netexec"):
        rc, out, _ = run_cmd(
            ["netexec", "smb", target, "-u", "", "-p", "", "--shares"], timeout=30
        )
        result["raw"] = out[:600]
        result["shares"] = re.findall(r"SHARE\s+(\S+)", out)
        for s in result["shares"]:
            ok(f"SMB share: {s}")
        rc2, out2, _ = run_cmd(
            ["netexec", "smb", target, "-u", "guest", "-p", "", "--shares"], timeout=30
        )
        for s in re.findall(r"SHARE\s+(\S+)", out2):
            if s not in result["shares"]:
                result["shares"].append(s)
                ok(f"SMB share (guest): {s}")
    elif shutil.which("smbclient"):
        rc, out, _ = run_cmd(["smbclient", "-L", target, "-N"], timeout=30)
        result["raw"]    = out[:600]
        result["shares"] = re.findall(r"\s+(\S+)\s+Disk", out)
        for s in result["shares"]:
            ok(f"SMB share (null): {s}")
    else:
        info("netexec/smbclient not available — running nmap smb scripts")

    if result.get("shares"):
        crit(f"SMB SHARES ACCESSIBLE: {', '.join(result['shares'])}")
    else:
        info("SMB: no accessible shares found.")

    state.quick_wins.append(result)

    # nmap smb scripts
    if shutil.which("nmap"):
        info("Running nmap SMB scripts…")
        rc, out, _ = run_cmd(
            ["nmap", f"-p{port}",
             "--script", "smb-enum-shares,smb-security-mode,smb-vuln-ms17-010,smb-os-discovery",
             target], timeout=120,
        )
        for line in out.splitlines():
            if re.match(r"\s+\|", line):
                clean = line.strip().lstrip("|_ ")
                if clean:
                    console.print(f"  [htb.dim]│[/]  {clean}")


def enum_ldap(target: str, port: int, state: ReconState) -> None:
    section(f"LDAP ENUMERATION  ·  port {port}")
    result: dict = {"service": "LDAP", "anonymous_bind": False, "port": str(port)}

    # ldap3 if available
    try:
        import ldap3  # type: ignore
        srv  = ldap3.Server(target, port=port, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(srv, auto_bind=True)
        result["anonymous_bind"] = conn.bound
        if srv.info:
            result["namingContexts"] = str(srv.info.naming_contexts)[:200]
        conn.unbind()
    except ImportError:
        result["note"] = "ldap3 not installed — trying ldapsearch"
        if shutil.which("ldapsearch"):
            rc, out, _ = run_cmd(
                ["ldapsearch", "-x", "-h", target, "-p", str(port),
                 "-b", "", "-s", "base"], timeout=30,
            )
            if out and "dn:" in out:
                result["anonymous_bind"] = True
                dn = re.search(r"namingContexts:\s*(.+)", out)
                if dn:
                    result["namingContexts"] = dn.group(1).strip()
    except Exception as e:
        result["error"] = str(e)

    state.quick_wins.append(result)

    if result.get("anonymous_bind"):
        crit("LDAP ANONYMOUS BIND — ALLOWED!")
        if result.get("namingContexts"):
            ok(f"NamingContexts: {result['namingContexts']}")
    else:
        info("LDAP anonymous bind: denied.")


def enum_rpc(target: str, port: int, state: ReconState) -> None:
    section(f"RPC ENUMERATION  ·  port {port}")
    result: dict = {"service": "RPC", "users": [], "port": str(port)}

    if shutil.which("rpcclient"):
        rc, out, _ = run_cmd(
            ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"],
            timeout=30,
        )
        if out and "user:" in out.lower():
            result["users"] = re.findall(r"user:\[(.*?)\]", out)
            crit(f"RPC NULL SESSION — users: {', '.join(result['users'])}")
        else:
            info("RPC null session denied.")
    else:
        info("rpcclient not available.")

    state.quick_wins.append(result)


def enum_winrm(target: str, port: int, state: ReconState) -> None:
    section(f"WinRM CHECK  ·  port {port}")
    result: dict = {"service": "WinRM", "responding": False, "port": str(port)}
    try:
        resp = requests.get(
            f"http://{target}:{port}/wsman",
            timeout=8, verify=False,
        )
        result["responding"] = True
        result["status"] = resp.status_code
        crit(f"WinRM IS RESPONDING on port {port} — status {resp.status_code}")
    except Exception as e:
        info(f"WinRM not responding: {e}")
    state.quick_wins.append(result)


def enum_nfs(target: str, port: int, state: ReconState) -> None:
    section(f"NFS ENUMERATION  ·  port {port}")
    result: dict = {"service": "NFS", "mounts": [], "port": str(port)}
    if shutil.which("showmount"):
        rc, out, _ = run_cmd(["showmount", "-e", target], timeout=20)
        result["raw"]    = out[:300]
        result["mounts"] = re.findall(r"(/[^\s]+)", out)
        if result["mounts"]:
            crit(f"NFS EXPORTS EXPOSED: {', '.join(result['mounts'])}")
        else:
            info("NFS: no exposed mounts.")
    else:
        info("showmount not available.")
    state.quick_wins.append(result)


def enum_ssh_banner(target: str, port: int, state: ReconState) -> None:
    section(f"SSH BANNER  ·  port {port}")
    result: dict = {"service": "SSH", "port": str(port), "banner": ""}
    try:
        s = socket.create_connection((target, port), timeout=8)
        s.settimeout(5)
        banner = s.recv(256).decode(errors="replace").strip()
        s.close()
        result["banner"] = banner
        ok(f"SSH banner: {banner}")
        m = re.search(r"SSH-[\d\.]+-([^\s]+)", banner)
        if m:
            state.notes.append(f"SSH software: {m.group(1)}")
    except Exception as e:
        info(f"SSH: {e}")
    state.quick_wins.append(result)


PROTO_HANDLERS: dict[int, tuple[str, callable]] = {
    21:   ("FTP",   enum_ftp),
    22:   ("SSH",   enum_ssh_banner),
    139:  ("SMB",   enum_smb),
    445:  ("SMB",   enum_smb),
    389:  ("LDAP",  enum_ldap),
    636:  ("LDAP",  enum_ldap),
    111:  ("RPC",   enum_rpc),
    135:  ("RPC",   enum_rpc),
    2049: ("NFS",   enum_nfs),
    5985: ("WinRM", enum_winrm),
    5986: ("WinRM", enum_winrm),
}


def run_protocol_enum(state: ReconState) -> None:
    port_set: set[int] = set()
    for p in state.ports:
        try:
            port_set.add(int(p.split("/")[0]))
        except ValueError:
            pass
    seen_protocols: set[str] = set()

    for port_int, (proto_name, fn) in PROTO_HANDLERS.items():
        if port_int in port_set and proto_name not in seen_protocols:
            seen_protocols.add(proto_name)
            fn(state.target, port_int, state)

# ═══════════════════════════════════════════════════════════════════════════════
#  SEARCHSPLOIT
# ═══════════════════════════════════════════════════════════════════════════════

def searchsploit_lookup(term: str) -> list[dict]:
    if not shutil.which("searchsploit"):
        return []
    rc, out, _ = run_cmd(["searchsploit", "--json", term], timeout=30)
    if rc != 0 or not out.strip():
        return []
    try:
        return json.loads(out).get("RESULTS_EXPLOIT", [])
    except Exception:
        return []


def run_searchsploit(state: ReconState) -> None:
    section("SEARCHSPLOIT  ·  EXPLOIT LOOKUP")
    if not shutil.which("searchsploit"):
        warn("searchsploit not found — skipping exploit search.")
        return
    if not state.services and not state.fingerprints:
        info("No services or fingerprints to query.")
        return

    # ── Build the query terms list ────────────────────────────────────────────
    # Order: detected frameworks first (highest value), then nmap services.
    seen_terms: set[str] = set()
    query_items: list[tuple[str, str]] = []   # (display_label, searchsploit_term)

    # 1. Extract frameworks / technologies from web fingerprints
    for fp in state.fingerprints:
        # Next.js — targeted CVE-aware queries
        nxt = fp.get("nextjs", {})
        if nxt.get("detected"):
            ver = nxt.get("version", "")
            for term in ([f"Next.js {ver}", "Next.js"] if ver else ["Next.js"]):
                if term not in seen_terms:
                    seen_terms.add(term)
                    query_items.append((f"Next.js{'  v'+ver if ver else ''}", term))
            # Always also try CVEs directly in searchsploit
            for cve_term in ("CVE-2025-29927", "CVE-2025-55182", "Next.js middleware"):
                if cve_term not in seen_terms:
                    seen_terms.add(cve_term)
                    query_items.append((cve_term, cve_term))


        # Generic tech_hints (Laravel, WordPress, PHP, Express, etc.)
        for hint in fp.get("tech_hints", []):
            # Strip version from label e.g. "Next.js 15.2.1 (pages router)"
            base_hint = re.split(r'[ /]', hint)[0].strip()
            if base_hint and base_hint not in seen_terms and "Next" not in base_hint:
                seen_terms.add(base_hint)
                query_items.append((hint, base_hint))

        # Server header (e.g. "Apache/2.4.49", "nginx/1.18")
        for key in ("server", "x_powered_by"):
            val = fp.get(key, "")
            if not val:
                continue
            clean = re.sub(r'\(.*?\)', '', val).strip()
            parts = clean.split("/")
            svc_name = parts[0].strip()
            svc_ver  = parts[1].strip() if len(parts) > 1 else ""
            if svc_name and svc_name not in seen_terms:
                seen_terms.add(svc_name)
                term = f"{svc_name} {svc_ver}".strip() if svc_ver else svc_name
                query_items.append((f"{svc_name} {svc_ver}".strip(), term))
                # Also inject into state.services for deduplication tracking
                if not any(s["service"].lower() == svc_name.lower() for s in state.services):
                    state.services.append({"port": "web", "service": svc_name, "version": svc_ver})

    # 2. Nmap service versions (skip generic ones already covered)
    for svc in state.services:
        svc_lower = svc["service"].lower()
        # Focus: web stacks, ftp, ssh, smb, database services
        relevant = (
            "http" in svc_lower or "web" in svc_lower or
            "apache" in svc_lower or "nginx" in svc_lower or
            "iis" in svc_lower or "tomcat" in svc_lower or
            "ftp" in svc_lower or "ssh" in svc_lower or
            "smb" in svc_lower or "samba" in svc_lower or
            "mysql" in svc_lower or "postgres" in svc_lower or
            "mssql" in svc_lower or "mongo" in svc_lower or
            "redis" in svc_lower or "elastic" in svc_lower
        )
        if not relevant:
            continue
        ver_parts = svc.get("version", "").split()
        # Prefer "Service Version" → "Service" fallback
        for term in (
            [f"{svc['service']} {ver_parts[0]}", svc["service"]] if ver_parts
            else [svc["service"]]
        ):
            if term not in seen_terms:
                seen_terms.add(term)
                query_items.append((term, term))

    if not query_items:
        info("No actionable terms to search.")
        return

    seen_edb_ids: set[str] = set()

    # ── Run queries ──────────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="htb.red"),
        TextColumn("[htb.dim]{task.description}"),
        BarColumn(bar_width=None, style="red", complete_style="htb.red"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        expand=True,
    ) as progress:
        task_id = progress.add_task("Searchsploit Lookups", total=len(query_items))
        
        for label, term in query_items:
            progress.update(task_id, description=f"Searchsploit querying: [cyan]{label}[/]")
            raw_hits = searchsploit_lookup(term)
            
            # Deduplicate by EDB-ID across all queries
            hits = []
            for h in raw_hits:
                edb = h.get("EDB-ID")
                if edb and edb not in seen_edb_ids:
                    seen_edb_ids.add(edb)
                    hits.append(h)
                    
            if hits:
                state.exploits[term] = hits[:10]
                t = Table(
                    title=f"[htb.red]⚡ Exploits → {label}[/]",
                    box=box.SIMPLE_HEAD, border_style="red",
                    expand=False
                )
                t.add_column("EDB-ID", style="bold cyan",  width=8,  justify="center")
                t.add_column("Title",  style="bold white",  overflow="fold")
                t.add_column("CVE",    style="htb.yellow",  width=18)
                t.add_column("Type",   style="htb.magenta", width=10)
                for h in hits[:10]:
                    edb   = h.get("EDB-ID", "")
                    title = h.get("Title", "")
                    codes = h.get("Codes", "")
                    htype = h.get("Type", "")
                    t.add_row(edb, title, codes, htype)
                console.print(t)
            progress.advance(task_id)

# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(state: ReconState) -> Path:
    section("GENERATING REPORT")
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dur  = elapsed(state.started_at)
    path = state.workdir / "report.md"

    lines: list[str] = [
        f"# HTB Recon Report — {state.lab}",
        "",
        f"> **Target:** `{state.target}` &nbsp; **OS:** {state.os_guess or 'Unknown'} &nbsp; **TTL:** {state.ttl}",
        f"> **Date:** {now} &nbsp; **Duration:** {dur}",
        "",
        "---",
        "",
        "## 🗺️ Attack Surface Overview",
        "",
        f"- **Open ports:** `{', '.join(state.ports) or 'none'}`",
        f"- **Domains:** `{', '.join(state.domains) or 'none'}`",
        f"- **VHosts found:** `{', '.join(state.vhosts) or 'none'}`",
        f"- **Directories found:** {len(state.directories)}",
        f"- **Spidered links:** {len(state.spider_links)}",
        f"- **Potential exploits:** {sum(len(v) for v in state.exploits.values())}",
        "",
        "---",
        "",
        "## 1. Services & Ports",
        "",
        "| Port | Service | Version |",
        "|:----:|---------|---------|",
    ]
    for svc in state.services:
        lines.append(f"| `{svc['port']}` | **{svc['service']}** | {svc['version']} |")

    lines += ["", "## 2. Domains & VHosts", ""]
    for d in state.domains:
        lines.append(f"- 🌐 `{d}`")
    for v in state.vhosts:
        lines.append(f"- 🔀 `{v}` *(vhost)*")

    lines += ["", "## 3. Web Fingerprints", ""]
    for fp in state.fingerprints:
        lines.append(f"### `{fp.get('url', '?')}`")
        for key in ("status", "server", "x_powered_by", "x_generator", "title", "content_type"):
            val = fp.get(key)
            if val:
                lines.append(f"- **{key.replace('_', ' ').title()}:** {val}")
        if fp.get("cookies"):
            lines.append(f"- **Cookies:** {', '.join(fp['cookies'].keys())}")
        if fp.get("tech_hints"):
            lines.append(f"- **Tech Hints:** {', '.join(fp['tech_hints'])}")
        if fp.get("whatweb"):
            lines.append(f"- **WhatWeb:** `{fp['whatweb'][:250]}`")
        # Next.js detection results
        nxt = fp.get("nextjs", {})
        if nxt.get("detected"):
            ver  = nxt.get("version", "")
            rtr  = nxt.get("router", "unknown")
            bid  = nxt.get("build_id", "")
            lines.append("")
            lines.append(f"#### ⚡ Framework: Next.js{' v'+ver if ver else ''}")
            if rtr != "unknown": lines.append(f"- **Router:** {rtr}")
            if bid:               lines.append(f"- **BuildId:** `{bid}`")
            if nxt.get("indicators"):
                lines.append("- **Detection evidence:**")
                for ind in nxt["indicators"]:
                    lines.append(f"  - `{ind}`")
            if nxt.get("cves"):
                lines.append("- **⚠️ CVE Alerts:**")
                for cve in nxt["cves"]:
                    lines.append(f"  - 🔴 `{cve}`")
        lines.append("")

    lines += ["## 4. Directory Fuzzing", ""]
    if state.directories:
        lines += ["| Status | Size | URL |", "|:------:|-----:|-----|"]
        for d in state.directories:
            lines.append(f"| `{d.get('status', '')}` | {d.get('size', '')} | {d.get('url', '')} |")
    else:
        lines.append("*No directories found.*")

    lines += ["", "## 5. Passive Spider Links", ""]
    for lnk in state.spider_links[:50]:
        lines.append(f"- `{lnk}`")

    lines += ["", "## 6. Nuclei Results", ""]
    nuclei_out = state.workdir / "nuclei_results.txt"
    if nuclei_out.exists():
        nuclei_lines = nuclei_out.read_text().splitlines()
        if nuclei_lines:
            for l in nuclei_lines:
                lines.append(f"- `{l}`")
        else:
            lines.append("*No vulnerabilities found by Nuclei.*")
    else:
        lines.append("*Nuclei scan was not run.*")

    lines += ["", "## 7. Potential Exploits (Searchsploit)", ""]
    for term, hits in state.exploits.items():
        lines.append(f"### `{term}`")
        lines += ["| Title | Type | Path |", "|-------|------|------|"]
        for h in hits:
            title = h.get("Title", "").replace("|", "\\|")
            typ   = h.get("Type", "")
            pth   = h.get("Path", "")
            lines.append(f"| {title} | {typ} | `{pth}` |")
        lines.append("")

    lines += ["## 7. Quick Win Results", ""]
    for qw in state.quick_wins:
        svc = qw.get("service", "?")
        lines.append(f"### {svc} (port {qw.get('port', qw.get('ports', '?'))})")
        for k, v in qw.items():
            if k in ("service", "port", "ports", "raw"):
                continue
            if isinstance(v, list):
                v = ", ".join(v) or "—"
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    if state.notes:
        lines += ["## 8. Analyst Notes", ""]
        for n in state.notes:
            lines.append(f"- {n}")
        lines.append("")

    lines += ["## 9. Suggested Next Steps", ""]
    port_ints = set()
    for p in state.ports:
        try: port_ints.add(int(p.split("/")[0]))
        except ValueError: pass
    
    if port_ints & {80, 443, 8080, 8443}: lines.append("- **Web:** manual enumeration → LFI, SQLi, IDOR, auth bypass")
    if 445 in port_ints: lines.append("- **SMB:** smbmap, netexec, check EternalBlue (MS17-010)")
    if 5985 in port_ints: lines.append("- **WinRM:** evil-winrm with valid creds")
    if 389 in port_ints: lines.append("- **LDAP:** BloodHound / ldapdomaindump for AD enumeration")
    if 21 in port_ints: lines.append("- **FTP:** check anonymous upload, binary mode, bounce attack")
    for v in state.vhosts: lines.append(f"- **VHost:** Enumerate vhost further: `{v}`")
    if state.exploits: lines.append("- **Exploits:** Review searchsploit results — check Metasploit / PoC")
    if state.directories: lines.append(f"- **Paths:** Investigate {len(state.directories)} discovered paths manually")
    if state.fingerprints or state.services:
        lines.append("- ⚠️ **Manual CVE Search:** Search Google/Exploit-DB manually for CVEs affecting the detected framework versions (Searchsploit may be outdated or incomplete).")
        
    lines.append("- 🎯 **Pwn:** Automated recon is complete. Time to get your hands dirty and pop some shells. Happy Hacking!")
    lines.append("")

    lines += [
        "## 10. Raw Nmap (Services Scan)",
        "",
        "```",
        (state.nmap_raw[:8000] if state.nmap_raw else "(no output)"),
        "```",
        "",
        "---",
        f"*Generated by reconthebox.py v{VERSION} · {now}*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    ok(f"Report written → {path}")
    return path

# ═══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY TREE
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(state: ReconState, report_path: Optional[Path] = None) -> None:
    # Deduplicate arrays to prevent bloat on re-runs
    state.fingerprints = list({fp["url"]: fp for fp in state.fingerprints}.values())
    state.quick_wins = list({qw.get("service", str(qw)): qw for qw in state.quick_wins}.values())
    state.services = list({f"{s['port']}-{s['service']}": s for s in state.services}.values())
    state.domains = list(dict.fromkeys(state.domains))
    state.vhosts = list(dict.fromkeys(state.vhosts))
    
    console.print()
    dur = elapsed(state.started_at)

    tree = Tree(
        f"[bold bright_green]◈ RECON COMPLETE — {state.lab}  [{dur}][/]",
        guide_style="dark_green",
    )

    tree.add(f"[htb.cyan]Target[/]  {state.target}  ({state.os_guess or '?'}  TTL={state.ttl})")

    node_ports = tree.add(f"[htb.cyan]Ports[/]  {len(state.ports)} open")
    for svc in state.services:
        node_ports.add(f"[dim]{svc['port']}/tcp[/]  {svc['service']}  [dim]{svc['version'][:50]}[/]")

    node_web = tree.add(f"[htb.cyan]Web[/]  {len(state.fingerprints)} surface(s)")
    for fp in state.fingerprints:
        fp_node = node_web.add(f"[dim]{fp.get('url', '')}[/]  → {fp.get('title', '') or fp.get('server', '')}")
        # Explicitly include full Next.js version detection strings if they exist
        nxt = fp.get("nextjs", {})
        if nxt.get("detected") and not any("Next.js" in h for h in fp.get("tech_hints", [])):
            ver = nxt.get("version", "unknown")
            fp.setdefault("tech_hints", []).append(f"Next.js {ver}")
            
        if fp.get("tech_hints"):
            fp_node.add(f"[htb.yellow]Technologies:[/] {', '.join(fp['tech_hints'])}")

    node_dns = tree.add(f"[htb.cyan]Domains & VHosts[/]  {len(state.domains) + len(state.vhosts)}")
    for d in state.domains:
        node_dns.add(f"[htb.green]{d}[/]")
    for v in state.vhosts:
        node_dns.add(f"[htb.green]{v}[/]  [dim](vhost)[/]")

    node_fuzz = tree.add(f"[htb.cyan]Fuzzing[/]  {len(state.directories)} path(s)")
    for d in state.directories[:10]:
        node_fuzz.add(f"[dim]{d.get('status')}[/]  {d.get('url', '')}")
    if len(state.directories) > 10:
        node_fuzz.add(f"[dim]… and {len(state.directories) - 10} more[/]")

    node_spider = tree.add(f"[htb.cyan]Spider[/]  {len(state.spider_links)} link(s)")
    for lnk in state.spider_links[:5]:
        node_spider.add(f"[dim]{lnk}[/]")

    nuclei_out = state.workdir / "nuclei_results.txt"
    if nuclei_out.exists():
        nuclei_lines = nuclei_out.read_text().splitlines()
        if nuclei_lines:
            node_nuclei = tree.add(f"[htb.red]Nuclei[/]  {len(nuclei_lines)} issue(s)")
            for l in nuclei_lines[:5]:
                node_nuclei.add(f"[htb.red]{l}[/]")
            if len(nuclei_lines) > 5:
                node_nuclei.add(f"[dim]… and {len(nuclei_lines) - 5} more[/]")
        else:
            tree.add("[htb.cyan]Nuclei[/]  [dim]0 issue(s)[/]")

    node_exp = tree.add(f"[htb.red]Exploits[/]  {sum(len(v) for v in state.exploits.values())} hit(s)")
    for term, hits in state.exploits.items():
        for h in hits[:3]:
            node_exp.add(f"[htb.red]{h.get('Title', '')[:60]}[/]")

    node_qw = tree.add("[htb.cyan]Protocol Checks[/]")
    
    expected_checks = {
        "FTP":   "[dim]skip (port closed)[/]",
        "SSH":   "[dim]skip (port closed)[/]",
        "SMB":   "[dim]skip (port closed)[/]",
        "RPC":   "[dim]skip (port closed)[/]",
        "LDAP":  "[dim]skip (port closed)[/]",
        "WinRM": "[dim]skip (port closed)[/]",
        "NFS":   "[dim]skip (port closed)[/]"
    }

    for qw in state.quick_wins:
        svc = qw.get("service", "?")
        anon = (
            qw.get("anonymous") or
            qw.get("anonymous_bind") or
            bool(qw.get("shares")) or
            bool(qw.get("mounts")) or
            bool(qw.get("users")) or
            qw.get("responding")
        )
        badge = "[htb.green]✔  HIT[/]" if anon else "[dim]✘  denied[/]"
        expected_checks[svc] = badge

    for svc, badge in expected_checks.items():
        node_qw.add(f"{svc:<6} {badge}")

    if report_path:
        tree.add(f"[htb.cyan]Report[/]  {report_path}")

    console.print(Panel(tree, border_style="green", padding=(1, 2)))

    # Suggested next steps
    section("SUGGESTED NEXT STEPS")
    steps: list[str] = []
    port_ints = set()
    for p in state.ports:
        try:
            port_ints.add(int(p.split("/")[0]))
        except ValueError:
            pass

    if port_ints & {80, 443, 8080, 8443}:
        steps.append("Web: manual enumeration → LFI, SQLi, IDOR, auth bypass")
    if 445 in port_ints:
        steps.append("SMB: smbmap, netexec, check EternalBlue (MS17-010)")
    if 5985 in port_ints:
        steps.append("WinRM: evil-winrm with valid creds")
    if 389 in port_ints:
        steps.append("LDAP: BloodHound / ldapdomaindump for AD enumeration")
    if 21 in port_ints:
        steps.append("FTP: check anonymous upload, binary mode, bounce attack")
    for v in state.vhosts:
        steps.append(f"Enumerate vhost further: {v}")
    if state.exploits:
        steps.append("Review searchsploit results — check Metasploit / PoC")
    if state.fingerprints or state.services:
        steps.append("[bold htb.yellow]Search Google/Exploit-DB manually for CVEs affecting the detected framework versions (Searchsploit may be outdated or incomplete).[/]")
    if state.directories:
        steps.append(f"Investigate {len(state.directories)} discovered paths manually")
    
    steps.append("[bold htb.green]🎯 Pwn: Automated recon is complete. Time to get your hands dirty and pop some shells. Happy Hacking![/]")

    for i, step in enumerate(steps, 1):
        console.print(f"  [htb.magenta]{i}.[/]  {step}")

    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconthebox.py",
        description="🔍 HTB Recon Automation — v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 reconthebox.py -t 10.129.1.5 -n Meow\n"
            "  python3 reconthebox.py -t 10.10.11.230 -n CozyHosting -v\n"
            "  python3 reconthebox.py -t 10.10.10.3 --no-udp --no-proto\n"
            "  python3 reconthebox.py -t 10.10.10.3 -n WingData --wl-vhosts ~/seclists/Discovery/DNS/subdomains-top1million-110000.txt\n"
            "  python3 reconthebox.py -t 10.10.10.3 -n WingData --output-dir /tmp/recon\n"
        ),
    )
    parser.add_argument("-t",  "--target",      required=True,       help="Target IP address")
    parser.add_argument("-n",  "--name",        default=None,        help="Lab name — creates output dir")
    parser.add_argument("-v",  "--verbose",     action="store_true", help="Show full raw tool output")
    parser.add_argument("--no-udp",            action="store_true", help="Skip UDP scan")
    parser.add_argument("--no-fuzz",           action="store_true", help="Skip dir/vhost fuzzing")
    parser.add_argument("--no-exploits",       action="store_true", help="Skip searchsploit")
    parser.add_argument("--no-proto",          action="store_true", help="Skip FTP/SMB/LDAP/RPC checks")
    parser.add_argument("--wl-dirs",           default=None, metavar="PATH",
                        help="Custom wordlist for directory/file fuzzing")
    parser.add_argument("--wl-vhosts",         default=None, metavar="PATH",
                        help="Custom wordlist for vhost/subdomain fuzzing")
    parser.add_argument("--output-dir", "-o",  default=None, metavar="DIR",
                        help="Custom output directory (default: ~/htb/{NAME}/)")
    return parser.parse_args()

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = parse_args()

    if not validate_ip(args.target):
        console.print(f"[htb.red]Invalid IP address: {args.target}[/]")
        sys.exit(1)

    lab_name = args.name or "unknown"

    # Determine output directory
    if args.output_dir:
        workdir = Path(args.output_dir).expanduser().resolve()
    else:
        workdir = Path(os.path.expanduser(f"~/htb/{lab_name}"))
    workdir.mkdir(parents=True, exist_ok=True)

    # Validate custom wordlists
    wl_dirs   = None
    wl_vhosts = None
    if args.wl_dirs:
        p = Path(args.wl_dirs).expanduser()
        if p.exists():
            wl_dirs = str(p)
        else:
            warn(f"--wl-dirs path not found: {args.wl_dirs} — using default")
    if args.wl_vhosts:
        p = Path(args.wl_vhosts).expanduser()
        if p.exists():
            wl_vhosts = str(p)
        else:
            warn(f"--wl-vhosts path not found: {args.wl_vhosts} — using default")

    state_file = workdir / "state.pkl"
    state = None
    
    if state_file.exists():
        from rich.prompt import Confirm
        import pickle
        if Confirm.ask("[htb.yellow]Previous session state found. Do you want to resume?[/]", default=True):
            try:
                with open(state_file, "rb") as f:
                    state = pickle.load(f)
                info("Session state loaded successfully.")
            except Exception as e:
                err(f"Failed to load state: {e}. Starting fresh.")
                
    if not state:
        state = ReconState(
            target    = args.target,
            workdir   = workdir,
            lab       = lab_name,
            wl_dirs   = wl_dirs,
            wl_vhosts = wl_vhosts,
        )

    # Helper function to save state after phases
    def save_state():
        import pickle
        try:
            with open(state_file, "wb") as f:
                pickle.dump(state, f)
        except Exception:
            pass

    # Banner is printed in __main__ before argparse; print session panel here
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim green", width=12)
    grid.add_column(style="bold bright_green")
    grid.add_row("TARGET",  state.target)
    grid.add_row("LAB",     state.lab)
    grid.add_row("WORKDIR", str(state.workdir))
    grid.add_row("STARTED", state.started_at.strftime("%Y-%m-%d  %H:%M:%S"))
    console.print(Panel(grid, title="[dim green]◈ SESSION[/]",
                        border_style="dark_green", padding=(0, 2)))
    console.print()

    # ── Dependency Check ──────────────────────────────────────────────────────
    available = check_dependencies()

    # ── Phase 1: OS Detection ─────────────────────────────────────────────────
    detect_os_by_ttl(state)

    # ── Phase 2: Port Scanning ────────────────────────────────────────────────
    run_nmap(state, no_udp=args.no_udp)
    save_state()

    if not state.ports:
        warn("No open ports found. Exiting.")
        sys.exit(0)

    # ── Phase 3: SSL Certificate ──────────────────────────────────────────────
    port_ints = set()
    for p in state.ports:
        try:
            port_ints.add(int(p.split("/")[0]))
        except ValueError:
            pass

    if 443 in port_ints:
        section("SSL CERTIFICATE  ·  HOSTNAME EXTRACTION")
        ssl_domains = inspect_ssl(state.target, "443")
        for d in ssl_domains:
            info(f"SSL SAN/CN: {d}")
            if d not in state.domains:
                state.domains.append(d)
                state.notes.append(f"Domain from SSL cert: {d}")

    # ── Phase 4: Protocol Enumeration ─────────────────────────────────────────
    if not args.no_proto:
        run_protocol_enum(state)
        save_state()
    else:
        info("Protocol enumeration skipped (--no-proto).")

    # ── Phase 5: Web Services ─────────────────────────────────────────────────
    web_ports = get_web_ports(state)

    # Derive main domain from lab name
    main_domain: Optional[str] = None
    if args.name:
        main_domain = f"{args.name.lower()}.htb"

    if web_ports:
        section("WEB SERVICES DETECTED")
        for wp in web_ports:
            info(f"  Port {wp['port']} [{wp['scheme']}]")

        for wp in web_ports:
            scheme   = wp["scheme"]
            port     = wp["port"]
            port_str = wp["port_str"]

            url_ip = make_url(scheme, state.target, port)

            # Add main domain to /etc/hosts if not present
            if main_domain:
                section(f"/etc/hosts  ·  {main_domain}")
                add_hosts_entry(state.target, main_domain)
                if main_domain not in state.domains:
                    state.domains.append(main_domain)

            # Fingerprint via hostname if domain is known, else IP
            if main_domain:
                url_host = make_url(scheme, main_domain, port)
                section(f"WEB FINGERPRINT  ·  {url_host}")
                fp = fingerprint_web(url_host)
                state.fingerprints.append(fp)
                display_fingerprint(fp)
            else:
                section(f"WEB FINGERPRINT  ·  {url_ip}")
                fp0 = fingerprint_web(url_ip)
                state.fingerprints.append(fp0)
                display_fingerprint(fp0)

                # Detect redirect domain
                if fp0.get("redirect_domain"):
                    rd = fp0["redirect_domain"].split(":")[0]
                    if rd not in state.domains and rd != state.target:
                        state.domains.append(rd)
                        state.notes.append(f"Domain via HTTP redirect: {rd}")
                        section(f"/etc/hosts  ·  {rd}")
                        add_hosts_entry(state.target, rd)
                        
                        # Fingerprint the newly discovered domain
                        url_host = make_url(scheme, rd, port)
                        section(f"WEB FINGERPRINT  ·  {url_host}")
                        fp1 = fingerprint_web(url_host)
                        state.fingerprints.append(fp1)
                        display_fingerprint(fp1)

            # Passive spider
            spider_url = make_url(scheme, main_domain or state.target, port)
            passive_spider(spider_url, state)

            if not args.no_fuzz:
                # Directory fuzzing (on main domain or IP)
                fuzz_url = make_url(scheme, main_domain or state.target, port)
                dirs = fuzz_directories(fuzz_url, state)
                save_state()

                # Vhost fuzzing (for each web port separately)
                if main_domain:
                    domain_for_vhost = main_domain  # e.g. "meow.htb"
                    new_vhosts = fuzz_vhosts_smart(
                        state, domain_for_vhost, scheme, port
                    )
                    for vh in new_vhosts[:5]:
                        if vh not in state.vhosts:
                            state.vhosts.append(vh)
                        add_hosts_entry(state.target, vh)

                        # Fingerprint + spider + dir fuzz each vhost
                        vh_url = make_url(scheme, vh, port)

                        section(f"VHOST RECON  ·  {vh}")
                        fp_v = fingerprint_web(vh_url)
                        state.fingerprints.append(fp_v)
                        display_fingerprint(fp_v)

                        passive_spider(vh_url, state)
                        fuzz_directories(vh_url, state)

            else:
                info("Fuzzing skipped (--no-fuzz).")

            # Only fuzz first web port for efficiency; loop handles multiple ports for fingerprint
            # Comment out the break below to fuzz ALL detected web ports
            break

    # ── Phase 5.5: Nuclei ─────────────────────────────────────────────────────
    if not args.no_fuzz and shutil.which("nuclei"):
        section("NUCLEI  ·  VULNERABILITY SCAN")
        urls_file = state.workdir / "nuclei_targets.txt"
        nuclei_out = state.workdir / "nuclei_results.txt"
        
        targets = set()
        for fp in state.fingerprints:
            targets.add(fp["url"])
        for vh in state.vhosts:
            for wp in web_ports:
                targets.add(make_url(wp["scheme"], vh, wp["port"]))
                
        if targets:
            urls_file.write_text("\n".join(targets) + "\n")
            info(f"Running Nuclei on {len(targets)} target(s)...")
            cmd = [
                "nuclei", "-l", str(urls_file),
                "-tags", "cves,default-logins,exposed-panels,misconfiguration",
                "-o", str(nuclei_out),
                "-silent"
            ]
            cmd_str = " ".join(cmd)
            info(f"Running: [bold cyan]{cmd_str}[/]")
            try:
                subprocess.call(cmd)
            except KeyboardInterrupt:
                warn("Caught keyboard interrupt (Ctrl-C) during nuclei.")
            
            if nuclei_out.exists():
                lines = nuclei_out.read_text().splitlines()
                if lines:
                    ok(f"Nuclei found {len(lines)} issue(s)! Check {nuclei_out.name}")
                    for line in lines[:10]:
                        console.print(f"  [htb.crit]⚡[/] {line}")
                    state.notes.append(f"Nuclei issues found: {len(lines)}")
                else:
                    info("Nuclei found no issues.")
        else:
            info("No web targets found for Nuclei.")
            
        save_state()

    # ── Phase 6: Searchsploit ─────────────────────────────────────────────────
    if not args.no_exploits:
        # Fingerprints are already attached to state; run_searchsploit
        # reads them directly to extract frameworks (Next.js, etc.) and
        # server headers before falling back to nmap service names.
        run_searchsploit(state)
    else:
        info("Exploit search skipped (--no-exploits).")

    # ── Phase 7: Report ───────────────────────────────────────────────────────
    report_path = generate_report(state)
    print_summary(state, report_path)
    save_state()

    # ── Exploit Downloader ────────────────────────────────────────────────────
    if state.exploits and shutil.which("searchsploit"):
        console.print()
        from rich.prompt import Prompt
        edb_ids = Prompt.ask(
            "[htb.cyan]Do you want to download any exploits? (Enter EDB-ID comma-separated, or press Enter to skip)[/]",
            default=""
        ).strip()
        
        if edb_ids:
            for edb in edb_ids.split(","):
                edb = edb.strip()
                if not edb: continue
                # Searchsploit needs the clean ID (e.g. 50720)
                cmd = ["searchsploit", "-m", edb]
                info(f"Downloading exploit {edb}...")
                proc = subprocess.run(cmd, cwd=state.workdir, capture_output=True, text=True)
                if proc.returncode == 0:
                    ok(f"Exploit {edb} saved to {state.workdir}/")
                else:
                    err(f"Failed to download {edb}: {proc.stderr.strip()}")

    ok("[htb.green]Reconnaissance complete.[/]")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT  — banner printed BEFORE argparse
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Print banner before argument parsing so it always shows
    tagline = random.choice(TAGLINES)
    art = Text()
    lines = BANNER_ART.strip("\n").split("\n")
    colors = [
        "bright_green", "bright_green", "green",
        "green", "dark_green", "dark_green",
        "bright_cyan", "cyan", "cyan",
        "dark_cyan", "dark_cyan", "dark_cyan",
    ]
    for i, line in enumerate(lines):
        art.append(line + "\n", style=colors[min(i, len(colors) - 1)])
    art.append(f"\n  {tagline}\n", style="dim green")
    art.append(f"                                v{VERSION}  ·  author: x0xx0x0x\n", style="dim cyan")
    console.print(Panel(art, border_style="green", padding=(0, 1)))
    console.print()

    main()
