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
import shutil
import socket
import subprocess
import sys
import time
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
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗██╗  ██╗███████╗    ██████╗  ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔═══██╗╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ███████║█████╗      ██████╔╝██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██╔══██║██╔══╝      ██╔══██╗██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ██║  ██║███████╗    ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝"""

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

    # Print full command before starting
    cmd_str = " ".join(cmd)
    console.print(f"  [dim green]►[/] [dim]{cmd_str}[/]")

    # Count wordlist for progress
    total_lines = _wordlist_size(wordlist_path) if wordlist_path else 0
    lines_seen  = 0

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="htb.green"),
        TextColumn("[htb.dim]{task.description}"),
        BarColumn(bar_width=None, style="dark_green", complete_style="htb.green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        expand=True,
    ) as progress:
        cmd_str = " ".join(cmd)
        task_id = progress.add_task(
            label,
            total=total_lines if total_lines > 0 else None,
        )
        progress.update(task_id, description=f"{label} [dim]({cmd_str})[/]")

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
                    if verbose or (line_filter and line_filter(line)):
                        console.print(f"    [dim]{line}[/]")
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
    info("Running: " + " ".join(cmd))

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
    info("Running: " + " ".join(cmd))

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
    info("Running: " + " ".join(cmd))
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

        # Extract version for Wing FTP Server
        if "Wing FTP Server" in fp["server"]:
            try:
                r2 = requests.get(url.rstrip("/") + "/login.html", timeout=HTTP_TIMEOUT, verify=False)
                ver_m = re.search(r'Wing FTP Server v([0-9\.]+)', r2.text, re.I)
                if ver_m:
                    fp["server"] = f"Wing FTP Server/{ver_m.group(1)}"
            except Exception:
                pass

        hints = []
        for cname in fp["cookies"]:
            if "PHPSESSID"  in cname: hints.append("PHP")
            if "JSESSIONID" in cname: hints.append("Java/Tomcat")
            if "ASP.NET"    in cname: hints.append("ASP.NET")
            if "laravel"    in cname.lower(): hints.append("Laravel")
            if "wordpress"  in cname.lower(): hints.append("WordPress")
        fp["tech_hints"] = list(set(hints))

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
    t.add_column(style="dim green", width=16)
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
        transient=False,
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

            # Depth-0: root
            for m in _LINK_RE.finditer(body):
                process_href(m.group(1))

            # Depth-1: follow relative links that look like pages
            depth1_targets = [h for h in list(links)[:15] if h.startswith("/")]
            for path in depth1_targets:
                sub_url = url.rstrip("/") + path
                try:
                    progress.update(t, description=f"spidering {path}")
                    r2 = requests.get(sub_url, timeout=8, verify=False, allow_redirects=True)
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

        cmd_str = " ".join(cmd)
        info(f"Running: [bold cyan]{cmd_str}[/]")

        try:
            subprocess.call(cmd)
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
        
        cmd_str = " ".join(cmd)
        info(f"Running: [bold cyan]{cmd_str}[/]")

        try:
            subprocess.call(cmd)
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
        
    cmd = [
        "ffuf", "-c", "-s",
        "-u", url,
        "-w", wordlist,
        "-H", f"Host:FUZZ.{domain}",
        "-mc", "200",
        "-o", out_json,
        "-of", "json"
    ]

    cmd_str = " ".join(cmd)
    info(f"Running: [bold cyan]{cmd_str}[/]")
    
    # Run ffuf natively to display its real-time progress bar and banner directly
    try:
        subprocess.call(cmd)
    except KeyboardInterrupt:
        warn("Caught keyboard interrupt (Ctrl-C) during ffuf.")
    except Exception as exc:
        err(f"ffuf error: {exc}")

    # Parse JSON output for results
    if os.path.exists(out_json):
        try:
            with open(out_json, "r") as f:
                data = json.load(f)
                for res in data.get("results", []):
                    sub = res.get("host", "").split(".")[0]
                    vhost = f"{sub}.{domain}"
                    if vhost not in found_set:
                        found_set.add(vhost)
                        ok(f"FFUF VHOST FOUND: [bold white]{vhost}[/]  [{res.get('status')}]")
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
    if not state.services:
        info("No services to query.")
        return

    for svc in state.services:
        # Focus on web technologies
        svc_name_lower = svc["service"].lower()
        if "http" not in svc_name_lower and "web" not in svc_name_lower and "apache" not in svc_name_lower and "nginx" not in svc_name_lower and "ftp" not in svc_name_lower:
            continue
            
        ver_parts = svc.get("version", "").split()
        terms = []
        if ver_parts:
            terms.append(f"{svc['service']} {ver_parts[0]}")
        terms.append(svc["service"])
        
        for term in terms:
            info(f"Querying: {term}")
            hits = searchsploit_lookup(term)
            if hits:
                state.exploits[term] = hits[:10]
                t = Table(
                    title=f"[htb.red]⚡ Exploits → {term}[/]",
                    box=box.SIMPLE_HEAD, border_style="red",
                )
                t.add_column("Title", style="bold white", max_width=55)
                t.add_column("Type",  style="htb.yellow", width=14)
                t.add_column("Path",  style="dim",        max_width=35)
                for h in hits[:8]:
                    t.add_row(h.get("Title", ""), h.get("Type", ""), h.get("Path", ""))
                console.print(t)
                break
            else:
                info(f"No results for: {term}")

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

    lines += ["", "## 6. Potential Exploits (Searchsploit)", ""]
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

    lines += [
        "## 9. Raw Nmap (Services Scan)",
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
        node_web.add(f"[dim]{fp.get('url', '')}[/]  → {fp.get('title', '') or fp.get('server', '')}")

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

    node_exp = tree.add(f"[htb.red]Exploits[/]  {sum(len(v) for v in state.exploits.values())} hit(s)")
    for term, hits in state.exploits.items():
        for h in hits[:3]:
            node_exp.add(f"[htb.red]{h.get('Title', '')[:60]}[/]")

    node_qw = tree.add("[htb.cyan]Protocol Checks[/]")
    for qw in state.quick_wins:
        anon = (
            qw.get("anonymous") or
            qw.get("anonymous_bind") or
            bool(qw.get("shares")) or
            bool(qw.get("mounts")) or
            qw.get("responding")
        )
        badge = "[htb.green]✔  HIT[/]" if anon else "[dim]✘  denied[/]"
        node_qw.add(f"{qw.get('service', '?')}  {badge}")

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

    if 22 in port_ints:
        steps.append("SSH: try default creds / key-based auth / user enum")
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
    if state.directories:
        steps.append(f"Investigate {len(state.directories)} discovered paths manually")

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

    state = ReconState(
        target    = args.target,
        workdir   = workdir,
        lab       = lab_name,
        wl_dirs   = wl_dirs,
        wl_vhosts = wl_vhosts,
    )

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

            # Fingerprint via IP
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

            # Fingerprint via hostname
            if main_domain:
                url_host = make_url(scheme, main_domain, port)
                if url_host != url_ip:
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

    # ── Phase 6: Searchsploit ─────────────────────────────────────────────────
    if not args.no_exploits:
        # Extract technologies from web fingerprints to query searchsploit
        for fp in state.fingerprints:
            for key in ["server", "x_powered_by"]:
                val = fp.get(key)
                if val:
                    # Clean up common noise like "(Debian)" or "(Free Edition)"
                    clean_val = re.sub(r'\(.*?\)', '', val).strip()
                    # If it has a version like "Apache/2.4.66", split it
                    parts = clean_val.split("/")
                    svc_name = parts[0].strip()
                    svc_ver = parts[1].strip() if len(parts) > 1 else ""
                    
                    # Avoid duplicates
                    if not any(s["service"].lower() == svc_name.lower() for s in state.services):
                        state.services.append({
                            "port": "web",
                            "service": svc_name,
                            "version": svc_ver
                        })
                        
        run_searchsploit(state)
    else:
        info("Exploit search skipped (--no-exploits).")

    # ── Phase 7: Report ───────────────────────────────────────────────────────
    report_path = generate_report(state)
    print_summary(state, report_path)

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
