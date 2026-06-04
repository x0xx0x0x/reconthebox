# 🔍 reconthebox

> **Automated initial reconnaissance for [HackTheBox](https://www.hackthebox.com/) labs.**  
> Cut the repetitive setup — focus on what matters.

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

---

## ⚠️ Ethical Use Notice

> **This tool is designed exclusively for use in [HackTheBox](https://www.hackthebox.com/) lab environments and other authorized CTF/training platforms.**
>
> Running this script against systems you do not own or have **explicit written permission** to test is **illegal** and **unethical**. The author takes no responsibility for misuse. Always hack responsibly.

---

## What is this?

`reconthebox.py` is a Python automation script that handles the **initial reconnaissance phase** of a HackTheBox machine. Every lab starts the same way — port scan, check for web services, enumerate directories, hunt for subdomains, fingerprint technologies — and this script does all of that for you in a single run, with clean and readable output.

No more copy-pasting nmap commands. No more manually checking `/etc/hosts`. No more switching between five tools to get basic recon done.

---

## What it does

| Step | What happens |
|------|-------------|
| 🖥️ **OS Detection** | Guesses the OS (Linux / Windows) by analyzing the TTL from a ping response |
| 🔌 **Port Scanning** | Fast full TCP SYN scan (`-p-`) followed by version + script detection on open ports. Optional UDP top-100 scan |
| 🌐 **Web Detection** | Identifies HTTP/HTTPS ports and checks if the machine hostname (`NAME.htb`) is already in `/etc/hosts` — adds it automatically if not |
| 🔬 **Tech Fingerprinting** | Runs `whatweb` against the target to identify frameworks, CMS, server versions, and more |
| 🕷️ **Passive Spidering** | Fetches the root page and extracts all internal links (`href`, `src`, `action`) to map the app surface |
| 📂 **Directory Enumeration** | Runs `dirsearch` to find exposed files and directories. Only shows positive hits (200, 301, 403, 401...) |
| 🏷️ **Vhost / Subdomain Enum** | Uses `ffuf` and `gobuster` with dynamic baseline filtering to discover virtual hosts. Caps output to avoid noise |
| ➕ **Auto /etc/hosts** | Automatically adds discovered vhosts to `/etc/hosts` (up to 2) via `sudo tee` |
| 🔐 **Protocol Enumeration** | On common ports, tests for anonymous/null sessions: FTP anon login, SMB null session + share listing, LDAP anonymous bind, RPC null session, WinRM availability |
| 🔎 **Exploit Search** | Runs `searchsploit` against all detected product versions to surface known CVEs and exploits |
| 📋 **Summary** | Prints a final table with all discovered versions, vhosts, exploits, and suggested next steps |

---

## Requirements

### Tools (must be installed)

| Tool | Install |
|------|---------|
| `nmap` | `sudo apt install nmap` |
| `dirsearch` | `sudo apt install dirsearch` |
| `gobuster` | `sudo apt install gobuster` |
| `ffuf` | `sudo apt install ffuf` |
| `whatweb` | `sudo apt install whatweb` |
| `searchsploit` | `sudo apt install exploitdb` |
| `curl` | `sudo apt install curl` |

### Optional (used when available)

| Tool | Used for |
|------|----------|
| `smbclient` | SMB share enumeration |
| `enum4linux` / `enum4linux-ng` | SMB user/group enumeration |
| `rpcclient` | RPC null session testing |
| `ldapsearch` | LDAP anonymous bind |

> The script checks for each tool at startup and warns you about anything missing — it won't crash, it just skips what it can't find.

### Wordlists

Expected at `~/seclists/` (from [SecLists](https://github.com/danielmiessler/SecLists)).  
Falls back to `/usr/share/seclists/` and `/usr/share/wordlists/` if not found.

```bash
git clone https://github.com/danielmiessler/SecLists.git ~/seclists
```

---

## Usage

```bash
# Basic scan
python3 reconthebox.py -t 10.129.13.12

# With lab name (creates ~/htb/Meow/ directory)
python3 reconthebox.py -t 10.129.13.12 -n Meow

# Verbose mode (shows raw tool output)
python3 reconthebox.py -t 10.129.13.12 -n Meow -v

# Skip UDP scan (much faster)
python3 reconthebox.py -t 10.129.13.12 -n Meow --no-udp

# Skip protocol enumeration (FTP/SMB/LDAP/RPC)
python3 reconthebox.py -t 10.129.13.12 -n Meow --no-proto

# Skip exploit search
python3 reconthebox.py -t 10.129.13.12 -n Meow --no-exploits
```

### All flags

```
  -t, --target      Target IP address (required)
  -n, --name        Lab name — creates ~/htb/{NAME}/ output directory
  -v, --verbose     Show full raw output from every tool
  --no-udp          Skip UDP scan (faster runs)
  --no-proto        Skip FTP / SMB / LDAP / RPC / WinRM checks
  --no-exploits     Skip searchsploit CVE lookup
```

---

## Output structure

The script produces color-coded, structured output split into clearly labeled sections:

```
═══════════════════════════════════════════
║  PORT SCAN
═══════════════════════════════════════════

  ┌──────────┬────────┬──────────────────────┬──────────────────────────┐
  │ PORT     │ PROTO  │ SERVICE              │ VERSION                  │
  ├──────────┼────────┼──────────────────────┼──────────────────────────┤
  │ 22       │ tcp    │ ssh                  │ OpenSSH 8.9p1 Ubuntu     │
  │ 80       │ tcp    │ http                 │ Apache httpd 2.4.52      │
  └──────────┴────────┴──────────────────────┴──────────────────────────┘

═══════════════════════════════════════════
║  RECONNAISSANCE SUMMARY
═══════════════════════════════════════════

  ╔══════════════════════════════════════╗
  ║  TARGET SUMMARY — HackTheBox Recon  ║
  ╠══════════════════════════════════════╣
  ║  IP Target          10.129.13.12    ║
  ║  Hostname           meow.htb        ║
  ║  OS Guess           Linux/Unix      ║
  ║  Open Ports         2               ║
  ╚══════════════════════════════════════╝
```

---

## Paths & conventions

| Path | Purpose |
|------|---------|
| `~/htb/{NAME}/` | Output directory per lab (created with `-n`) |
| `~/seclists/` | SecLists wordlist root |
| `~/hacktools/impacket/examples/` | Impacket scripts location |
| `/etc/hosts` | Auto-updated with `NAME.htb` and discovered vhosts |

---

## Author

**x0xx0x0x**  
Built for personal use in HackTheBox labs. Shared as-is for the community.

> _"Automate the boring parts. Think about the interesting ones."_

---

## License

This project is released for **educational and ethical hacking purposes only**, strictly within authorized environments such as HackTheBox, TryHackMe, or your own lab infrastructure.

**Do not use this tool against systems you do not have explicit permission to test.**
