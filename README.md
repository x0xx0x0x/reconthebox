# ReconTheBox

```text
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ████████╗██╗  ██╗███████╗ ██████╗  ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ ╚══██╔══╝██║  ██║██╔════╝ ██╔══██╗██╔═══██╗╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ███████║█████╗   ██████╔╝██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║   ██╔══██║██╔══╝   ██╔══██╗██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║   ██║  ██║███████╗ ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

[ EN | ES ]

## [ EN ]

**Philosophy**  
Recon is the backbone of any engagement, but doing the exact same initial enumeration on every CTF or HTB machine is repetitive noise. ReconTheBox is built to automate the boilerplate—silently and efficiently—so you can drop the scanner and get back to the actual hacking: finding the RCE, abusing the logic flaws, and popping shells. It's built by and for the community to keep the focus on exploitation.

**Scan Phases**
1. 🐧 **OS Fingerprinting:** TTL analysis for rapid OS detection.
2. 🔍 **Port Sweeping:** Aggressive SYN sweeps hooked into surgical `-sCV` probes.
3. 🌐 **Web Fingerprinting:** Deep DOM parsing, HTTP header extraction, and regex matching to unmask framework versions (Next.js, React, Laravel).
4. 🕸️ **Passive Spidering:** Silent crawling. Prioritizes `.js` chunks to extract hidden API routes and framework data directly from the source code.
5. 👻 **Dynamic Fuzzing:** Hands-off `ffuf` integration. Auto-calibrates filters to kill false positives on the fly while fuzzing VHosts and directories.
6. 📝 **Auto-Routing:** Dynamically maps discovered domains to your `/etc/hosts`.
7. ⚡ **Nuclei & Searchsploit:** Cross-references open ports and exact tech versions against Exploit-DB and Nuclei templates to map your attack vectors instantly.
8. 💾 **State Resilience:** Drops connection? No problem. State is saved locally so you can resume exactly where the process died.

**Usage**
```bash
python3 reconthebox.py -t <TARGET_IP> -n <MACHINE_NAME>
```

**Flags**
- `--no-udp`: Skip UDP sweeps.
- `--no-fuzz`: Skip VHost and directory Fuzzing.
- `--no-exploits`: Skip local `searchsploit` lookups.
- `--no-proto`: Skip FTP, SMB, and LDAP targeted checks.

> **Automate repetitive recon. Focus on pwn the box. Happy Hacking!**

---

## [ ES ]

**Filosofía**  
El recon es la columna vertebral de cualquier auditoría, pero repetir la misma enumeración inicial en cada máquina de HTB o CTF es ruido puro. ReconTheBox nace para automatizar ese trabajo repetitivo de forma silenciosa y eficiente para que dejes el escáner de lado y te enfoques en el hacking real: buscar el RCE, abusar de fallos lógicos y conseguir shells. Es un aporte para la comunidad, diseñado para mantener el foco en la explotación.

**Fases del Scan**
1. 🐧 **OS Fingerprinting:** Análisis de TTL para detección rápida del sistema operativo.
2. 🔍 **Port Sweeping:** Escaneos SYN agresivos encadenados a sondeos `-sCV` quirúrgicos.
3. 🌐 **Web Fingerprinting:** Parsing profundo del DOM, extracción de headers e inyección de regex para desenmascarar versiones de frameworks (Next.js, React, Laravel).
4. 🕸️ **Passive Spidering:** Crawling silencioso. Prioriza chunks `.js` para extraer rutas de API ocultas y data de frameworks directo del source code.
5. 👻 **Dynamic Fuzzing:** Integración limpia con `ffuf`. Auto-calibra filtros on-the-fly para matar falsos positivos al buscar VHosts y directorios.
6. 📝 **Auto-Enrutamiento:** Mapea dinámicamente los dominios descubiertos a tu `/etc/hosts`.
7. ⚡ **Nuclei & Searchsploit:** Cruza puertos y versiones exactas con Exploit-DB y plantillas de Nuclei para trazar tus vectores de ataque al instante.
8. 💾 **State Resilience:** ¿Se cae la VPN? El estado se guarda localmente para reanudar justo donde murió el proceso.

**Uso**
```bash
python3 reconthebox.py -t <IP_OBJETIVO> -n <NOMBRE_MAQUINA>
```

**Flags**
- `--no-udp`: Omite sweeps por UDP.
- `--no-fuzz`: Omite el Fuzzing de VHosts y directorios.
- `--no-exploits`: Salta las consultas locales a `searchsploit`.
- `--no-proto`: Salta los checks directos a FTP, SMB y LDAP.

> **Automatiza el recon repetitivo. Enfócate en pwnear la máquina. Happy Hacking!**
