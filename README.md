# ReconTheBox

```text
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ████████╗██╗  ██╗███████╗ ██████╗  ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ ╚══██╔══╝██║  ██║██╔════╝ ██╔══██╗██╔═══██╗╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ███████║█████╗   ██████╔╝██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║   ██╔══██║██╔══╝   ██╔══██╗██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║   ██║  ██║███████╗ ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

**ReconTheBox** is a straightforward Python script built to do the heavy lifting of reconnaissance for your CTF and lab targets (like HackTheBox). It automates the boring enumeration stuff so you can focus on what really matters: exploiting the box and popping shells.

## What's under the hood? (English)

The script intelligently chains your favorite industry tools (`nmap`, `ffuf`, `dirsearch`, `whatweb`, `searchsploit`, `nuclei`) together. When one tool finds something juicy, it feeds it right into the next phase.

**How it attacks the target:**
1. 🐧 **OS Guessing:** Quick TTL check to see if we're dealing with Linux or Windows.
2. 🔍 **Port Scanning:** Blazing fast SYN scan + deep `-sCV` on the open ports using Nmap.
3. 🔒 **SSL Snooping:** Extracts hidden hostnames (SAN/CN) from SSL certificates.
4. 🌐 **Protocol Enum:** Checks for easy wins like FTP anonymous logins, open SMB shares, or LDAP null sessions.
5. 🌍 **Web Fingerprinting:** Hits HTTP/HTTPS ports to extract headers, tech stacks (WordPress, Laravel, etc.), and specific versions.
6. 🕷️ **Passive Spidering:** Crawls the site for hidden links and subdomains straight from the source code.
7. 👻 **VHost Fuzzing:** Smart `ffuf` runs to uncover hidden Virtual Hosts (it automatically filters out the noise).
8. 📂 **Directory Fuzzing:** Uses `dirsearch` to find hidden endpoints, returning only the clean hits.
9. 📝 **Auto `/etc/hosts`:** Automatically appends discovered domains and vhosts to your hosts file (sudo required).
10. ⚡ **Nuclei Integration:** Shoots all discovered web endpoints into `nuclei` to catch quick CVEs, default logins, and exposed panels.
11. 💥 **Exploit Lookup & Download:** Cross-references versions with Exploit-DB, shows you the table, and even prompts you to download the exploits straight to your lab folder.
12. 💾 **State Persistence:** Did your VPN drop? Don't sweat it. The script saves your state locally so you can resume without starting over.
13. 📊 **Slick Reporting:** Drops a `report.md` in your workspace and draws a beautiful tree in your terminal to review the attack surface.

## Quick Start

You'll need `python3` and the standard hacking tools installed.

```bash
python3 reconthebox.py -t <TARGET_IP> -n <LAB_NAME>
```

**Extra Flags:**
- `--no-udp`: Skip UDP scans.
- `--no-fuzz`: Skip the noisy Fuzzing phase (no VHosts or Directories).
- `--no-exploits`: Skip the `searchsploit` lookup.
- `--no-proto`: Skip FTP, SMB, and LDAP enumerations.

*Hack the box, don't scan it all day.*

---

## ¿Qué hay bajo el capó? (Español)

**ReconTheBox** es un script sencillo en Python que te ayudará a obtener información inicial de tu objetivo. Automatiza todo el proceso tedioso de enumeración de forma rápida e inteligente para que te enfoques en lo que realmente importa: la explotación y conseguir esa *reverse shell*.

El script encadena tus herramientas favoritas (`nmap`, `ffuf`, `dirsearch`, `whatweb`, `searchsploit`, `nuclei`). Si un módulo descubre algo interesante, el siguiente módulo lo aprovecha.

**Flujo de ataque:**
1. 🐧 **Detección de OS:** Análisis de TTL para saber si vamos contra Linux o Windows.
2. 🔍 **Escaneo de Puertos:** Escaneo SYN ultra-rápido seguido de un análisis profundo (`-sCV`) sobre los puertos abiertos.
3. 🔒 **Fisgoneo de SSL:** Extrae dominios ocultos (SAN/CN) directamente de los certificados SSL.
4. 🌐 **Protocolos Comunes:** Busca victorias rápidas (logins anónimos en FTP, recursos compartidos en SMB o sesiones nulas LDAP).
5. 🌍 **Web Fingerprinting:** Inspecciona puertos HTTP/HTTPS extrayendo cabeceras, tecnologías (PHP, WP) y versiones exactas.
6. 🕷️ **Passive Spidering:** Rastrea el código fuente buscando rutas expuestas y subdominios ocultos.
7. 👻 **Fuzzing de VHosts:** Descubre Virtual Hosts ocultos usando `ffuf` (con un filtro inteligente que ignora el ruido).
8. 📂 **Descubrimiento de Directorios:** Fuzzing rápido con `dirsearch` para revelar rutas ocultas, mostrando solo lo válido.
9. 📝 **Magia en `/etc/hosts`:** Añade automáticamente los dominios recién descubiertos a tu archivo hosts (requiere sudo).
10. ⚡ **Escaneo con Nuclei:** Inyecta todos los targets web descubiertos a `nuclei` para cazar CVEs, paneles expuestos y logins por defecto.
11. 💥 **Búsqueda y Descarga de Exploits:** Cruza versiones con Exploit-DB (`searchsploit`) y te permite descargar el código del exploit directo a tu carpeta.
12. 💾 **Persistencia (Pause/Resume):** ¿Se te cayó la VPN? No pasa nada. El script guarda tu progreso para que puedas reanudar la sesión sin empezar de cero.
13. 📊 **Reporte Limpio:** Genera un árbol visual en consola y consolida todo en un `report.md` directo en el directorio del laboratorio.

## Uso Básico

Solo necesitas `python3` y las dependencias típicas de hacking.

```bash
python3 reconthebox.py -t <IP_DEL_TARGET> -n <NOMBRE_LAB>
```

**Banderas Extra:**
- `--no-udp`: Omite los puertos UDP.
- `--no-fuzz`: Omite la fase ruidosa de Fuzzing (VHosts y Directorios).
- `--no-exploits`: Salta la consulta automática a `searchsploit`.
- `--no-proto`: Salta la enumeración de protocolos (FTP, SMB, LDAP).

*Hackea la máquina, no te pases el día escaneando.*
