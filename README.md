# ReconTheBox

```text
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗██╗  ██╗███████╗    ██████╗  ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔═══██╗╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ███████║█████╗      ██████╔╝██║   ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██╔══██║██╔══╝      ██╔══██╗██║   ██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ██║  ██║███████╗    ██████╔╝╚██████╔╝██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

**ReconTheBox** es una herramienta automatizada de enumeración exhaustiva diseñada específicamente para entornos de laboratorio y CTFs (como HackTheBox). Se encarga de hacer todo el trabajo inicial de escaneo, descubrimiento de rutas, enumeración de protocolos y búsqueda de exploits en cuestión de minutos, dejándote el panorama completamente limpio y preparado para enfocarte directamente en la explotación.

## ¿Qué hace y qué cubre?

El script orquesta múltiples herramientas estándar de la industria (`nmap`, `ffuf`, `dirsearch`, `whatweb`, `searchsploit`, etc.) de forma inteligente y encadenada. Si un módulo descubre nueva información, los siguientes módulos la utilizarán.

**Fases de ejecución:**
1. 🐧 **Detección de OS:** Realiza análisis de TTL (Time-To-Live) para identificar si estás frente a un entorno Linux o Windows.
2. 🔍 **Escaneo de Puertos (Nmap):** Ejecuta un escaneo SYN ultra-rápido de todos los puertos seguido de un análisis profundo de servicios y scripts (`-sCV`) sobre los puertos abiertos.
3. 🔒 **Certificados SSL:** Extrae nombres de dominios alternativos (SAN/CN) desde los certificados SSL encontrados en puertos seguros.
4. 🌐 **Protocolos Comunes:** Enumera silenciosamente configuraciones erróneas en protocolos como FTP (anonymous login), SMB (recursos compartidos/null sessions) y LDAP.
5. 🌍 **Web Fingerprinting:** Inspecciona los puertos HTTP/HTTPS descubiertos. Extrae cabeceras, tecnologías (PHP, Laravel, WordPress, etc.), y versiones exactas navegando dinámicamente.
6. 🕷️ **Passive Spidering:** Rastrea las páginas principales buscando rutas expuestas y subdominios ocultos directamente en el código fuente.
7. 👻 **Fuzzing de VHosts (FFUF):** Descubre Virtual Hosts ocultos utilizando `ffuf` de forma silenciosa, filtrando inteligentemente las variaciones de tamaño para evitar falsos positivos.
8. 📂 **Descubrimiento de Directorios (Dirsearch):** Ejecuta un fuzzing rápido para revelar rutas ocultas, devolviendo únicamente resultados válidos y limpios (sin ruido).
9. 📝 **Gestión Automática del `/etc/hosts`:** Añade automáticamente al archivo `hosts` los dominios y subdominios recién descubiertos (requiere contraseña de sudo).
10. ⚡ **Búsqueda de Exploits (Searchsploit):** Cruza las versiones tecnológicas extraídas (tanto de Nmap como del código fuente HTML) y busca inmediatamente vectores públicos y CVEs en la base de datos de Exploit-DB.
11. 📊 **Reporte Markdown:** Genera un árbol visual en consola y consolida todos los hallazgos en un informe `report.md` guardado en el directorio de trabajo del laboratorio.

## Uso Básico

El script requiere `python3` y las dependencias (listadas al ejecutar).

```bash
python3 reconthebox.py -t <IP_DEL_TARGET> -n <NOMBRE_LAB>
```

**Opciones adicionales:**
- `--no-udp`: Omite el escaneo de puertos UDP.
- `--no-fuzz`: Omite la fase agresiva de Fuzzing (VHosts y Directorios).
- `--no-exploits`: Salta la consulta automática a `searchsploit`.
- `--no-proto`: Salta la enumeración de protocolos auxiliares (FTP, SMB, LDAP).

*Creado para hacer que los CTF vuelvan a enfocarse en hackear, no en escanear.*
