#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                                                                          ║
# ║   ⚔️  12ak_H4ck Tools — Agent de Surveillance v6.0  🛡️                  ║
# ║                                                                          ║
# ║   MODULE : Agent Windows/Linux — Endpoint Detection & Response           ║
# ║   AUTEUR : 12ak_H4ck                                                     ║
# ║                                                                          ║
# ║   INSTALLATION :                                                         ║
# ║     pip install psutil requests colorama websockets                      ║
# ║                                                                          ║
# ║   LANCEMENT :                                                            ║
# ║     python agent_v5.py                                                   ║
# ║   (Lancer en Administrateur pour le KILL et l'IPS complets)              ║
# ║                                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import os, sys, json, time, threading, datetime, socket, ipaddress
import platform, subprocess, collections, re, hashlib, asyncio, stat

# ─── Dépendances externes ──────────────────────────────────────────────────

try:
    import psutil
except ImportError:
    print("[!] pip install psutil"); sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

try:
    import websockets
    WS_OK = True
except ImportError:
    WS_OK = False
    print("[!] websockets manquant — pip install websockets (KILL distant désactivé)")

try:
    from colorama import Fore, Style, init as ci; ci(autoreset=True)
    R=Fore.RED; Y=Fore.YELLOW; G=Fore.GREEN; C=Fore.CYAN
    M=Fore.MAGENTA; RST=Style.RESET_ALL; BLD=Style.BRIGHT
except ImportError:
    R=Y=G=C=M=RST=BLD=""

# ══════════════════════════════════════════════════════════════════════
#  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗
#  ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝
#  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
#  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
#  ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
#   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝
# ══════════════════════════════════════════════════════════════════════

# ─── Serveur Central ──────────────────────────────────────────────────────
SERVER_IP   = "54.147.128.163"   # ← IP de ton serveur EC2 (à modifier si changement)
SERVER_PORT = 9999               # Port HTTP agents → serveur
WS_PORT     = 9998               # Port WebSocket (ordres serveur → agent)
AGENT_NAME  = socket.gethostname()
SERVER_URL  = f"http://{SERVER_IP}:{SERVER_PORT}"

# ─── Telegram (optionnel — alertes CRITICAL) ──────────────────────────────
# Mettre TELEGRAM_ENABLED = True et remplir le token/chat_id pour activer
TELEGRAM_ENABLED = False
TELEGRAM_TOKEN   = ""            # ← Ton token BotFather
TELEGRAM_CHAT_ID = ""            # ← Ton chat_id

# ─── Intervalles de scan (secondes) ──────────────────────────────────────
INTERVAL_SYSINFO  = 5    # CPU / RAM / Disk
INTERVAL_PROCS    = 5    # Processus actifs
INTERVAL_NETWORK  = 3    # Connexions réseau
INTERVAL_FILES    = 10   # Fichiers utilisateur (Downloads, Desktop, Documents)
INTERVAL_SYS_FILES = 300 # Fichiers système (toutes les 5 min)
INTERVAL_PS_AUDIT = 60   # Audit PowerShell Event Log

# ─── Throttle alertes : une même alerte max toutes les 30s ───────────────
ALERT_THROTTLE_SEC = 30

# ══════════════════════════════════════════════════════════════════════
#  WHITELIST — Notre infrastructure, jamais bloquée/alertée
# ══════════════════════════════════════════════════════════════════════

# IPs qui ne seront JAMAIS bloquées ni signalées comme suspectes
WHITELIST_IPS = {
    SERVER_IP,           # Serveur EC2
    "127.0.0.1",
    "::1",
}

# Ports de notre infrastructure — pas d'alerte sur ces ports
WHITELIST_PORTS = {
    SERVER_PORT,  # 9999  HTTP agents
    WS_PORT,      # 9998  WebSocket
    31337,        # Dashboard
    80, 443,      # HTTP/HTTPS standard
    53,           # DNS
    123,          # NTP
    67, 68,       # DHCP
}

# ══════════════════════════════════════════════════════════════════════
#  PORTS SUSPECTS — Signatures d'outils offensifs connus
# ══════════════════════════════════════════════════════════════════════

SUSPECT_PORTS = {
    # ── Metasploit / Meterpreter ──
    4444, 4445, 4446, 4447,      # Meterpreter défaut
    4443,                         # HTTPS reverse shell
    # ── C2 / RAT communs ──
    1337, 31338,                  # Hacker culture / ancien 31337 retiré (dashboard)
    5555, 6666, 7777, 8888,
    9001, 9002,                   # Tor / C2
    9090,                         # Cobalt Strike Beacon HTTP
    # ── Outils offensifs ──
    4000, 1234, 12345, 54321,
    2222,                         # SSH alternatif (pivot)
    6667, 6668,                   # IRC (C2 legacy)
    3333, 11211,                  # Memcached exploit
    50050,                        # Cobalt Strike Team Server
    # ── Proxies / TOR ──
    1080,                         # SOCKS proxy
    3128, 8118,                   # HTTP proxy (Squid/Privoxy)
    9050, 9051,                   # TOR
    # ── VNC (prise de contrôle) ──
    5900, 5901, 5902,
    # ── Empire / PowerShell C2 ──
    8443,                         # Empire HTTPS
    # ── Shells web connus ──
    1177,
}

# ══════════════════════════════════════════════════════════════════════
#  SIGNATURES METASPLOIT / PAYLOAD — Détection sans AV
# ══════════════════════════════════════════════════════════════════════

# Noms de processus malveillants connus
SUSPECT_PROC_NAMES = {
    # ── Credential Dumping ──
    "mimikatz", "wce", "fgdump", "pwdump", "lazagne",
    "gsecdump", "cachedump", "lsadump",
    # ── Post-exploitation ──
    "meterpreter", "cobaltstrike", "beacon",
    "empire", "metasploit", "msf",
    # ── Recon / Scan ──
    "nmap", "masscan", "zmap",
    # ── Lateral movement ──
    "psexec", "psexecsvc", "wmiexec", "smbexec",
    # ── Shells ──
    "nc", "ncat", "netcat", "pwncat",
    # ── Enumération AD ──
    "sharphound", "bloodhound", "adfind",
    # ── Privilege escalation ──
    "winpeas", "linpeas", "getsystem",
    "rubeus", "certify", "seatbelt",
    # ── Dumping outils ──
    "procdump", "taskdump",
    # ── Loaders / Injectors ──
    "donut", "srum", "hollows_hunter",
}

# Patterns PowerShell / CMD malveillants (regex)
PS_PATTERNS = [

    # ── Obfuscation / Encodage ────────────────────────────────────────
    (r'-enc\s+[A-Za-z0-9+/=]{20,}',             "PS_ENCODED_CMD"),
    (r'-encodedcommand\s',                        "PS_ENCODED_CMD"),
    (r'[A-Za-z0-9+/]{150,}={0,2}',               "BASE64_LONGUE"),
    # Obfuscation char codes : [char]73+[char]69 = IE...
    (r'\[char\]\d+\s*[+,]\s*\[char\]\d+',        "CHAR_OBFUSCATION"),
    # Obfuscation env : $env:comspec[4,15,25]-join
    (r'\$env:[a-z]+\[\d+',                        "ENV_OBFUSCATION"),
    # Reverse string : -join('abc'[5..0])
    (r'-join.*\[\d+\.\.-?\d+\]',                  "REVERSE_STRING"),
    # Tick obfuscation : i`e`x
    (r'[a-z]`[a-z]`[a-z]',                        "TICK_OBFUSCATION"),
    # ScriptBlock::Create pour contourner la détection
    (r'\[scriptblock\]::create',                   "SCRIPTBLOCK_CREATE"),

    # ── Commande dangereuse classique ─────────────────────────────────
    # PowerShell -ExecutionPolicy Bypass -WindowStyle Hidden -Command
    (r'-executionpolicy\s+bypass',                 "EXECPOLICY_BYPASS"),
    (r'-ep\s+bypass',                              "EXECPOLICY_BYPASS"),
    (r'(-windowstyle|-w)\s+hid',                   "HIDDEN_WINDOW"),
    (r'-noprofile\s.*-noninteractive',              "STEALTH_LAUNCH"),
    (r'-nop\s.*-w\s+h',                            "STEALTH_LAUNCH"),
    # Combinaison complète la plus utilisée par les payloads
    (r'powershell.*-ep\s+bypass.*-w.*hid',         "PAYLOAD_CLASSIC"),
    (r'powershell.*bypass.*hidden.*command',        "PAYLOAD_CLASSIC"),

    # ── Download & Execute ────────────────────────────────────────────
    (r'(iex|invoke-expression)\s*[\(\$\[]',        "IEX_EXEC"),
    (r'downloadstring\s*\(',                        "DOWNLOAD_EXEC"),
    (r'downloadfile\s*\(',                          "DOWNLOAD_FILE"),
    (r'(invoke-webrequest|iwr)\s+.*http',           "DOWNLOAD_HTTP"),
    (r'(webclient|webrequest).*http',               "DOWNLOAD_HTTP"),
    (r'net\.webclient',                             "WEBCLIENT"),
    (r'start-bitstransfer',                         "BITS_TRANSFER"),

    # ── LOLBins — Living off the Land Binaries ────────────────────────
    # certutil : décode base64 ou télécharge des fichiers
    (r'certutil.*(-decode|-urlcache|-f\s+http)',    "CERTUTIL_LOLBIN"),
    # mshta : exécute HTA scripts depuis internet
    (r'mshta\s+(http|javascript|vbscript)',         "MSHTA_LOLBIN"),
    # regsvr32 Squiblydoo : contourne AppLocker
    (r'regsvr32.*(/s|/i).*http',                   "REGSVR32_LOLBIN"),
    # wmic : exécution distante ou XSL transform
    (r'wmic.*process.*call.*create',               "WMIC_EXEC"),
    (r'wmic.*os.*get.*/format.*http',              "WMIC_XSL"),
    # rundll32 : exécute JS ou DLL distante
    (r'rundll32.*javascript:',                      "RUNDLL32_JS"),
    (r'rundll32.*http',                             "RUNDLL32_REMOTE"),
    # msiexec : installe MSI depuis internet
    (r'msiexec.*/i\s+http',                        "MSIEXEC_REMOTE"),
    # bitsadmin : téléchargement discret en arrière-plan
    (r'bitsadmin.*/transfer',                       "BITSADMIN_LOLBIN"),
    # cscript/wscript : exécute des scripts VBS/JS
    (r'(cscript|wscript).*http',                    "SCRIPT_REMOTE"),
    # forfiles, pcalua, cmstp : bypass AppLocker
    (r'forfiles.*/c.*cmd',                          "FORFILES_LOLBIN"),
    (r'cmstp.*/ni.*/s.*http',                       "CMSTP_LOLBIN"),

    # ── AMSI Bypass ───────────────────────────────────────────────────
    (r'amsicontext|amsiinitfailed',                 "AMSI_BYPASS"),
    (r'amsi.*utils',                                "AMSI_BYPASS"),
    (r'amsiscanbuffer',                             "AMSI_PATCH"),
    (r'system\.management\.automation\.amsi',       "AMSI_BYPASS"),
    (r'\[runtime\.interopservices\.marshal\].*copy',"AMSI_PATCH"),
    # Patch AMSI via réflexion
    (r'getfield.*amsiinitfailed',                   "AMSI_REFLECTION"),

    # ── Injection mémoire / Shellcode ────────────────────────────────
    (r'virtualalloc',                               "VIRTUALALLOC"),
    (r'writeprocessmemory',                         "PROCESS_INJECT"),
    (r'createremotethread',                         "REMOTE_THREAD"),
    (r'ntcreatethread|ntcreatethreadex',            "NT_INJECT"),
    (r'\[system\.runtime\.interopservices',         "PINVOKE_INJECT"),
    # Add-Type avec TypeDefinition = P/Invoke pour appels Win32
    (r'add-type.*-typedefinition',                  "PINVOKE_ADDTYPE"),
    (r'getprocaddress|loadlibrary',                 "API_RESOLVE"),
    # Allocation mémoire RWX (Read-Write-Execute) = shellcode
    (r'virtualalloc.*0x40|virtualalloc.*rwx',       "RWX_ALLOC"),

    # ── Persistence ───────────────────────────────────────────────────
    (r'currentversion.run',                         "REGISTRY_PERSIST"),
    (r'new-itemproperty.*run',                      "REGISTRY_PERSIST"),
    (r'schtasks.*/create',                          "SCHTASK_PERSIST"),
    (r'new-scheduledtask',                          "SCHTASK_PERSIST"),
    # Startup folder
    (r'startup.*\.lnk|\.lnk.*startup',             "STARTUP_PERSIST"),

    # ── Désactivation défenses ────────────────────────────────────────
    (r'set-mppreference.*disabl',                   "DEFENDER_DISABLE"),
    (r'add-mppreference.*exclusion',                "DEFENDER_EXCLUSION"),
    (r'sc\s+(stop|delete)\s+windefend',             "WINDEFEND_STOP"),
    (r'netsh.*advfirewall.*off',                    "FIREWALL_DISABLE"),
    (r'disableantispyware|disableav',               "AV_DISABLE"),
    # Suppression des logs Event Log
    (r'clear-eventlog|wevtutil.*cl',                "EVENTLOG_CLEAR"),

    # ── Credential Dumping ────────────────────────────────────────────
    (r'invoke-mimikatz',                            "MIMIKATZ_PS"),
    (r'sekurlsa|kerberos::ptt',                     "MIMIKATZ_CMD"),
    (r'(lsadump|dpapi)::',                          "MIMIKATZ_MODULE"),
    # Accès direct à LSASS via PowerShell
    (r'lsass.*minidump|minidump.*lsass',            "LSASS_DUMP"),

    # ── Enumération réseau / AD ───────────────────────────────────────
    (r'invoke-bloodhound',                          "BLOODHOUND_PS"),
    (r'get-aduser.*-filter\s+\*',                   "AD_ENUM_ALL"),
    (r'net\s+(user|group|localgroup).*/domain',     "AD_ENUM_NET"),
    # Port scan depuis PowerShell
    (r'test-netconnection.*-port',                  "PS_PORTSCAN"),

    # ── Exfiltration ─────────────────────────────────────────────────
    (r'invoke-restmethod.*post.*body',              "HTTP_POST_EXFIL"),
    (r'(compress-archive|zip).*send',               "DATA_EXFIL"),
]

# Signatures de payload Metasploit (bytes hex dans les fichiers)
# Ces patterns se retrouvent dans les stagers msfvenom courants
MSF_SIGNATURES = [
    b'\xfc\x48\x83\xe4\xf0',   # Meterpreter x64 prologue
    b'\xfc\xe8\x82\x00\x00',   # Meterpreter x86 prologue
    b'\x4d\x5a\x90\x00\x03',   # PE header (EXE dans fichier non-exe)
    b'MSFV',                    # msfvenom marker
    b'ReflectiveDll',           # Reflective DLL injection
    b'meterpreter',             # String meterpreter en clair
    b'stdapi_',                 # API Meterpreter
]

# Extensions de fichiers surveillées (dossiers utilisateur)
WATCH_EXTENSIONS = {
    # Exécutables
    '.exe', '.dll', '.scr', '.pif', '.com',
    # Scripts
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.wsh', '.hta',
    # Packages
    '.msi', '.msp', '.jar', '.py', '.sh',
    # Liens / Raccourcis
    '.lnk', '.url',
    # Docs avec macros
    '.docm', '.xlsm', '.pptm',
    # Archives (souvent utilisées pour dropper)
    '.zip', '.rar', '.7z', '.gz',
    # Fichiers config modifiés
    '.reg', '.inf', '.cpl',
}

# ══════════════════════════════════════════════════════════════════════
#  ÉTAT GLOBAL — Partagé entre les threads
# ══════════════════════════════════════════════════════════════════════

_seen_conns    = set()        # Connexions réseau déjà vues
_seen_files    = {}           # Fichiers vus → {path: (hash, mtime)}
_known_procs   = {}           # PIDs connus → nom
_ips_blocked   = set()        # IPs bloquées par l'IPS local
_lock          = threading.Lock()
_running       = True

# File d'envoi non bloquante (évite de bloquer les threads de détection)
_send_queue    = collections.deque(maxlen=1000)

# Throttle : évite le spam d'alertes identiques (clé → dernier timestamp)
_alert_throttle = {}
_throttle_lock  = threading.Lock()

# ══════════════════════════════════════════════════════════════════════
#  UTILITAIRES
# ══════════════════════════════════════════════════════════════════════

def now():
    """Horodatage formaté."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_private(ip):
    """Vérifie si une IP est dans un réseau privé RFC1918."""
    try: return ipaddress.ip_address(ip).is_private
    except: return False

def is_loopback(ip):
    """Vérifie si une IP est en loopback (127.x.x.x / ::1)."""
    try: return ipaddress.ip_address(ip).is_loopback
    except: return False

def is_multicast(ip):
    """Vérifie si une IP est multicast (224.x.x.x etc.)."""
    try: return ipaddress.ip_address(ip).is_multicast
    except: return False

def get_file_hash(path, max_size=10*1024*1024):
    """
    Calcule le hash MD5 d'un fichier (max 10 MB).
    Utilisé pour détecter les modifications et les signatures connues.
    """
    try:
        if os.path.getsize(path) > max_size:
            return None
        h = hashlib.md5()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except: return None

def scan_msf_signature(path, max_size=5*1024*1024):
    """
    Lit les premiers octets d'un fichier et cherche des signatures Metasploit.
    Retourne le nom de la signature trouvée ou None.
    """
    try:
        size = os.path.getsize(path)
        if size > max_size or size == 0:
            return None
        with open(path, 'rb') as f:
            data = f.read(min(4096, size))
        for sig in MSF_SIGNATURES:
            if sig in data:
                return sig.decode('utf-8', errors='replace')[:30]
    except: pass
    return None

def throttle_ok(key):
    """
    Retourne True si l'alerte peut être envoyée (pas envoyée depuis ALERT_THROTTLE_SEC).
    Évite le spam d'alertes identiques sur le dashboard.
    """
    now_ts = time.time()
    with _throttle_lock:
        last = _alert_throttle.get(key, 0)
        if now_ts - last >= ALERT_THROTTLE_SEC:
            _alert_throttle[key] = now_ts
            return True
    return False

def get_pid_name(pid):
    """Récupère le nom d'un processus par son PID."""
    try: return psutil.Process(pid).name()
    except: return "?"

# ══════════════════════════════════════════════════════════════════════
#  ENVOI — Thread dédié non bloquant
# ══════════════════════════════════════════════════════════════════════

def send(level, category, title, detail, extra=None, throttle_key=None):
    """
    Enfile une alerte pour envoi au serveur.
    Si throttle_key est donné, l'alerte est ignorée si déjà envoyée récemment.
    """
    if throttle_key and not throttle_ok(throttle_key):
        return  # Throttle actif — on ne spam pas

    payload = {
        "agent":    AGENT_NAME,
        "time":     now(),
        "level":    level,
        "category": category,
        "title":    title,
        "detail":   str(detail)[:800],
        "extra":    extra or {}
    }
    _send_queue.append(payload)

def _send_worker():
    """
    Thread dédié à l'envoi HTTP vers le serveur.
    Tourne en continu, vide la file d'envoi sans bloquer les autres threads.
    """
    while _running:
        if _send_queue:
            payload = _send_queue.popleft()
            try:
                requests.post(f"{SERVER_URL}/alert", json=payload, timeout=3)
            except Exception:
                pass  # Silencieux — la file reprendra au prochain cycle
        else:
            time.sleep(0.05)  # Petite pause si file vide

# ══════════════════════════════════════════════════════════════════════
#  TELEGRAM — Alertes critiques (optionnel)
# ══════════════════════════════════════════════════════════════════════

def telegram_alert(title, detail):
    """
    Envoie une alerte CRITICAL vers Telegram.
    Activé uniquement si TELEGRAM_ENABLED = True et token/chat_id configurés.
    """
    if not TELEGRAM_ENABLED or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        msg = f"🚨 *12ak Shield ALERTE*\n\n*{title}*\n`{detail[:200]}`\n\n🖥️ Agent: `{AGENT_NAME}`\n🕐 {now()}"
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=5
        )
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════
#  IPS — Intrusion Prevention System
#  Bloque les IPs suspectes au niveau du firewall OS
# ══════════════════════════════════════════════════════════════════════

def ips_block_ip(ip, reason):
    """
    Bloque une IP via Windows Firewall (netsh) ou Linux iptables.
    L'IP est isolée du réseau — ne peut plus communiquer avec la machine.
    Les IPs de la WHITELIST ne sont jamais bloquées.
    """
    # Protection whitelist — jamais bloquer notre infrastructure
    if ip in WHITELIST_IPS:
        return
    if ip in _ips_blocked:
        return  # Déjà bloquée

    _ips_blocked.add(ip)

    try:
        if platform.system() == 'Windows':
            # Bloquer en entrée ET en sortie (isolation complète)
            subprocess.run(
                f'netsh advfirewall firewall add rule name="12ak_BLOCK_{ip}" '
                f'dir=in action=block remoteip={ip}',
                shell=True, capture_output=True, timeout=5
            )
            subprocess.run(
                f'netsh advfirewall firewall add rule name="12ak_BLOCK_{ip}_OUT" '
                f'dir=out action=block remoteip={ip}',
                shell=True, capture_output=True, timeout=5
            )
        else:
            # Linux — iptables INPUT et OUTPUT
            subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP'],
                           capture_output=True, timeout=5)
            subprocess.run(['iptables','-I','OUTPUT','-d',ip,'-j','DROP'],
                           capture_output=True, timeout=5)

        print(f"  {R}[IPS BLOCK]{RST} {ip} — {reason}")
        send("CRITICAL", "IPS",
             f"IP BLOQUEE ET ISOLEE : {ip}",
             f"Raison: {reason} | Action: règle firewall créée",
             {"type":"ips_block","ip":ip,"reason":reason,"action":"BLOCKED"})
        telegram_alert(f"IP BLOQUEE : {ip}", reason)

    except Exception as e:
        send("WARNING", "IPS", f"Echec blocage {ip}", str(e))

def ips_unblock_ip(ip):
    """Débloque une IP — supprime les règles firewall créées par l'IPS."""
    _ips_blocked.discard(ip)
    try:
        if platform.system() == 'Windows':
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="12ak_BLOCK_{ip}"',
                shell=True, capture_output=True, timeout=5)
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="12ak_BLOCK_{ip}_OUT"',
                shell=True, capture_output=True, timeout=5)
        else:
            subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'],
                           capture_output=True, timeout=5)
            subprocess.run(['iptables','-D','OUTPUT','-d',ip,'-j','DROP'],
                           capture_output=True, timeout=5)
        print(f"  {G}[IPS UNBLOCK]{RST} {ip}")
        send("INFO","IPS",f"IP debloquee : {ip}","Regle firewall supprimee",
             {"type":"ips_unblock","ip":ip})
    except Exception as e:
        send("WARNING","IPS",f"Echec deblocage {ip}",str(e))

def ips_kill_process(pid, name, reason):
    """
    Tue un processus malveillant identifié par l'IPS.
    Utilisé uniquement pour les outils de credential dumping avérés.
    """
    try:
        p = psutil.Process(pid)
        p.terminate()
        time.sleep(0.5)
        if p.is_running(): p.kill()
        print(f"  {R}[IPS KILL]{RST} PID {pid} ({name}) — {reason}")
        send("CRITICAL","IPS",f"PROCESSUS TUE PAR IPS : {name} (PID {pid})",
             f"Raison: {reason}",
             {"type":"ips_kill","pid":pid,"name":name,"reason":reason})
        telegram_alert(f"IPS KILL : {name}", reason)
    except Exception as e:
        send("WARNING","IPS",f"Echec kill PID {pid}",str(e))

# ══════════════════════════════════════════════════════════════════════
#  MODULE 1 — SYSINFO : CPU / RAM / DISK
# ══════════════════════════════════════════════════════════════════════

def loop_sysinfo():
    """
    Envoie les métriques système toutes les 5 secondes.
    Alerte si CPU > 85% ou RAM > 90% de manière prolongée.
    """
    cpu_hist = collections.deque(maxlen=12)  # Historique 1 minute

    while _running:
        try:
            cpu  = psutil.cpu_percent(interval=1)
            cpu_hist.append(cpu)
            ram  = psutil.virtual_memory()
            cpu_avg = sum(cpu_hist) / len(cpu_hist)

            # Collecte infos disques
            disks = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "mount":    part.mountpoint,
                        "total_gb": round(usage.total/(1<<30),1),
                        "used_gb":  round(usage.used/(1<<30),1),
                        "free_gb":  round(usage.free/(1<<30),1),
                        "percent":  usage.percent,
                        "fstype":   part.fstype,
                    })
                    # Alerte disque plein
                    if usage.percent > 95:
                        send("CRITICAL","SYSINFO",
                             f"DISQUE PLEIN : {part.mountpoint}",
                             f"{round(usage.used/(1<<30),1)} GB / {round(usage.total/(1<<30),1)} GB",
                             {"type":"disk_full","mount":part.mountpoint,"percent":usage.percent},
                             throttle_key=f"disk_{part.mountpoint}")
                except PermissionError: pass

            # Niveau d'alerte global
            level = "INFO"
            if cpu_avg > 90 or ram.percent > 93: level = "CRITICAL"
            elif cpu_avg > 78 or ram.percent > 82: level = "WARNING"

            # Réseau I/O
            net = psutil.net_io_counters()

            send(level, "SYSINFO",
                 f"CPU {cpu:.0f}% | RAM {ram.percent:.0f}% | "
                 f"{ram.used//1024//1024} MB / {ram.total//1024//1024} MB",
                 f"Moy CPU 1min: {cpu_avg:.1f}%",
                 {
                     "type":          "sysinfo",
                     "cpu":           cpu,
                     "cpu_avg1m":     round(cpu_avg, 1),
                     "cpu_count":     psutil.cpu_count(),
                     "ram_percent":   ram.percent,
                     "ram_used_mb":   ram.used // 1024 // 1024,
                     "ram_total_mb":  ram.total // 1024 // 1024,
                     "ram_avail_mb":  ram.available // 1024 // 1024,
                     "disks":         disks,
                     "os":            platform.system()+" "+platform.version()[:35],
                     "net_sent":      net.bytes_sent,
                     "net_recv":      net.bytes_recv,
                 })
        except Exception: pass

        time.sleep(max(1, INTERVAL_SYSINFO - 1))

# ══════════════════════════════════════════════════════════════════════
#  MODULE 2 — PROCESSUS : Détection avancée
# ══════════════════════════════════════════════════════════════════════

def _check_parent_spoof(proc):
    """
    Détecte le PPID Spoofing (parent process spoofing).
    Exemple : Word qui lance cmd.exe = macro malveillante probable.
    """
    try:
        parent = proc.parent()
        if not parent: return False, ""
        pname = parent.name().lower()
        cname = proc.name().lower()
        # Office → Shell = macro / exploit document
        office = {'winword','excel','powerpnt','outlook','mspub','msaccess','onenote'}
        shells = {'cmd','powershell','pwsh','wscript','cscript','mshta','rundll32'}
        if any(o in pname for o in office) and any(s in cname for s in shells):
            return True, f"OFFICE→SHELL: {parent.name()} lance {proc.name()}"
        # Explorer lance directement svchost = suspect
        if 'explorer' in pname and 'svchost' in cname:
            return True, f"EXPLORER→SVCHOST suspect"
    except: pass
    return False, ""

def _check_process_hollow(proc):
    """
    Heuristique Process Hollowing :
    Processus système qui a spawné un enfant shell = suspect.
    """
    try:
        if platform.system() != 'Windows': return False
        name = proc.name().lower()
        sys_procs = {'svchost','lsass','winlogon','csrss','smss','wininit','spoolsv'}
        if any(s in name for s in sys_procs):
            for child in proc.children():
                cname = child.name().lower()
                if any(s in cname for s in ['cmd','powershell','wscript','mshta']):
                    return True
    except: pass
    return False

def loop_processes():
    """
    Surveille tous les processus actifs.
    Détecte : noms suspects, parent spoofing, hollow, PS malveillant, CPU anormal.
    """
    global _known_procs

    while _running:
        try:
            current_pids = {}
            proc_list    = []

            for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent',
                                           'status','username','cmdline','exe']):
                try:
                    info  = p.info
                    pid   = info['pid']
                    name  = (info['name'] or '').lower()
                    cmd   = ' '.join(info.get('cmdline') or [])[:400].lower()
                    cpu   = info['cpu_percent'] or 0
                    mem   = round(info['memory_percent'] or 0, 2)
                    exe   = info.get('exe','') or ''

                    current_pids[pid] = name

                    # ── Détection 1 : Nom malveillant connu ──────────────
                    if any(s in name for s in SUSPECT_PROC_NAMES):
                        tkey = f"sus_proc_{pid}"
                        send("CRITICAL","PROCESS",
                             f"PROCESSUS MALVEILLANT : {info['name']} (PID {pid})",
                             f"Outil offensif détecté | CMD: {cmd[:200]}",
                             {"type":"suspect_proc","pid":pid,"name":info['name'],
                              "cmd":cmd[:200],"cpu":cpu,"mem":mem,"exe":exe},
                             throttle_key=tkey)
                        telegram_alert(f"PROCESSUS MALVEILLANT : {info['name']}", cmd[:100])
                        # Auto-kill des outils de dumping de credentials
                        if any(s in name for s in {'mimikatz','lazagne','wce','fgdump','pwdump'}):
                            ips_kill_process(pid, info['name'], "Outil credential dumping détecté")

                    # ── Détection 2 : Parent Spoofing ────────────────────
                    spoof, spoof_reason = _check_parent_spoof(p)
                    if spoof:
                        send("CRITICAL","PROCESS",
                             f"PARENT SPOOF : {info['name']} (PID {pid})",
                             spoof_reason,
                             {"type":"parent_spoof","pid":pid,"name":info['name'],
                              "cmd":cmd[:200],"reason":spoof_reason},
                             throttle_key=f"spoof_{pid}")
                        telegram_alert(f"PARENT SPOOFING", spoof_reason)

                    # ── Détection 3 : Process Hollowing ─────────────────
                    if _check_process_hollow(p):
                        send("CRITICAL","PROCESS",
                             f"PROCESS HOLLOW : {info['name']} (PID {pid})",
                             "Processus système avec enfant shell — injection probable",
                             {"type":"hollow","pid":pid,"name":info['name']},
                             throttle_key=f"hollow_{pid}")

                    # ── Détection 4 : Commandes PowerShell malveillantes ─
                    if any(s in name for s in {'powershell','pwsh','cmd','wscript',
                                                'cscript','mshta','wmic','regsvr32'}):
                        for pattern, sig_name in PS_PATTERNS:
                            if re.search(pattern, cmd, re.IGNORECASE):
                                send("CRITICAL","POWERSHELL",
                                     f"CMD MALVEILLANTE [{sig_name}] : {info['name']} (PID {pid})",
                                     f"CMD: {cmd[:250]}",
                                     {"type":"malicious_cmd","sig":sig_name,
                                      "pid":pid,"name":info['name'],"cmd":cmd[:250]},
                                     throttle_key=f"ps_{pid}_{sig_name}")
                                telegram_alert(f"PowerShell malveillant [{sig_name}]", cmd[:150])
                                break

                    # ── Détection 5 : Port ouvert par processus ──────────
                    # (Détecté dans loop_network — pas de doublon ici)

                    # ── Détection 6 : Nouveau processus ─────────────────
                    with _lock:
                        if pid not in _known_procs:
                            _known_procs[pid] = name
                            # On ne signale pas les processus système évidents
                            if name not in {'','system','idle','[system]',
                                            'registry','memory compression'}:
                                send("INFO","PROCESS",
                                     f"Nouveau processus : {info['name']} (PID {pid})",
                                     f"User: {info.get('username','?')} | CMD: {cmd[:100]}",
                                     {"type":"new_proc","pid":pid,"name":info['name'],
                                      "cmd":cmd[:100],"user":info.get('username','?'),
                                      "exe":exe[:80]},
                                     throttle_key=f"newproc_{pid}")

                    proc_list.append({
                        "pid":    pid,
                        "name":   info['name'] or '?',
                        "cpu":    round(cpu, 1),
                        "mem":    mem,
                        "status": info.get('status','?'),
                        "user":   (info.get('username','?') or '?').split('\\')[-1][:20],
                        "exe":    exe[:80],
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied): pass

            # Nettoyage des PIDs morts
            with _lock:
                dead = {p for p in _known_procs if p not in current_pids}
                for pid in dead:
                    del _known_procs[pid]

            # Snapshot trié CPU décroissant → dashboard Processus
            proc_list.sort(key=lambda x: (-x['cpu'], -x['mem']))
            send("INFO","PROC_LIST",
                 f"Processus actifs : {len(proc_list)}",
                 f"Top CPU: {proc_list[0]['name'] if proc_list else '?'}",
                 {"type":"proc_list","procs":proc_list[:100]})

        except Exception: pass
        time.sleep(INTERVAL_PROCS)

# ══════════════════════════════════════════════════════════════════════
#  MODULE 3 — RÉSEAU : Surveillance connexions
# ══════════════════════════════════════════════════════════════════════

def loop_network():
    """
    Surveille toutes les connexions réseau actives.
    Détecte : ports suspects, C2 beacon, latéralisation SMB, nouvelles IPs externes.
    Les IPs de la WHITELIST ne génèrent jamais d'alerte.
    """
    while _running:
        try:
            conns     = psutil.net_connections(kind='inet')
            conn_list = []

            for c in conns:
                try:
                    lip   = c.laddr.ip if c.laddr else ''
                    lport = c.laddr.port if c.laddr else 0
                    rip   = c.raddr.ip if c.raddr else ''
                    rport = c.raddr.port if c.raddr else 0
                    pid   = c.pid
                    proto = 'TCP' if c.type == 1 else 'UDP'
                    status = c.status or ''

                    # Ignorer loopback pur et multicast
                    if rip and (is_loopback(rip) and is_loopback(lip)): continue
                    if rip and is_multicast(rip): continue

                    rip_private = is_private(rip) if rip else True
                    rip_public  = not rip_private and rip != ''
                    ip_type     = 'PRIVATE' if rip_private else ('PUBLIC' if rip else 'LOCAL')
                    proc_name   = get_pid_name(pid) if pid else '?'

                    conn_entry = {
                        "lip":lip,"lport":lport,"rip":rip,"rport":rport,
                        "proto":proto,"status":status,"pid":pid,
                        "proc":proc_name,"ip_type":ip_type,"ip_known":rip_private,
                    }
                    conn_list.append(conn_entry)

                    # ── Skip si IP dans whitelist ────────────────────────
                    if rip in WHITELIST_IPS: continue
                    if rport in WHITELIST_PORTS and lport in WHITELIST_PORTS: continue

                    conn_key = f"{rip}:{rport}:{pid}"

                    # ── Nouvelle connexion externe ────────────────────────
                    if rip and rip_public and conn_key not in _seen_conns:
                        _seen_conns.add(conn_key)
                        lvl   = "INFO"
                        title = f"Nouvelle connexion externe : {rip}:{rport}"
                        detail= f"{proc_name} (PID {pid}) → {rip}:{rport}"

                        # Port suspect → CRITICAL + blocage IPS
                        if (rport in SUSPECT_PORTS or lport in SUSPECT_PORTS) and \
                           rport not in WHITELIST_PORTS:
                            lvl   = "CRITICAL"
                            title = f"PORT SUSPECT : {proc_name} → {rip}:{rport}"
                            ips_block_ip(rip, f"Port suspect {rport} utilisé par {proc_name}")

                        # Processus système qui contacte internet = possible C2
                        elif proc_name.lower() in {'svchost','lsass','winlogon','csrss'} \
                             and rport not in {80,443,53}:
                            lvl   = "CRITICAL"
                            title = f"C2 BEACON POSSIBLE : {proc_name} → {rip}:{rport}"

                        elif rport in {23, 69}:
                            lvl   = "WARNING"
                            title = f"Port dangereux (Telnet/TFTP) : {rip}:{rport}"

                        cat = "NET_TCP" if proto == 'TCP' else "NET_UDP"
                        send(lvl, cat, title, detail,
                             {**conn_entry,"type":"new_ext_conn"},
                             throttle_key=f"conn_{rip}_{rport}")
                        if lvl == "CRITICAL":
                            telegram_alert(title, detail)

                    # ── Connexion interne suspecte ────────────────────────
                    elif rip and rip_private and not is_loopback(rip) \
                         and conn_key not in _seen_conns:
                        _seen_conns.add(conn_key)

                        if rport in SUSPECT_PORTS and rport not in WHITELIST_PORTS:
                            send("WARNING","NET_TCP",
                                 f"CONN INTERNE SUSPECTE : {rip}:{rport}",
                                 f"{proc_name} (PID {pid}) → port suspect interne",
                                 {**conn_entry,"type":"internal_suspect"},
                                 throttle_key=f"internal_{rip}_{rport}")

                        # Latéralisation SMB (mouvement latéral réseau)
                        elif rport == 445 and proc_name.lower() not in {'system','svchost'}:
                            send("WARNING","NET_TCP",
                                 f"LATERALISATION SMB : {proc_name} → {rip}:445",
                                 "Processus non-système se connecte à SMB",
                                 {**conn_entry,"type":"smb_lateral"},
                                 throttle_key=f"smb_{rip}")

                except Exception: pass

            # Snapshot complet → dashboard Réseau
            send("INFO","NET_LIST",
                 f"Connexions actives : {len(conn_list)}",
                 f"Pub: {sum(1 for c in conn_list if c['ip_type']=='PUBLIC')} "
                 f"| Priv: {sum(1 for c in conn_list if c['ip_type']=='PRIVATE')}",
                 {"type":"conn_list","connections":conn_list})

        except Exception: pass
        time.sleep(INTERVAL_NETWORK)

# ══════════════════════════════════════════════════════════════════════
#  MODULE 4 — FICHIERS : Surveillance dossiers utilisateur UNIQUEMENT
#  Downloads, Desktop, Documents, Temp, AppData/Roaming
#  PAS de dossiers système (Windows, System32 etc.)
# ══════════════════════════════════════════════════════════════════════

def _get_user_dirs():
    """
    Retourne la liste des dossiers utilisateur à surveiller.
    Strictement limité aux dossiers personnels — pas de System32 etc.
    """
    if platform.system() == 'Windows':
        up = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
        return [
            os.path.join(up, 'Downloads'),          # Téléchargements
            os.path.join(up, 'Desktop'),             # Bureau
            os.path.join(up, 'Documents'),           # Documents
            os.path.join(up, 'AppData','Local','Temp'),  # Temp utilisateur
            os.path.join(up, 'AppData','Roaming'),   # AppData Roaming
            os.path.join(up, 'Music'),
            os.path.join(up, 'Videos'),
        ]
    else:
        home = os.path.expanduser('~')
        return [
            os.path.join(home,'Downloads'),
            os.path.join(home,'Desktop'),
            os.path.join(home,'Documents'),
            '/tmp',
        ]

def _scan_user_files(watch_dirs):
    """
    Parcourt les dossiers utilisateur et signale sur le dashboard :
    - TOUT fichier nouveau (téléchargé, copié, créé) dans les 5 dernières minutes
    - Modifications de fichiers existants (hash changé)
    - Double extension (document.pdf.exe) → CRITICAL
    - Signature Metasploit dans le contenu → CRITICAL
    - Nom déguisé en processus système → CRITICAL
    - Extensions suspectes (.exe, .ps1, .bat...) → WARNING

    IMPORTANT : On signale TOUS les nouveaux fichiers utilisateur,
    pas uniquement les suspects — pour que le dashboard montre les
    téléchargements en temps réel.
    """
    sys_names = {'svchost','csrss','lsass','winlogon','smss','wininit',
                 'explorer','taskhost','conhost','dllhost','rundll32'}

    for base_dir in watch_dirs:
        if not os.path.exists(base_dir): continue
        try:
            for root, dirs, files in os.walk(base_dir):
                # Limiter profondeur à 4 niveaux pour les perfs
                depth = root[len(base_dir):].count(os.sep)
                if depth > 4:
                    dirs.clear(); continue

                for fname in files:
                    fpath = os.path.join(root, fname)
                    ext   = os.path.splitext(fname)[1].lower()
                    parts = fname.lower().split('.')

                    try:
                        st    = os.stat(fpath)
                        mtime = st.st_mtime
                        size  = st.st_size
                        age   = time.time() - mtime
                    except: continue

                    # ── Analyses de risque ──────────────────────────────
                    # Double extension : document.pdf.exe
                    is_double_ext = (len(parts) >= 3 and
                                     f'.{parts[-1]}' in WATCH_EXTENSIONS)
                    # Nom déguisé en processus Windows légitime
                    base_name    = os.path.splitext(fname.lower())[0]
                    is_disguised = any(s in base_name and base_name != s
                                       for s in sys_names)
                    # Extension suspecte
                    is_watch_ext = ext in WATCH_EXTENSIONS

                    # Label lisible du dossier pour le dashboard
                    rl = root.lower()
                    label = ("TELECHARGEMENT" if "download" in rl else
                             "BUREAU"         if "desktop"  in rl else
                             "DOCUMENTS"      if "document" in rl else
                             "TEMP"           if "temp"     in rl else
                             "APPDATA"        if "appdata"  in rl else
                             "MUSIQUE"        if "music"    in rl else
                             "VIDEOS"         if "video"    in rl else "USER")

                    # ── Nouveau fichier (< 5 minutes) ────────────────────
                    # On signale TOUS les fichiers nouveaux, pas que les suspects
                    # Fenêtre de 5 min (300s) pour attraper les téléchargements lents
                    if age < 300 and fpath not in _seen_files:
                        fhash   = get_file_hash(fpath)
                        msf_sig = scan_msf_signature(fpath) if is_watch_ext else None

                        _seen_files[fpath] = (fhash or '', mtime)

                        # Construire les raisons et le niveau
                        reasons = []
                        level   = "INFO"   # Tous les nouveaux fichiers = INFO minimum

                        if is_double_ext:
                            reasons.append("DOUBLE EXTENSION")
                            level = "CRITICAL"
                        if is_disguised:
                            reasons.append("NOM DEGUISE")
                            level = "CRITICAL"
                        if msf_sig:
                            reasons.append(f"SIGNATURE METASPLOIT: {msf_sig}")
                            level = "CRITICAL"
                        if is_watch_ext and level != "CRITICAL":
                            reasons.append(f"Extension suspecte ({ext})")
                            level = "WARNING"

                        # Titre clair pour le dashboard
                        if level == "CRITICAL":
                            title = f"FICHIER DANGEREUX : {fname}"
                        elif level == "WARNING":
                            title = f"Fichier suspect : {fname}"
                        else:
                            title = f"Nouveau fichier : {fname}"

                        reason_str = " | ".join(reasons) if reasons else "Nouveau"
                        detail = (f"[{label}] {reason_str} | "
                                  f"Chemin: {fpath} | "
                                  f"Taille: {size} octets | "
                                  f"Hash: {(fhash or 'N/A')[:16]}...")

                        send(level, "FILE", title, detail,
                             {"type":       "new_file",
                              "name":       fname,
                              "path":       fpath,
                              "dir":        root,
                              "label":      label,
                              "size":       size,
                              "ext":        ext,
                              "hash":       fhash,
                              "msf_sig":    msf_sig,
                              "double_ext": is_double_ext,
                              "disguised":  is_disguised,
                              "reasons":    reasons,
                              "age_sec":    int(age)},
                             throttle_key=f"newfile_{fpath}")

                        if level == "CRITICAL":
                            telegram_alert(title, detail)
                        continue

                    # ── Fichier déjà connu — vérifier modification ───────
                    if fpath in _seen_files and (is_watch_ext or is_double_ext):
                        # Vérifier seulement si mtime a changé (optimisation)
                        prev_hash, prev_mtime = _seen_files[fpath]
                        if mtime != prev_mtime:
                            fhash = get_file_hash(fpath)
                            if fhash and prev_hash and fhash != prev_hash:
                                _seen_files[fpath] = (fhash, mtime)
                                send("WARNING", "FILE",
                                     f"Fichier modifie : {fname}",
                                     f"[{label}] Contenu changé | {fpath} | {size} octets",
                                     {"type":   "file_modified",
                                      "name":   fname,
                                      "path":   fpath,
                                      "dir":    root,
                                      "label":  label,
                                      "ext":    ext,
                                      "hash":   fhash,
                                      "size":   size},
                                     throttle_key=f"filemod_{fpath}")

                    # ── Premier scan — enregistrer sans alerter ──────────
                    elif fpath not in _seen_files:
                        # Fichier existant avant le démarrage de l'agent
                        # On l'enregistre silencieusement pour détecter les futures modifs
                        try:
                            fhash = get_file_hash(fpath) if size < 5*1024*1024 else None
                            _seen_files[fpath] = (fhash or '', mtime)
                        except: pass

        except PermissionError: pass

def loop_files():
    """Thread de surveillance des fichiers utilisateur."""
    watch_dirs = _get_user_dirs()
    while _running:
        _scan_user_files(watch_dirs)
        time.sleep(INTERVAL_FILES)

# ══════════════════════════════════════════════════════════════════════
#  MODULE 5 — POWERSHELL AUDIT (Windows uniquement)
#  Lit l'Event Log PowerShell Operational pour détecter les commandes
# ══════════════════════════════════════════════════════════════════════

def loop_ps_audit():
    """
    Audit PowerShell via Windows Event Log (Script Block Logging).
    Nécessite que le Script Block Logging soit activé dans les GPO.
    Fonctionne uniquement sur Windows.
    """
    if platform.system() != 'Windows': return

    while _running:
        try:
            result = subprocess.run(
                ['wevtutil','qe',
                 'Microsoft-Windows-PowerShell/Operational',
                 '/c:30','/rd:true','/f:text'],
                capture_output=True, text=True, timeout=12,
                encoding='utf-8', errors='ignore'
            )
            if result.stdout:
                log_lower = result.stdout.lower()
                for pattern, sig_name in PS_PATTERNS:
                    if re.search(pattern, log_lower, re.IGNORECASE):
                        send("CRITICAL","POWERSHELL",
                             f"EVENT LOG PS SUSPECT [{sig_name}]",
                             f"Pattern détecté dans Event Log PowerShell",
                             {"type":"ps_eventlog","sig":sig_name},
                             throttle_key=f"pslog_{sig_name}")
                        telegram_alert(f"PS Event Log [{sig_name}]",
                                       "Activité PowerShell suspecte détectée")
                        break
        except Exception: pass
        time.sleep(INTERVAL_PS_AUDIT)

# ══════════════════════════════════════════════════════════════════════
#  MODULE 6 — MÉMOIRE : Détection Fileless & Injection In-Memory
#  Détecte les payloads qui tournent en RAM sans fichier sur disque
# ══════════════════════════════════════════════════════════════════════

def _check_rwx_memory(proc):
    """
    Vérifie si un processus a des régions mémoire RWX (Read-Write-Execute).
    RWX = shellcode injecté ou payload fileless en cours d'exécution.
    Fonctionne uniquement sur Windows avec accès aux memory maps.
    Retourne (True, taille_rwx) si suspect, sinon (False, 0).
    """
    if platform.system() != 'Windows':
        return False, 0
    try:
        rwx_size = 0
        for mmap in proc.memory_maps(grouped=False):
            perms = getattr(mmap, 'perms', '') or ''
            # rwx = Read + Write + Execute simultanément = shellcode probable
            if 'r' in perms and 'w' in perms and 'x' in perms:
                rwx_size += getattr(mmap, 'rss', 0)
        # Seuil : plus de 100 KB en RWX = très suspect
        return rwx_size > 100 * 1024, rwx_size
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return False, 0
    except Exception:
        return False, 0

def _check_fileless(proc):
    """
    Détecte les processus fileless : processus qui tourne sans fichier
    exécutable sur le disque (deleted on disk / memory-only payload).
    """
    try:
        exe = proc.exe()
        if not exe:
            return True   # Pas de chemin = fileless probable
        if not os.path.exists(exe):
            return True   # Fichier supprimé après lancement
        # Chemin inhabituel pour un processus système
        name = proc.name().lower()
        sys_procs = {'svchost','lsass','csrss','winlogon','smss'}
        if any(s in name for s in sys_procs):
            expected = r'c:\windows\system32'
            if exe and expected not in exe.lower():
                return True  # svchost depuis un chemin non-système
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    except Exception:
        pass
    return False

def loop_memory_scan():
    """
    Scan mémoire toutes les 10 secondes.
    Détecte :
    - Régions mémoire RWX (shellcode injecté)
    - Processus fileless (deleted on disk)
    - Processus sans DLL chargées (hollow)
    - Processus .NET avec assemblies suspectes en mémoire
    Performance : léger, accès memory_maps uniquement si nécessaire.
    """
    if platform.system() != 'Windows':
        return  # Principalement utile sur Windows

    # Processus légitimes qui peuvent avoir du RWX (browsers, JIT compilers)
    RWX_WHITELIST = {
        'chrome', 'brave', 'firefox', 'msedge', 'opera',
        'node', 'python', 'java', 'javaw', 'dotnet',
        'code', 'devenv', 'idea64',
    }

    while _running:
        try:
            for proc in psutil.process_iter(['pid','name','exe','status']):
                try:
                    pid  = proc.info['pid']
                    name = (proc.info['name'] or '').lower()
                    exe  = proc.info.get('exe','') or ''

                    # Skip les processus whitelistés (browsers, IDE, runtimes)
                    if any(w in name for w in RWX_WHITELIST):
                        continue
                    # Skip PID 0 et 4 (System)
                    if pid in (0, 4):
                        continue

                    # ── Détection 1 : Mémoire RWX ────────────────────
                    is_rwx, rwx_size = _check_rwx_memory(proc)
                    if is_rwx:
                        send("CRITICAL", "MEMORY",
                             f"MEMOIRE RWX DETECTEE : {proc.info['name']} (PID {pid})",
                             f"Shellcode probable en memoire | {rwx_size//1024} KB RWX",
                             {"type":"rwx_memory","pid":pid,"name":proc.info['name'],
                              "rwx_kb":rwx_size//1024,"exe":exe},
                             throttle_key=f"rwx_{pid}")
                        telegram_alert(
                            f"SHELLCODE IN-MEMORY : {proc.info['name']}",
                            f"PID {pid} | {rwx_size//1024} KB RWX"
                        )

                    # ── Détection 2 : Processus Fileless ─────────────
                    if _check_fileless(proc):
                        send("CRITICAL", "MEMORY",
                             f"PROCESSUS FILELESS : {proc.info['name']} (PID {pid})",
                             f"Processus sans fichier exe sur disque — payload in-memory",
                             {"type":"fileless","pid":pid,"name":proc.info['name'],
                              "exe":exe},
                             throttle_key=f"fileless_{pid}")
                        telegram_alert(
                            f"FILELESS DETECTE : {proc.info['name']}",
                            f"PID {pid} — pas de fichier sur disque"
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

        except Exception:
            pass
        time.sleep(10)  # Scan toutes les 10s — léger sur CPU

# ══════════════════════════════════════════════════════════════════════
#  MODULE 7 — DEFENDER CHECK (Windows uniquement)
# ══════════════════════════════════════════════════════════════════════

def loop_defender():
    """
    Vérifie l'état de Windows Defender toutes les 60 secondes.
    Alerte CRITICAL si la protection temps réel est désactivée.
    """
    if platform.system() != 'Windows': return

    while _running:
        try:
            result = subprocess.run(
                ['powershell','-NoProfile','-Command',
                 'Get-MpComputerStatus | Select-Object AntivirusEnabled,'
                 'RealTimeProtectionEnabled,AMServiceEnabled | ConvertTo-Json'],
                capture_output=True, text=True, timeout=10,
                encoding='utf-8', errors='ignore'
            )
            if result.stdout:
                d = json.loads(result.stdout.strip())
                av  = d.get('AntivirusEnabled', True)
                rtp = d.get('RealTimeProtectionEnabled', True)
                am  = d.get('AMServiceEnabled', True)

                if not rtp or not av:
                    send("CRITICAL","DEFENDER",
                         "WINDOWS DEFENDER DESACTIVE",
                         f"AV={av} | RealTimeProtection={rtp} | AMService={am}",
                         {"type":"defender_off","av":av,"rtp":rtp,"am":am},
                         throttle_key="defender_off")
                    telegram_alert("DEFENDER DÉSACTIVÉ",
                                   f"AV={av} | RTP={rtp} | AM={am}")
                else:
                    send("INFO","DEFENDER","Defender actif",
                         f"AV={av} | RTP={rtp} | AM={am}",
                         {"type":"defender_ok","av":av,"rtp":rtp,"am":am},
                         throttle_key="defender_ok")
        except Exception: pass
        time.sleep(60)

# ══════════════════════════════════════════════════════════════════════
#  MODULE 7 — WEBSOCKET BIDIRECTIONNEL
#  Reçoit les ordres du serveur : KILL, BLOCK_IP, UNBLOCK_IP
# ══════════════════════════════════════════════════════════════════════

async def _ws_listen():
    """
    Connexion WebSocket persistante vers le serveur.
    Reçoit et exécute les ordres en temps réel :
    - KILL    → tue un processus par PID
    - BLOCK_IP  → bloque une IP via firewall
    - UNBLOCK_IP → débloque une IP
    - PING    → répond PONG (keepalive)
    Reconnexion automatique avec backoff exponentiel.
    """
    url         = f"ws://{SERVER_IP}:{WS_PORT}/agent?name={AGENT_NAME}"
    retry_delay = 3

    while _running:
        try:
            print(f"  {C}[WS]{RST} Connexion → {url}")
            async with websockets.connect(
                url, ping_interval=20, ping_timeout=10
            ) as ws:
                print(f"  {G}[WS]{RST} Canal de commandes ouvert")
                send("INFO","AGENT","Agent WS connecté",
                     f"Canal bidirectionnel actif vers {SERVER_IP}:{WS_PORT}",
                     {"type":"ws_connected"})
                retry_delay = 3  # reset backoff

                async for raw in ws:
                    try:
                        cmd    = json.loads(raw)
                        action = cmd.get("action","")
                        print(f"  {Y}[ORDRE]{RST} {action} ← serveur")

                        if action == "KILL":
                            pid = int(cmd.get("pid",0))
                            _execute_kill(pid)

                        elif action == "BLOCK_IP":
                            ip = cmd.get("ip","")
                            if ip: ips_block_ip(ip, cmd.get("reason","ordre dashboard"))

                        elif action == "UNBLOCK_IP":
                            ip = cmd.get("ip","")
                            if ip: ips_unblock_ip(ip)

                        elif action == "PING":
                            await ws.send(json.dumps({
                                "action":"PONG","agent":AGENT_NAME,"time":now()
                            }))

                    except Exception as e:
                        print(f"  {R}[WS CMD ERR]{RST} {e}")

        except websockets.exceptions.ConnectionClosed:
            print(f"  {Y}[WS]{RST} Connexion perdue — retry {retry_delay}s")
        except Exception as e:
            print(f"  {R}[WS]{RST} {e} — retry {retry_delay}s")

        if not _running: break
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 60)  # Backoff max 60s

def _execute_kill(pid):
    """
    Tue un processus par PID sur ordre du dashboard.
    Protège les processus système critiques.
    """
    if pid <= 0:
        send("WARNING","RESPONSE","KILL: PID invalide",str(pid)); return

    # Processus système intouchables
    PROTECTED = {
        "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
        "lsass.exe","services.exe","svchost.exe","explorer.exe",
        "dwm.exe","audiodg.exe","spoolsv.exe"
    }

    try:
        proc = psutil.Process(pid)
        name = proc.name()

        if name.lower() in PROTECTED:
            send("WARNING","RESPONSE",
                 f"KILL REFUSE : {name} (PID {pid})",
                 "Processus système protégé — non supprimable",
                 {"type":"kill_refused","pid":pid,"name":name})
            print(f"  {Y}[KILL REFUSE]{RST} {name} — protégé")
            return

        proc.terminate()          # SIGTERM (gracieux)
        try: proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()           # SIGKILL si résiste

        send("INFO","RESPONSE",
             f"KILL EXECUTE : {name} (PID {pid})",
             "Processus terminé sur ordre du dashboard",
             {"type":"kill_done","pid":pid,"name":name})
        print(f"  {G}[KILL OK]{RST} {name} (PID {pid})")

    except psutil.NoSuchProcess:
        send("INFO","RESPONSE",
             f"KILL: PID {pid} inexistant","Processus déjà terminé",
             {"type":"kill_not_found","pid":pid})
    except psutil.AccessDenied:
        send("WARNING","RESPONSE",
             f"KILL REFUSE: PID {pid}",
             "Permissions insuffisantes — relance l'agent en Administrateur",
             {"type":"kill_denied","pid":pid})
        print(f"  {R}[KILL REFUSE]{RST} PID {pid} — pas admin")
    except Exception as e:
        send("WARNING","RESPONSE",f"KILL ERREUR PID {pid}",str(e),
             {"type":"kill_error","pid":pid})

def loop_ws():
    """Lance la boucle asyncio WebSocket dans un thread dédié."""
    if not WS_OK:
        print(f"  {Y}[WS]{RST} KILL distant désactivé (pip install websockets)")
        return
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_ws_listen())
    finally:
        loop.close()

# ══════════════════════════════════════════════════════════════════════
#  BANNIÈRE
# ══════════════════════════════════════════════════════════════════════

def banner():
    os.system("clear" if os.name != "nt" else "cls")
    print(f"{R}{BLD}")
    print("  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║  ⚔️  12ak_H4ck Tools — Agent de Surveillance v6.0  🛡️    ║")
    print("  ║  Endpoint Detection & Response — Blue Team SOC           ║")
    print("  ╚═══════════════════════════════════════════════════════════╝")
    print(f"{RST}")
    print(f"  {G}[+]{RST} Agent   : {C}{AGENT_NAME}{RST}")
    print(f"  {G}[+]{RST} Serveur : {C}{SERVER_URL}{RST}")
    print(f"  {G}[+]{RST} OS      : {C}{platform.system()} {platform.release()}{RST}")
    print(f"  {G}[+]{RST} WS KILL : {C}{'ACTIF' if WS_OK else 'INACTIF (pip install websockets)'}{RST}")
    print(f"  {G}[+]{RST} Telegram: {C}{'ACTIF' if TELEGRAM_ENABLED else 'DÉSACTIVÉ'}{RST}")
    print(f"\n  {Y}[i]{RST} Modules :")
    print(f"       Sysinfo (CPU/RAM/Disk) → {INTERVAL_SYSINFO}s")
    print(f"       Processus + détection  → {INTERVAL_PROCS}s")
    print(f"       Réseau + C2 detect     → {INTERVAL_NETWORK}s")
    print(f"       Fichiers user          → {INTERVAL_FILES}s")
    print(f"       Fichiers sys           → {INTERVAL_SYS_FILES}s")
    print(f"       PowerShell Audit       → {INTERVAL_PS_AUDIT}s")
    print(f"       IPS (firewall auto)    → actif")
    print(f"       Scan memoire RWX       → 10s")
    print(f"       Throttle alertes       → {ALERT_THROTTLE_SEC}s")
    if platform.system() == 'Windows':
        print(f"       Defender Check         → 60s")
    print(f"\n{G}{'─'*61}{RST}")
    print(f"  {G}[*]{RST} Démarrage — CTRL+C pour arrêter\n")

# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    banner()

    # Initialisation CPU (premier appel toujours 0)
    psutil.cpu_percent(interval=None)

    # Snapshot initial des processus connus (évite de les signaler comme "nouveaux")
    for p in psutil.process_iter(['pid','name']):
        try:
            with _lock:
                _known_procs[p.info['pid']] = (p.info['name'] or '').lower()
        except: pass

    # ── Threads de surveillance ────────────────────────────────────────
    threads = [
        # Worker d'envoi HTTP (non bloquant)
        threading.Thread(target=_send_worker,    daemon=True, name="send_worker"),
        # Canal WS bidirectionnel (ordres du dashboard)
        threading.Thread(target=loop_ws,         daemon=True, name="ws_commands"),
        # Surveillance système
        threading.Thread(target=loop_sysinfo,    daemon=True, name="sysinfo"),
        threading.Thread(target=loop_processes,  daemon=True, name="procs"),
        threading.Thread(target=loop_network,    daemon=True, name="network"),
        threading.Thread(target=loop_files,      daemon=True, name="files"),
        # Scan mémoire RWX / fileless (Windows)
        threading.Thread(target=loop_memory_scan,daemon=True, name="memory_scan"),
    ]

    # Modules Windows uniquement
    if platform.system() == 'Windows':
        threads += [
            threading.Thread(target=loop_ps_audit, daemon=True, name="ps_audit"),
            threading.Thread(target=loop_defender, daemon=True, name="defender"),
        ]

    for t in threads:
        t.start()
        print(f"  {G}[+]{RST} {t.name} démarré")

    # Message de démarrage envoyé au serveur
    send("INFO","AGENT",f"Agent {AGENT_NAME} v6.0 connecté",
         f"OS: {platform.system()} {platform.release()} | "
         f"CPU: {psutil.cpu_count()} cores | "
         f"RAM: {psutil.virtual_memory().total//1024//1024} MB",
         {"os":   platform.system()+" "+platform.release(),
          "cpu_cores": psutil.cpu_count(),
          "ram_total_mb": psutil.virtual_memory().total//1024//1024,
          "version":"6.0","telegram":TELEGRAM_ENABLED})

    print(f"\n  {Y}[!]{RST} Tous les modules actifs. CTRL+C pour arrêter.\n")

    try:
        while True: time.sleep(5)
    except KeyboardInterrupt:
        _running = False
        print(f"\n  {Y}[!]{RST} Agent arrêté proprement.")
