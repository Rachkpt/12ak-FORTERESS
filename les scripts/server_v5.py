#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                                                                          ║
# ║   ⚔️  12ak_H4ck Tools — Serveur Central v5.0  🛡️                        ║
# ║                                                                          ║
# ║   MODULE : Serveur Linux/Ubuntu — Collecte, WebSocket, Dashboard        ║
# ║   AUTEUR : 12ak_H4ck                                                     ║
# ║                                                                          ║
# ║   INSTALLATION :                                                         ║
# ║     pip install websockets colorama                                      ║
# ║                                                                          ║
# ║   LANCEMENT :                                                            ║
# ║     python server_v5.py                                                  ║
# ║                                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import os, sys, json, threading, datetime, time, collections, hashlib, secrets, asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import websockets
    from websockets.server import serve as ws_serve
    WS_OK = True
except ImportError:
    WS_OK = False
    print("[!] pip install websockets")

try:
    from colorama import Fore, Style, init as ci; ci(autoreset=True)
    R=Fore.RED; Y=Fore.YELLOW; G=Fore.GREEN; C=Fore.CYAN
    M=Fore.MAGENTA; DG=Fore.WHITE; BLD=Style.BRIGHT; RST=Style.RESET_ALL
except ImportError:
    R=Y=G=C=M=DG=BLD=RST=""

# ══════════════════════════════════════════════════════════════════════
#  PORTS
# ══════════════════════════════════════════════════════════════════════

AGENT_PORT = 9999    # HTTP — agents → POST /alert
WS_PORT    = 9998    # WebSocket — dashboard + agents (bidirectionnel)
DASH_PORT  = 31337   # HTTP — interface web dashboard
MAX_ALERTS = 5000    # Nombre max d'alertes en mémoire
LOG_FILE   = "shield_v5.log"

# ══════════════════════════════════════════════════════════════════════
#  AUTHENTIFICATION
#  Pour changer un mot de passe :
#  python3 -c "import hashlib; print(hashlib.sha256(b'NOUVEAU_MOT_DE_PASSE').hexdigest())"
# ══════════════════════════════════════════════════════════════════════

CREDENTIALS = {
    "12ak":  hashlib.sha256(b"fortress2024").hexdigest(),
    "admin": hashlib.sha256(b"Rach9047@").hexdigest(),
}

ACCESS_TOKEN     = secrets.token_hex(16)   # Token URL généré à chaque démarrage
sessions         = {}
sessions_lock    = threading.Lock()
SESSION_DURATION = 8 * 3600               # Session de 8 heures

# ══════════════════════════════════════════════════════════════════════
#  STOCKAGE PARTAGÉ — Thread-safe avec verrou
# ══════════════════════════════════════════════════════════════════════

alerts        = collections.deque(maxlen=MAX_ALERTS)  # Alertes en mémoire
agents        = {}        # name → {last_seen, os, count, ws_connected, online}
stats         = {"CRITICAL":0,"WARNING":0,"INFO":0,"total":0}
blocked_ips   = set()     # IPs bloquées par le dashboard
lock          = threading.Lock()

# Clients dashboard connectés en WebSocket (pour push temps réel)
dash_clients      = set()
dash_clients_lock = threading.Lock()

# Agents connectés en WebSocket (pour leur envoyer des ordres)
agent_ws      = {}
agent_ws_lock = threading.Lock()

# Données détaillées par agent (dernier snapshot reçu)
agent_sysinfo = {}   # name → sysinfo dict
agent_procs   = {}   # name → liste processus
agent_conns   = {}   # name → liste connexions

# Timestamp du dernier message reçu par agent (pour statut online/offline)
agent_last_ping = {}   # name → time.time()
AGENT_TIMEOUT   = 30   # Agent considéré offline après 30s sans message

# Event loop asyncio WebSocket (initialisé dans le thread WS)
ws_loop = None

# ══════════════════════════════════════════════════════════════════════
#  MOTEUR DE CORRÉLATION — SIEM Engine
#
#  Principe : fenêtre glissante de 2 minutes par agent.
#  Chaque événement est stocké dans une timeline.
#  Toutes les 5 secondes, on applique les règles de corrélation.
#  Si plusieurs événements correspondent à une règle → alerte combinée.
#
#  Règles implémentées :
#  1. REVERSE_SHELL   — Process suspect + connexion port C2 (< 30s)
#  2. DROPPER         — Nouveau process + nouveau fichier (< 60s)
#  3. KILL_CHAIN      — Process + C2 + fichier dans < 2 min (attaque complète)
#  4. LATERAL_MOVE    — Connexion SMB interne + nouveau process (< 60s)
# ══════════════════════════════════════════════════════════════════════

# Timeline par agent : {agent_name → deque d'événements}
# Chaque événement = {"ts": timestamp, "type": str, "data": dict}
corr_timeline  = collections.defaultdict(lambda: collections.deque(maxlen=200))
corr_lock      = threading.Lock()

# Évite de déclencher la même règle deux fois (throttle 60s par règle/agent)
corr_triggered = {}   # (agent, rule) → last_triggered_ts
CORR_THROTTLE  = 60   # secondes entre deux alertes de même règle/agent

# Fenêtre de corrélation par règle (secondes)
WINDOW_REVERSE_SHELL  = 30    # Reverse shell : process + C2 en 30s
WINDOW_DROPPER        = 60    # Dropper : process + fichier en 60s
WINDOW_KILL_CHAIN     = 120   # Kill chain complète en 2 minutes
WINDOW_LATERAL        = 60    # Mouvement latéral : SMB + process en 60s

# Ports considérés comme C2 pour la corrélation
C2_PORTS = {
    4444, 4445, 4446, 1337, 5555, 6666, 7777, 8888,
    9001, 9002, 9090, 50050, 8443, 4443,
}

def corr_add_event(agent, etype, data):
    """
    Ajoute un événement dans la timeline de corrélation d'un agent.
    etype : "PROC_SUSPECT" | "NET_C2" | "FILE_NEW" | "SMB_LATERAL"
    """
    with corr_lock:
        corr_timeline[agent].append({
            "ts":   time.time(),
            "type": etype,
            "data": data,
        })

def _corr_get_window(agent, window_sec):
    """Retourne les événements d'un agent dans la fenêtre de temps donnée."""
    cutoff = time.time() - window_sec
    with corr_lock:
        return [e for e in corr_timeline[agent] if e["ts"] >= cutoff]

def _corr_throttle_ok(agent, rule):
    """Vérifie si l'alerte de corrélation peut être déclenchée (anti-spam)."""
    key = (agent, rule)
    now_ts = time.time()
    last   = corr_triggered.get(key, 0)
    if now_ts - last >= CORR_THROTTLE:
        corr_triggered[key] = now_ts
        return True
    return False

def _fire_corr_alert(agent, rule, title, detail, events):
    """
    Déclenche une alerte de corrélation.
    Stocke comme alerte normale + push dashboard + log.
    """
    if not _corr_throttle_ok(agent, rule):
        return

    # Construire le résumé des événements impliqués
    evts_summary = []
    for e in events:
        ts_str = datetime.datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
        evts_summary.append(f"[{ts_str}] {e['type']}: {e['data'].get('name','?')} "
                            f"pid={e['data'].get('pid','?')}")

    alert = {
        "agent":    agent,
        "time":     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level":    "CRITICAL",
        "category": "CORRELATION",
        "title":    f"[CORRELATION] {title}",
        "detail":   f"{detail} | Événements: {' → '.join(evts_summary[:4])}",
        "extra": {
            "type":        "correlation",
            "rule":        rule,
            "events":      evts_summary,
            "event_count": len(events),
        }
    }

    print(f"  {R}[CORRÉLATION]{RST} {agent} → {rule} : {title}")
    store_alert(alert)

def _run_correlation_rules(agent):
    """
    Applique toutes les règles de corrélation sur la timeline d'un agent.
    Appelé toutes les 5 secondes par le thread de corrélation.
    """

    # ── Règle 1 : REVERSE SHELL ─────────────────────────────────────
    # Process suspect + connexion port C2 dans la même fenêtre de 30s
    events_30 = _corr_get_window(agent, WINDOW_REVERSE_SHELL)
    procs_sus  = [e for e in events_30 if e["type"] == "PROC_SUSPECT"]
    nets_c2    = [e for e in events_30 if e["type"] == "NET_C2"]

    if procs_sus and nets_c2:
        proc = procs_sus[-1]["data"]
        conn = nets_c2[-1]["data"]
        _fire_corr_alert(
            agent, "REVERSE_SHELL",
            f"REVERSE SHELL DETECTE : {proc.get('name','?')} → {conn.get('rip','?')}:{conn.get('rport','?')}",
            f"Process suspect ({proc.get('name','?')} PID {proc.get('pid','?')}) "
            f"a établi une connexion vers port C2 {conn.get('rport','?')} "
            f"dans une fenêtre de {WINDOW_REVERSE_SHELL}s",
            procs_sus + nets_c2
        )

    # ── Règle 2 : DROPPER DE PAYLOAD ────────────────────────────────
    # Nouveau process + nouveau fichier suspect dans 60s
    events_60  = _corr_get_window(agent, WINDOW_DROPPER)
    procs_new  = [e for e in events_60 if e["type"] == "PROC_SUSPECT"]
    files_new  = [e for e in events_60 if e["type"] == "FILE_NEW"]

    if procs_new and files_new:
        proc = procs_new[-1]["data"]
        fil  = files_new[-1]["data"]
        _fire_corr_alert(
            agent, "DROPPER",
            f"DROPPER DETECTE : {proc.get('name','?')} a deposé {fil.get('name','?')}",
            f"Process suspect ({proc.get('name','?')}) suivi d'un nouveau fichier "
            f"({fil.get('name','?')}) dans {WINDOW_DROPPER}s — "
            f"payload probable dans {fil.get('label','?')}",
            procs_new + files_new
        )

    # ── Règle 3 : KILL CHAIN COMPLÈTE ───────────────────────────────
    # Process suspect + connexion C2 + fichier dans 2 minutes
    # C'est le scénario d'attaque complet : exécution → C2 → dropper
    events_120 = _corr_get_window(agent, WINDOW_KILL_CHAIN)
    kc_procs   = [e for e in events_120 if e["type"] == "PROC_SUSPECT"]
    kc_nets    = [e for e in events_120 if e["type"] == "NET_C2"]
    kc_files   = [e for e in events_120 if e["type"] == "FILE_NEW"]

    if kc_procs and kc_nets and kc_files:
        proc = kc_procs[-1]["data"]
        conn = kc_nets[-1]["data"]
        fil  = kc_files[-1]["data"]
        _fire_corr_alert(
            agent, "KILL_CHAIN",
            f"KILL CHAIN COMPLETE — ATTAQUE EN COURS SUR {agent.upper()}",
            f"Séquence complète détectée en {WINDOW_KILL_CHAIN}s : "
            f"1) Process {proc.get('name','?')} "
            f"2) C2 {conn.get('rip','?')}:{conn.get('rport','?')} "
            f"3) Fichier {fil.get('name','?')} déposé — "
            f"INTERVENTION IMMEDIATE REQUISE",
            kc_procs + kc_nets + kc_files
        )

    # ── Règle 4 : MOUVEMENT LATÉRAL ─────────────────────────────────
    # Connexion SMB interne + nouveau process dans 60s
    events_lat = _corr_get_window(agent, WINDOW_LATERAL)
    smb_conns  = [e for e in events_lat if e["type"] == "SMB_LATERAL"]
    lat_procs  = [e for e in events_lat if e["type"] in ("PROC_SUSPECT","PROC_NEW")]

    if smb_conns and lat_procs:
        smb  = smb_conns[-1]["data"]
        proc = lat_procs[-1]["data"]
        _fire_corr_alert(
            agent, "LATERAL_MOVE",
            f"MOUVEMENT LATERAL : SMB {smb.get('rip','?')} + {proc.get('name','?')}",
            f"Connexion SMB vers {smb.get('rip','?')} suivie d'un nouveau process "
            f"({proc.get('name','?')} PID {proc.get('pid','?')}) dans {WINDOW_LATERAL}s — "
            f"propagation latérale probable",
            smb_conns + lat_procs
        )

def _correlation_engine():
    """
    Thread principal du moteur de corrélation.
    Tourne toutes les 5 secondes, applique les règles sur chaque agent actif.
    Léger : seulement des comparaisons de listes en mémoire.
    """
    print(f"  {G}[CORRÉLATION]{RST} Moteur SIEM actif — 4 règles chargées")
    while True:
        time.sleep(5)
        try:
            # Récupérer la liste des agents actifs
            with lock:
                active_agents = list(agents.keys())

            # Appliquer les règles pour chaque agent
            for agent in active_agents:
                try:
                    _run_correlation_rules(agent)
                except Exception as e:
                    pass  # Ne jamais crasher le moteur

            # Nettoyage : supprimer les entrées throttle expirées
            now_ts = time.time()
            expired = [k for k,v in corr_triggered.items()
                       if now_ts - v > CORR_THROTTLE * 2]
            for k in expired:
                corr_triggered.pop(k, None)

        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════
#  SESSIONS
# ══════════════════════════════════════════════════════════════════════

def create_session(user):
    """Crée une session sécurisée après authentification."""
    tok = secrets.token_hex(24)
    with sessions_lock:
        sessions[tok] = {"user":user,"expires":time.time()+SESSION_DURATION}
    return tok

def validate_session(cookie_header):
    """Valide le cookie de session — retourne le nom d'utilisateur ou None."""
    if not cookie_header: return None
    for part in cookie_header.split(";"):
        p = part.strip()
        if p.startswith("fortress_session="):
            tok = p[len("fortress_session="):]
            with sessions_lock:
                s = sessions.get(tok)
                if s and s["expires"] > time.time():
                    return s["user"]
    return None

def check_auth(headers):
    return validate_session(headers.get("Cookie",""))

def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ══════════════════════════════════════════════════════════════════════
#  STATUT AGENT — Online / Offline (vert/rouge sur le dashboard)
# ══════════════════════════════════════════════════════════════════════

def _update_agent_ping(agent_name):
    """Met à jour le timestamp du dernier message d'un agent."""
    with lock:
        agent_last_ping[agent_name] = time.time()
        if agent_name in agents:
            agents[agent_name]["online"] = True

def _agent_watchdog():
    """
    Thread watchdog : vérifie toutes les 10s quels agents sont offline.
    Un agent est offline s'il n'a pas envoyé de message depuis AGENT_TIMEOUT secondes.
    Push la mise à jour aux dashboards connectés.
    """
    while True:
        time.sleep(10)
        changed = False
        now_ts  = time.time()
        with lock:
            for name, ag in agents.items():
                last   = agent_last_ping.get(name, 0)
                online = (now_ts - last) < AGENT_TIMEOUT
                if ag.get("online") != online:
                    ag["online"] = online
                    changed = True
        if changed:
            push_agent_status()

def push_agent_status():
    """Envoie le statut complet des agents à tous les dashboards."""
    with lock:
        msg = {"type":"agents_update","agents":dict(agents),"stats":dict(stats)}
    _push(msg)

# ══════════════════════════════════════════════════════════════════════
#  STOCKAGE ET PUSH DES ALERTES
# ══════════════════════════════════════════════════════════════════════

def store_alert(a):
    """
    Traite une alerte reçue d'un agent :
    - Types spéciaux (sysinfo, proc_list, conn_list) → mis à jour sans stocker
    - Alertes normales → stockées, loguées, pushées aux dashboards
    """
    lvl   = a.get("level","INFO")
    extra = a.get("extra",{})
    atype = extra.get("type","")
    ag    = a.get("agent","?")

    # Mise à jour du ping agent (il est vivant)
    _update_agent_ping(ag)

    with lock:
        # ── Sysinfo (CPU/RAM/Disk) — pas stocké dans les alertes ──────
        if atype == "sysinfo":
            agent_sysinfo[ag] = extra
            if ag not in agents:
                agents[ag] = {"last_seen":"","os":extra.get("os","?"),
                              "count":0,"online":True}
            agents[ag]["last_seen"] = a.get("time","?")
            _push({"type":"sysinfo_update","agent":ag,"data":extra})
            return

        # ── Liste processus ────────────────────────────────────────────
        elif atype == "proc_list":
            agent_procs[ag] = extra.get("procs",[])
            _push({"type":"procs_update","agent":ag,"procs":agent_procs[ag]})
            return

        # ── Liste connexions réseau ────────────────────────────────────
        elif atype == "conn_list":
            agent_conns[ag] = extra.get("connections",[])
            _push({"type":"conns_update","agent":ag,"conns":agent_conns[ag]})
            return

        # ── Alerte normale → stockage ──────────────────────────────────
        alerts.append(a)
        stats["total"] += 1
        if lvl in stats: stats[lvl] += 1

        if ag not in agents:
            agents[ag] = {"last_seen":"","os":extra.get("os","?"),
                          "count":0,"online":True}
        agents[ag]["last_seen"] = a.get("time","?")
        agents[ag]["count"]    += 1

    # ── Alimentation du moteur de corrélation ─────────────────────────
    # On classe chaque alerte dans un type de corrélation
    # pour que le moteur SIEM puisse croiser les événements
    category = a.get("category","")
    extra2   = a.get("extra",{})
    atype2   = extra2.get("type","")

    # Événement : processus suspect
    if category == "PROCESS" and lvl == "CRITICAL":
        corr_add_event(ag, "PROC_SUSPECT", {
            "name": extra2.get("name", a.get("title","?")),
            "pid":  extra2.get("pid","?"),
            "cmd":  extra2.get("cmd",""),
        })

    # Événement : nouveau processus (pour règle mouvement latéral)
    elif atype2 == "new_proc":
        corr_add_event(ag, "PROC_NEW", {
            "name": extra2.get("name","?"),
            "pid":  extra2.get("pid","?"),
        })

    # Événement : connexion vers port C2
    elif category in ("NET_TCP","NET_UDP") and lvl == "CRITICAL":
        rport = extra2.get("rport", 0)
        if rport in C2_PORTS:
            corr_add_event(ag, "NET_C2", {
                "rip":   extra2.get("rip","?"),
                "rport": rport,
                "proc":  extra2.get("proc","?"),
                "pid":   extra2.get("pid","?"),
            })

    # Événement : nouveau fichier suspect (téléchargement ou drop)
    elif category == "FILE" and atype2 == "new_file":
        corr_add_event(ag, "FILE_NEW", {
            "name":  extra2.get("name","?"),
            "path":  extra2.get("path","?"),
            "label": extra2.get("label","?"),
            "ext":   extra2.get("ext","?"),
        })

    # Événement : connexion SMB interne (mouvement latéral)
    elif atype2 == "smb_lateral":
        corr_add_event(ag, "SMB_LATERAL", {
            "rip":  extra2.get("rip","?"),
            "proc": extra2.get("proc","?"),
            "pid":  extra2.get("pid","?"),
        })

    # Événement : PowerShell malveillant → aussi classé comme PROC_SUSPECT
    elif category == "POWERSHELL" and lvl == "CRITICAL":
        corr_add_event(ag, "PROC_SUSPECT", {
            "name": "powershell.exe",
            "pid":  extra2.get("pid","?"),
            "cmd":  extra2.get("cmd",""),
        })

    # Log sur disque
    try:
        with open(LOG_FILE,"a",encoding="utf-8") as f:
            f.write(json.dumps(a, ensure_ascii=False)+"\n")
    except Exception: pass

    _push(a)

def _push(msg):
    """Envoie un message JSON à tous les clients dashboard connectés via WebSocket."""
    if not ws_loop: return
    txt = json.dumps(msg, ensure_ascii=False)

    async def _send_all():
        dead = set()
        with dash_clients_lock:
            clients = list(dash_clients)
        for ws in clients:
            try:
                await ws.send(txt)
            except Exception:
                dead.add(ws)
        if dead:
            with dash_clients_lock:
                dash_clients.difference_update(dead)

    asyncio.run_coroutine_threadsafe(_send_all(), ws_loop)

# ══════════════════════════════════════════════════════════════════════
#  HANDLER AGENTS HTTP (port 9999)
#  Les agents envoient leurs alertes via POST /alert
# ══════════════════════════════════════════════════════════════════════

class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # Silence les logs HTTP

    def do_POST(self):
        if self.path == "/alert":
            try:
                n = int(self.headers.get("Content-Length",0))
                a = json.loads(self.rfile.read(n))
                store_alert(a)
                self._ok({"status":"ok"})
            except Exception as e:
                self._ok({"error":str(e)},400)
        else:
            self._ok({"error":"not found"},404)

    def do_GET(self):
        if self.path == "/status":
            with lock:
                self._ok({"stats":dict(stats),"agents":dict(agents)})
        else:
            self._ok({"error":"not found"},404)

    def _ok(self, d, code=200):
        b = json.dumps(d).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)

# ══════════════════════════════════════════════════════════════════════
#  WEBSOCKET SERVER (port 9998)
#  Gère DEUX types de clients :
#  - /dashboard → push temps réel vers le navigateur
#  - /agent     → canal de commandes vers les agents Windows
# ══════════════════════════════════════════════════════════════════════

async def ws_handler(websocket):
    """Dispatcher WebSocket — route selon le path."""
    path   = getattr(websocket,'path','/')
    if hasattr(websocket,'request'):
        path = websocket.request.path
    parsed = urlparse(path)
    qs     = parse_qs(parsed.query)
    role   = parsed.path.strip("/")

    if role == "dashboard":
        await _handle_dashboard_ws(websocket, qs)
    elif role == "agent":
        await _handle_agent_ws(websocket, qs)
    else:
        await websocket.close(1008, "Unknown role")

async def _handle_dashboard_ws(websocket, qs):
    """
    Connexion WebSocket d'un client dashboard (navigateur).
    - Vérifie la session
    - Envoie l'état complet initial
    - Reste connecté pour pousser les mises à jour en temps réel
    - Reçoit les commandes (KILL, BLOCK, UNBLOCK)
    """
    # Vérification session
    session_tok = qs.get("session",[""])[0]
    user = None
    with sessions_lock:
        s = sessions.get(session_tok)
        if s and s["expires"] > time.time():
            user = s["user"]
    if not user:
        await websocket.close(1008,"Unauthorized"); return

    # Enregistrement du client
    with dash_clients_lock:
        dash_clients.add(websocket)

    # Envoi état complet initial
    with lock:
        init = {
            "type":    "init",
            "alerts":  list(reversed(list(alerts)))[:500],
            "agents":  dict(agents),
            "stats":   dict(stats),
            "sysinfo": dict(agent_sysinfo),
            "procs":   dict(agent_procs),
            "conns":   dict(agent_conns),
            "blocked": list(blocked_ips),
        }
    await websocket.send(json.dumps(init, ensure_ascii=False))

    try:
        async for raw in websocket:
            try:
                cmd = json.loads(raw)
                await _handle_dash_command(cmd, user)
            except Exception: pass
    except Exception: pass
    finally:
        with dash_clients_lock:
            dash_clients.discard(websocket)

async def _handle_agent_ws(websocket, qs):
    """
    Connexion WebSocket d'un agent distant.
    - Enregistre l'agent comme connecté (WS LIVE)
    - Garde le canal ouvert pour envoyer des ordres
    - Met l'agent offline à la déconnexion
    """
    agent_name = qs.get("name",["unknown"])[0]

    with agent_ws_lock:
        agent_ws[agent_name] = websocket
    with lock:
        if agent_name not in agents:
            agents[agent_name] = {"last_seen":"","os":"?","count":0,"online":True}
        agents[agent_name]["ws_connected"] = True
        agents[agent_name]["online"]       = True
    push_agent_status()

    try:
        async for raw in websocket:
            try:
                a = json.loads(raw)
                store_alert(a)
            except Exception: pass
    except Exception: pass
    finally:
        with agent_ws_lock:
            agent_ws.pop(agent_name, None)
        with lock:
            if agent_name in agents:
                agents[agent_name]["ws_connected"] = False
        push_agent_status()

async def _handle_dash_command(cmd, user):
    """
    Exécute une commande reçue du dashboard.
    KILL → transmet à l'agent via son canal WS
    BLOCK → bloque l'IP sur tous les agents + stocke
    UNBLOCK → débloque
    """
    action = cmd.get("action","")
    agent  = cmd.get("agent","")

    if action == "KILL":
        pid = cmd.get("pid")
        if pid:
            with agent_ws_lock:
                ws = agent_ws.get(agent)
            if ws:
                try: await ws.send(json.dumps({"action":"KILL","pid":pid}))
                except Exception: pass
            store_alert({
                "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                "title":f"KILL PID {pid} envoye a {agent}",
                "detail":f"Operateur {user}",
                "extra":{"pid":pid,"agent":agent,"action":"KILL"}
            })

    elif action == "BLOCK":
        ip     = cmd.get("ip","")
        reason = cmd.get("reason","dashboard")
        if ip:
            with lock: blocked_ips.add(ip)
            # Propager BLOCK à tous les agents connectés
            with agent_ws_lock:
                for ws in list(agent_ws.values()):
                    try: await ws.send(json.dumps(
                        {"action":"BLOCK_IP","ip":ip,"reason":reason}))
                    except: pass
            store_alert({
                "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                "title":f"IP BLOQUEE : {ip}","detail":f"Operateur {user} — {reason}",
                "extra":{"ip":ip,"action":"BLOCK"}
            })
            # Push liste bloquées mise à jour
            _push({"type":"blocked_update","blocked":list(blocked_ips)})

    elif action == "UNBLOCK":
        ip = cmd.get("ip","")
        if ip:
            with lock: blocked_ips.discard(ip)
            with agent_ws_lock:
                for ws in list(agent_ws.values()):
                    try: await ws.send(json.dumps({"action":"UNBLOCK_IP","ip":ip}))
                    except: pass
            store_alert({
                "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                "title":f"IP DEBLOQUEE : {ip}","detail":f"Operateur {user}",
                "extra":{"ip":ip,"action":"UNBLOCK"}
            })
            _push({"type":"blocked_update","blocked":list(blocked_ips)})

def start_ws_thread():
    """Démarre le serveur WebSocket dans son propre event loop asyncio."""
    global ws_loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    ws_loop = loop

    async def _run():
        async with ws_serve(ws_handler,"0.0.0.0",WS_PORT):
            await asyncio.Future()

    loop.run_until_complete(_run())

# ══════════════════════════════════════════════════════════════════════
#  HANDLER DASHBOARD HTTP (port 31337)
#  Sert le dashboard HTML, gère le login, les API REST
# ══════════════════════════════════════════════════════════════════════

class DashHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location",loc)
        self.end_headers()

    def _json(self, d, code=200):
        b = json.dumps(d, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _html(self, content, code=200):
        b = content if isinstance(content,bytes) else content.encode()
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _serve_file(self, filename):
        """Lit un fichier HTML depuis le même dossier que le script."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        try:
            with open(path,"rb") as f: return f.read()
        except FileNotFoundError: return None

    # ── GET ────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        # ── Page racine → login ou redirect dashboard ──────────────────
        if path in ("/",""):
            user = check_auth(self.headers)
            if user:
                self._redirect("/dashboard"); return
            token = qs.get("token",[""])[0]
            if token == ACCESS_TOKEN:
                content = self._serve_file("login.html")
                if content is None:
                    self._html(b"<h1>login.html introuvable</h1>",500); return
                # Injecter le token pour le JS de login
                content = content.replace(
                    b"</body>",
                    f'<script>window._ACCESS_TOKEN="{ACCESS_TOKEN}";</script></body>'.encode()
                )
                self._html(content)
            else:
                # Page 403 custom
                self._html(b"""<!DOCTYPE html><html><head><title>403</title>
<style>body{background:#050c0f;color:#00d4aa;font-family:monospace;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
h1{font-size:80px;opacity:.15}p{opacity:.4;letter-spacing:3px}</style></head>
<body><div style="text-align:center"><h1>403</h1><p>ACCESS DENIED</p></div></body></html>""",403)
            return

        # ── Dashboard principal ────────────────────────────────────────
        if path == "/dashboard":
            user = check_auth(self.headers)
            if not user:
                self._redirect(f"/?token={ACCESS_TOKEN}"); return

            content = self._serve_file("dashboard_v5.html")
            if content is None:
                self._html(b"<h1>dashboard_v5.html introuvable</h1>",500); return

            # Injecter WS_PORT et session dans la page
            cookie   = self.headers.get("Cookie","")
            sess_tok = ""
            for part in cookie.split(";"):
                p = part.strip()
                if p.startswith("fortress_session="):
                    sess_tok = p[len("fortress_session="):]

            inject = (
                f'<script>'
                f'window._WS_PORT={WS_PORT};'
                f'window._WS_SESSION="{sess_tok}";'
                f'</script></body>'
            ).encode()
            content = content.replace(b"</body>", inject)
            self._html(content)
            return

        # ── API REST (authentification requise) ───────────────────────
        if path.startswith("/api/"):
            # Login et logout sont publics
            if path not in ("/api/login","/api/logout"):
                if not check_auth(self.headers):
                    self._json({"error":"unauthorized"},401); return

            if path == "/api/alerts":
                limit = min(int(qs.get("limit",["300"])[0]),2000)
                lvl   = qs.get("lvl",["ALL"])[0]
                cat   = qs.get("cat",["ALL"])[0]
                with lock:
                    snap = list(alerts)
                if lvl != "ALL": snap = [a for a in snap if a.get("level")==lvl]
                if cat != "ALL": snap = [a for a in snap if a.get("category")==cat]
                self._json({"alerts":list(reversed(snap))[:limit],"total":len(snap)})

            elif path == "/api/stats":
                with lock:
                    self._json({"stats":dict(stats),"agents":dict(agents)})

            elif path == "/api/agents":
                with lock:
                    self._json({"agents":dict(agents)})

            elif path == "/api/sysinfo":
                ag = qs.get("agent",[""])[0]
                with lock:
                    d = {"agent":ag,"data":agent_sysinfo.get(ag,{})} if ag \
                        else {"all":dict(agent_sysinfo)}
                self._json(d)

            elif path == "/api/procs":
                ag = qs.get("agent",[""])[0]
                with lock:
                    d = {"agent":ag,"procs":agent_procs.get(ag,[])} if ag \
                        else {"all":dict(agent_procs)}
                self._json(d)

            elif path == "/api/conns":
                ag = qs.get("agent",[""])[0]
                with lock:
                    d = {"agent":ag,"conns":agent_conns.get(ag,[])} if ag \
                        else {"all":dict(agent_conns)}
                self._json(d)

            elif path == "/api/blocked":
                with lock:
                    self._json({"blocked":list(blocked_ips)})

            elif path == "/api/logs":
                # Dernières lignes du fichier log
                try:
                    limit = int(qs.get("limit",["200"])[0])
                    lines = []
                    if os.path.exists(LOG_FILE):
                        with open(LOG_FILE,"r",encoding="utf-8") as f:
                            lines = f.readlines()[-limit:]
                    self._json({"lines":[json.loads(l) for l in lines if l.strip()]})
                except Exception as e:
                    self._json({"error":str(e)},500)

            else:
                self._json({"error":"not found"},404)
            return

        self.send_response(404); self.end_headers()

    # ── POST ────────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        # ── Login ──────────────────────────────────────────────────────
        if path == "/api/login":
            try:
                n = int(self.headers.get("Content-Length",0))
                d = json.loads(self.rfile.read(n))
                user  = d.get("user","").strip()
                pwd   = d.get("pwd","")
                token = d.get("token","")

                if token != ACCESS_TOKEN:
                    self._json({"ok":False,"error":"token invalide"},403); return

                h = hashlib.sha256(pwd.encode()).hexdigest()
                if user in CREDENTIALS and CREDENTIALS[user] == h:
                    tok = create_session(user)
                    b   = json.dumps({"ok":True}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Content-Length",str(len(b)))
                    self.send_header("Set-Cookie",
                        f"fortress_session={tok}; Path=/; HttpOnly; "
                        f"SameSite=Strict; Max-Age={SESSION_DURATION}")
                    self.end_headers()
                    self.wfile.write(b)
                else:
                    self._json({"ok":False,"error":"identifiants invalides"},401)
            except Exception as e:
                self._json({"error":str(e)},400)
            return

        # ── Logout ─────────────────────────────────────────────────────
        if path == "/api/logout":
            cookie = self.headers.get("Cookie","")
            for part in cookie.split(";"):
                p = part.strip()
                if p.startswith("fortress_session="):
                    tok = p[len("fortress_session="):]
                    with sessions_lock: sessions.pop(tok,None)
            b = json.dumps({"ok":True}).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(b)))
            self.send_header("Set-Cookie","fortress_session=; Path=/; Max-Age=0")
            self.end_headers()
            self.wfile.write(b)
            return

        # ── Auth requise pour les actions ──────────────────────────────
        user = check_auth(self.headers)
        if not user:
            self._json({"error":"unauthorized"},401); return

        # ── Kill processus ─────────────────────────────────────────────
        if path == "/api/kill":
            try:
                n  = int(self.headers.get("Content-Length",0))
                d  = json.loads(self.rfile.read(n))
                pid = int(d.get("pid",0))
                ag  = d.get("agent","")
                with agent_ws_lock:
                    ws = agent_ws.get(ag)
                if ws and ws_loop:
                    asyncio.run_coroutine_threadsafe(
                        ws.send(json.dumps({"action":"KILL","pid":pid})), ws_loop)
                store_alert({
                    "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                    "title":f"KILL PID {pid} → {ag}","detail":f"Operateur {user}",
                    "extra":{"pid":pid,"action":"kill"}
                })
                self._json({"status":"kill_sent","pid":pid})
            except Exception as e:
                self._json({"error":str(e)},400)

        # ── Bloquer IP ─────────────────────────────────────────────────
        elif path == "/api/block":
            try:
                n  = int(self.headers.get("Content-Length",0))
                d  = json.loads(self.rfile.read(n))
                ip = d.get("ip","")
                reason = d.get("reason","dashboard")
                with lock: blocked_ips.add(ip)
                # Propager à tous les agents
                if ws_loop:
                    async def _block_all():
                        with agent_ws_lock:
                            wss = list(agent_ws.values())
                        for ws in wss:
                            try: await ws.send(json.dumps(
                                {"action":"BLOCK_IP","ip":ip,"reason":reason}))
                            except: pass
                    asyncio.run_coroutine_threadsafe(_block_all(), ws_loop)
                store_alert({
                    "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                    "title":f"IP BLOQUEE : {ip}","detail":f"Operateur {user} — {reason}",
                    "extra":{"ip":ip,"action":"block"}
                })
                _push({"type":"blocked_update","blocked":list(blocked_ips)})
                self._json({"status":"blocked","ip":ip})
            except Exception as e:
                self._json({"error":str(e)},400)

        # ── Débloquer IP ───────────────────────────────────────────────
        elif path == "/api/unblock":
            try:
                n  = int(self.headers.get("Content-Length",0))
                d  = json.loads(self.rfile.read(n))
                ip = d.get("ip","")
                with lock: blocked_ips.discard(ip)
                if ws_loop:
                    async def _unblock_all():
                        with agent_ws_lock:
                            wss = list(agent_ws.values())
                        for ws in wss:
                            try: await ws.send(json.dumps({"action":"UNBLOCK_IP","ip":ip}))
                            except: pass
                    asyncio.run_coroutine_threadsafe(_unblock_all(), ws_loop)
                store_alert({
                    "agent":"FORTRESS","time":_now(),"level":"INFO","category":"RESPONSE",
                    "title":f"IP DEBLOQUEE : {ip}","detail":f"Operateur {user}",
                    "extra":{"ip":ip,"action":"unblock"}
                })
                _push({"type":"blocked_update","blocked":list(blocked_ips)})
                self._json({"status":"unblocked","ip":ip})
            except Exception as e:
                self._json({"error":str(e)},400)

        else:
            self.send_response(404); self.end_headers()

# ══════════════════════════════════════════════════════════════════════
#  BANNIÈRE
# ══════════════════════════════════════════════════════════════════════

def banner():
    os.system("clear" if os.name!="nt" else "cls")
    print(f"{R}{BLD}")
    print("  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║  ⚔️  12ak_H4ck Tools — Serveur Central v5.1  🛡️           ║")
    print("  ║  Blue Team SOC — WebSocket + IPS + SIEM Corrélation     ║")
    print("  ╚═══════════════════════════════════════════════════════════╝")
    print(f"{RST}")
    print(f"  {G}[+]{RST} Agents HTTP  → port {C}{AGENT_PORT}{RST}")
    print(f"  {G}[+]{RST} WebSocket WS → port {C}{WS_PORT}{RST}")
    print(f"  {G}[+]{RST} Dashboard    → port {C}{DASH_PORT}{RST}")
    print(f"  {G}[+]{RST} Log fichier  → {C}{LOG_FILE}{RST}")
    print(f"\n  {Y}[!]{RST} URL d'acces securisee :\n")
    print(f"  {R}{BLD}  http://0.0.0.0:{DASH_PORT}/?token={ACCESS_TOKEN}{RST}")
    print(f"\n  {Y}  Garde ce token secret !{RST}")
    print(f"\n{DG}{'─'*61}{RST}\n")

# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def run_http(handler_class, port):
    """Lance un serveur HTTP dans un thread bloquant."""
    srv = HTTPServer(("0.0.0.0",port), handler_class)
    srv.serve_forever()

if __name__ == "__main__":
    banner()

    if not WS_OK:
        print(f"  {R}[!]{RST} pip install websockets")
        sys.exit(1)

    # Thread HTTP agents (port 9999)
    t1 = threading.Thread(target=run_http, args=(AgentHandler,AGENT_PORT), daemon=True)
    # Thread HTTP dashboard (port 31337)
    t2 = threading.Thread(target=run_http, args=(DashHandler,DASH_PORT),  daemon=True)
    # Thread WebSocket (port 9998)
    t3 = threading.Thread(target=start_ws_thread, daemon=True)
    # Thread watchdog statut agents (vert/rouge)
    t4 = threading.Thread(target=_agent_watchdog,    daemon=True, name="watchdog")
    # Thread moteur de corrélation SIEM
    t5 = threading.Thread(target=_correlation_engine, daemon=True, name="correlation")

    t1.start(); t2.start(); t3.start(); t4.start(); t5.start()

    print(f"  {G}[+]{RST} Agents HTTP  actif")
    print(f"  {G}[+]{RST} Dashboard    actif")
    print(f"  {G}[+]{RST} WebSocket    actif")
    print(f"  {G}[+]{RST} Watchdog     actif (statut agents vert/rouge)")
    print(f"  {G}[+]{RST} Corrélation  actif (SIEM — 4 règles)")
    print(f"\n  {G}[*]{RST} Systeme operationnel !\n")

    try:
        while True: time.sleep(60)
    except KeyboardInterrupt:
        print(f"\n  {Y}[!]{RST} Serveur arrete.")
