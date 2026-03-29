# 12ak-FORTERESS

Blue Team 

# ⚔️ 12ak_H4ck Forteresse SOC 🛡️

> **Système EDR/SIEM Blue Team — Endpoint Detection & Response**
> Architecture Agent / Serveur / Dashboard — Surveillance temps réel, IPS automatique, moteur de corrélation SIEM, détection fileless & payloads in-memory

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Agent-v6.0-red?style=flat-square)
![Version](https://img.shields.io/badge/Serveur-v5.1-orange?style=flat-square)

---

## 📖 Présentation

**12ak_H4ck Forteresse SOC** est un outil de surveillance de sécurité complet développé en Python pur dans un contexte Blue Team / CTF. Il permet de **monitorer en temps réel** un ou plusieurs endpoints Windows/Linux depuis un dashboard web centralisé hébergé sur un serveur Linux/AWS EC2.

Le projet repose sur une architecture **3 couches** :

```
┌─────────────────────────────────────────────────────────────────────┐
│  PC Windows / Linux — Agent v6.0  (agent_v6.py)                    │
│  CPU · RAM · Disk · Processus · Réseau · Fichiers · Mémoire RWX    │
│  IPS local : blocage firewall automatique · Kill distant            │
│  60+ signatures PS · LOLBins · AMSI · Injection · Persistence       │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ HTTP POST /alert  (port 9999)
                            │ WebSocket /agent  (port 9998)
┌───────────────────────────▼─────────────────────────────────────────┐
│  Serveur Linux / AWS EC2 — Serveur v5.1  (server_v5.py)            │
│  Collecte · Sessions · Push WebSocket · Watchdog agents             │
│  Moteur SIEM : 4 règles de corrélation · Kill Chain detection       │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ WebSocket /dashboard  (port 9998)
                            │ HTTP REST API  (port 31337)
┌───────────────────────────▼─────────────────────────────────────────┐
│  Navigateur Web — Dashboard v5  (dashboard_v5.html)                 │
│  6 pages · Alertes · Réseau · Processus · Fichiers · Logs · SIEM   │
│  Bannière Kill Chain · IPs bloquées · Badge CORRELATION             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Fonctionnalités complètes

### 🖥️ Agent v6.0 — Endpoint (Windows/Linux)

#### Module 1 — Surveillance Système
- **CPU / RAM / Disque** — métriques toutes les 5 secondes
- Historique CPU sur 1 minute — alerte si moyenne > 85%
- Alerte RAM si > 90% prolongé
- Détection disque plein > 95% par partition
- Statistiques réseau I/O (bytes envoyés / reçus)

#### Module 2 — Processus — Détection Avancée
- Liste complète : PID réel, CPU%, RAM%, User, chemin exe
- **Noms malveillants connus** — 30+ outils offensifs détectés :
  `mimikatz`, `meterpreter`, `lazagne`, `bloodhound`, `rubeus`, `psexec`, `netcat`, `procdump`, `winpeas`, `cobaltstrike`, `empire`, `sharphound`, `certify`, `seatbelt`, `wce`, `fgdump`, `pwdump`...
- **Parent Process Spoofing** — Word/Excel/Outlook qui lance cmd.exe ou powershell → macro malveillante détectée
- **Process Hollowing** — processus système (svchost, lsass) avec enfants shells suspects
- **Kill automatique** des outils de credential dumping avérés (mimikatz, lazagne, wce...)
- Nouveau processus → alerte INFO avec chemin et user

#### Module 3 — Réseau — Connexions Actives
- Toutes les connexions TCP/UDP (IP locale, distante, port, protocole, PID, processus)
- **Nouvelle connexion externe** → alerte immédiate
- **Ports suspects** — 35+ ports C2/RAT/proxy/TOR détectés :
  `4444` (Meterpreter), `1337`, `50050` (Cobalt Strike), `9050` (TOR), `5900` (VNC), `8443` (Empire)...
- **C2 Beacon heuristique** — processus système contactant internet sur port non-standard
- **Latéralisation SMB** — processus non-système connecté à SMB (port 445)
- **Isolation automatique IPS** — IP bloquée en entrée ET sortie via firewall OS
- **Whitelist infrastructure** — IP serveur et ports de l'outil jamais alertés

#### Module 4 — Fichiers Utilisateur — Temps Réel
- Dossiers surveillés : **Downloads, Desktop, Documents, AppData/Temp, AppData/Roaming, Music, Videos**
- Aucun dossier système — uniquement les fichiers personnels
- **Fenêtre de 5 minutes** — tous les nouveaux fichiers signalés (téléchargements inclus)
- **Double extension** : `document.pdf.exe` → CRITICAL
- **Nom déguisé** : `svch0st.exe`, `explorer32.exe` → CRITICAL
- **Signatures Metasploit** dans le contenu binaire :
  - Prologue Meterpreter x64 `\xfc\x48\x83\xe4\xf0`
  - Prologue Meterpreter x86 `\xfc\xe8\x82\x00\x00`
  - PE header dans fichier non-exe
  - Strings `ReflectiveDll`, `stdapi_`, `meterpreter`, `MSFV`
- **Modification détectée** via hash MD5
- Labels clairs : TELECHARGEMENT / BUREAU / DOCUMENTS / TEMP

#### Module 5 — PowerShell & Commandes — 60+ Signatures

**Obfuscation :**
| Technique | Signature | Exemple |
|-----------|-----------|---------|
| Base64 encodé | `PS_ENCODED_CMD` | `-enc JABXAG...` |
| Char codes | `CHAR_OBFUSCATION` | `[char]73+[char]69+[char]88` |
| Tick obfuscation | `TICK_OBFUSCATION` | `i\`e\`x` |
| Reverse string | `REVERSE_STRING` | `-join('abc'[5..0])` |
| Env var | `ENV_OBFUSCATION` | `$env:comspec[4,15,25]-join''` |
| ScriptBlock | `SCRIPTBLOCK_CREATE` | `[ScriptBlock]::Create(...)` |

**Commande classique payload :**
| Commande | Signature |
|----------|-----------|
| `-ExecutionPolicy Bypass -WindowStyle Hidden` | `EXECPOLICY_BYPASS` + `HIDDEN_WINDOW` |
| `-ep bypass -w h` | `EXECPOLICY_BYPASS` + `STEALTH_LAUNCH` |
| `-NoProfile -NonInteractive` | `STEALTH_LAUNCH` |
| Combinaison complète | `PAYLOAD_CLASSIC` |

**Download & Execute :**
| Technique | Signature |
|-----------|-----------|
| `IEX (New-Object Net.WebClient).DownloadString(...)` | `IEX_EXEC` + `DOWNLOAD_EXEC` |
| `Invoke-WebRequest` / `wget` / `curl` | `DOWNLOAD_HTTP` |
| `Start-BitsTransfer` | `BITS_TRANSFER` |

**LOLBins — Living off the Land :**
| Binaire | Usage malveillant | Signature |
|---------|-------------------|-----------|
| `certutil` | `-decode` / `-urlcache` pour télécharger | `CERTUTIL_LOLBIN` |
| `mshta` | Exécute HTA depuis internet | `MSHTA_LOLBIN` |
| `regsvr32` | Squiblydoo — bypass AppLocker | `REGSVR32_LOLBIN` |
| `wmic` | `process call create` / XSL transform | `WMIC_EXEC` / `WMIC_XSL` |
| `rundll32` | Exécute JS ou DLL distante | `RUNDLL32_JS` / `RUNDLL32_REMOTE` |
| `msiexec` | Installe MSI depuis internet | `MSIEXEC_REMOTE` |
| `bitsadmin` | Téléchargement discret | `BITSADMIN_LOLBIN` |
| `cmstp` | Bypass AppLocker | `CMSTP_LOLBIN` |
| `forfiles` | Contourne restrictions | `FORFILES_LOLBIN` |

**AMSI Bypass :**
| Technique | Signature |
|-----------|-----------|
| Patch `AmsiUtils` / `AmsiInitFailed` | `AMSI_BYPASS` |
| Patch `AmsiScanBuffer` via `Marshal.Copy` | `AMSI_PATCH` |
| Réflexion `System.Management.Automation.Amsi` | `AMSI_BYPASS` |

**Injection Mémoire :**
| API / Technique | Signature |
|-----------------|-----------|
| `VirtualAlloc` RWX (0x40) | `VIRTUALALLOC` / `RWX_ALLOC` |
| `WriteProcessMemory` | `PROCESS_INJECT` |
| `CreateRemoteThread` | `REMOTE_THREAD` |
| `NtCreateThread` / `NtCreateThreadEx` | `NT_INJECT` |
| P/Invoke via `Add-Type -TypeDefinition` | `PINVOKE_ADDTYPE` |
| `GetProcAddress` / `LoadLibrary` | `API_RESOLVE` |

**Persistence :**
| Mécanisme | Signature |
|-----------|-----------|
| Registry `CurrentVersion\Run` | `REGISTRY_PERSIST` |
| `schtasks /create` / `New-ScheduledTask` | `SCHTASK_PERSIST` |
| Startup folder `.lnk` | `STARTUP_PERSIST` |

**Désactivation défenses :**
| Action | Signature |
|--------|-----------|
| `Set-MpPreference -DisableRealTimeMonitoring` | `DEFENDER_DISABLE` |
| `Add-MpPreference -ExclusionPath` | `DEFENDER_EXCLUSION` |
| `sc stop/delete WinDefend` | `WINDEFEND_STOP` |
| `netsh advfirewall set allprofiles state off` | `FIREWALL_DISABLE` |
| `Clear-EventLog` / `wevtutil cl` | `EVENTLOG_CLEAR` |

**Credential Dumping :**
| Technique | Signature |
|-----------|-----------|
| `Invoke-Mimikatz` | `MIMIKATZ_PS` |
| `sekurlsa::` / `kerberos::ptt` | `MIMIKATZ_CMD` |
| `lsadump::` / `dpapi::` | `MIMIKATZ_MODULE` |
| LSASS minidump | `LSASS_DUMP` |

#### Module 6 — Mémoire — Détection Fileless & In-Memory
- **Régions mémoire RWX** (Read+Write+Execute) > 100 KB → shellcode injecté probable
- **Processus fileless** → fichier exe supprimé après lancement (payload in-memory)
- **Processus système mal placés** → svchost/lsass depuis chemin non-System32
- Whitelist automatique : Chrome, Firefox, Python, Java, Node (JIT légitimes)
- Scan toutes les 10 secondes — impact CPU minimal

#### Module 7 — Audit PowerShell (Windows — Event Log)
- Lecture du **Script Block Logging** (wevtutil)
- Détection des 60+ patterns dans les 30 derniers événements
- Toutes les 60 secondes

#### Module 8 — Windows Defender Check
- Statut `AntivirusEnabled`, `RealTimeProtectionEnabled`, `AMServiceEnabled`
- Alerte CRITICAL si protection temps réel désactivée
- Toutes les 60 secondes

#### IPS — Intrusion Prevention System
- **Blocage firewall automatique** via Windows Firewall (netsh) ou iptables
- Isolation complète : règles entrée ET sortie simultanées
- **Kill automatique** des outils de credential dumping
- **Whitelist immuable** — IP serveur + ports infra jamais bloqués
- Déblocage depuis le dashboard propagé à tous les agents

#### Telegram (optionnel)
- Notifications immédiates sur toutes les alertes CRITICAL
- Activation/désactivation sans redémarrage
- Configuration : token BotFather + chat_id

#### Throttle Anti-Spam
- Même alerte envoyée **max 1 fois toutes les 30 secondes**
- Évite l'inondation du dashboard

---

### 🖧 Serveur v5.1 — Collecte & SIEM

#### Architecture
- **3 serveurs parallèles** : HTTP agents (9999), WebSocket (9998), Dashboard (31337)
- **WebSocket bidirectionnel** : push temps réel → dashboard + ordres → agents
- **Watchdog agents** : détecte offline (> 30s) → indicateur rouge dashboard
- **5000 alertes** en RAM + log fichier JSON
- **Authentification** : token URL secret + session cookie HttpOnly SHA-256

#### 🧠 Moteur de Corrélation SIEM — 4 Règles

Le moteur analyse une **fenêtre glissante** d'événements par agent et croise les alertes pour détecter les attaques complexes qu'une détection isolée manquerait.

**Règle 1 — REVERSE_SHELL** (fenêtre 30s)
```
Process suspect (mimikatz, powershell...) 
    + Connexion vers port C2 (4444, 50050...)
→ ALERTE CRITIQUE : "REVERSE SHELL DÉTECTÉ"
```

**Règle 2 — DROPPER** (fenêtre 60s)
```
Process suspect 
    + Nouveau fichier déposé (Downloads, Desktop...)
→ ALERTE CRITIQUE : "DROPPER DÉTECTÉ — process X a déposé payload.exe"
```

**Règle 3 — KILL_CHAIN** (fenêtre 2 min)
```
Process suspect 
    + Connexion C2 
    + Nouveau fichier
→ ALERTE CRITIQUE : "KILL CHAIN COMPLÈTE — ATTAQUE EN COURS"
→ Bannière rouge clignotante sur le dashboard
→ Notification navigateur
```

**Règle 4 — LATERAL_MOVE** (fenêtre 60s)
```
Connexion SMB interne (port 445) 
    + Nouveau processus
→ ALERTE CRITIQUE : "MOUVEMENT LATÉRAL — propagation réseau probable"
```

Les alertes de corrélation apparaissent avec le badge **⚡ SIEM** violet et un throttle de 60s pour éviter le spam.

#### API REST
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/alerts` | GET | Alertes (params: limit, lvl, cat) |
| `/api/stats` | GET | Statistiques + agents |
| `/api/agents` | GET | Statut de tous les agents |
| `/api/sysinfo` | GET | CPU/RAM/Disk par agent |
| `/api/procs` | GET | Processus par agent |
| `/api/conns` | GET | Connexions réseau par agent |
| `/api/blocked` | GET | IPs actuellement bloquées |
| `/api/logs` | GET | Dernières lignes du log fichier |
| `/api/login` | POST | Authentification |
| `/api/logout` | POST | Déconnexion |
| `/api/kill` | POST | Tuer un processus sur un agent |
| `/api/block` | POST | Bloquer une IP (propagé à tous) |
| `/api/unblock` | POST | Débloquer une IP |

---

### 📊 Dashboard v5 — Interface SOC (6 Pages)

#### Page 1 — Overview
- Gauges CPU% et RAM% animées en temps réel
- Barres disque par partition (vert/orange/rouge)
- Carte mondiale Leaflet des connexions IP géolocalisées
- **Panel Endpoints** : statut **🟢 EN LIGNE / 🔴 OFFLINE** par agent
- Mini-barres CPU/RAM par agent, score de sécurité 0-100

#### Page 2 — Réseau
- Tableau IPs publiques avec drapeau pays et organisation
- Tableau IPs privées (réseau local)
- Filtres : TOUT / CRITIQUE / WARN / TCP / UDP
- Boutons **BLOQUER** et **DÉBLOQUER** par IP
- Statistiques en direct : Total / Publiques / Privées / TCP / UDP / Suspects
- **Panel IPs bloquées permanent** — liste toujours visible avec bouton DÉBLOQUER direct

#### Page 3 — Processus
- Liste complète avec PID réel, CPU%, RAM%, Status, User, exe
- Tri cliquable par CPU / RAM / PID / Nom
- Filtres : TOUT / SUSPECTS / ▲ CPU / ▲ RAM
- Bouton **KILL** par processus — exécution réelle sur l'agent via WebSocket
- Panneau détail au clic
- Surlignage rouge des processus malveillants connus

#### Page 4 — Alertes
- Flux temps réel avec badges CRITICAL / WARNING / INFO
- **Badge ⚡ SIEM violet** pour les alertes de corrélation
- Dédoublonnage intelligent avec compteur ×occurrences
- Filtres : TOUT / CRITIQUE / WARNING / PROCESS / RÉSEAU / FICHIERS / **⚡ SIEM**
- Toast notifications pour les CRITICAL
- Statistiques par catégorie avec diagramme barres
- Boutons : ACTUALISER / EXPORTER JSON / IPs BLOQUÉES

#### Page 5 — Logs
- Journal complet filtrable (TOUT / CRITIQUE / WARNING / ACTIONS / RÉSEAU / FICHIERS)
- Journal WebSocket temps réel (connexions/déconnexions/messages)

#### Page 6 — Fichiers *(nouveau)*
- Tous les fichiers détectés par l'agent en temps réel
- Filtres : TOUT / CRITIQUE / SUSPECT / TÉLÉCHARGEMENT / BUREAU / DOCUMENTS / TEMP
- Chaque fichier : nom, chemin complet, taille, extension, raisons (double ext, signature MSF...)
- Compteurs : critiques / suspects / téléchargements / total
- Graphique des extensions les plus vues
- Bouton effacer historique

#### Fonctionnalités globales
- **Bannière Kill Chain rouge clignotante** — apparaît automatiquement quand la règle KILL_CHAIN se déclenche + notification navigateur
- Header permanent : CRITIQUE / WARNING / ÉVÉNEMENTS / BLOQUÉS / AGENTS
- Indicateur niveau de menace (FAIBLE → CRITIQUE)
- Statut WebSocket live / off / erreur
- Horloge temps réel
- Fallback HTTP polling toutes les 5s si WS déconnecté

---

## 📁 Structure du projet

```
12ak-forteresse-soc/
│
├── agent_v6.py              # Agent endpoint Windows/Linux
├── server_v5.py             # Serveur central Linux/Ubuntu/AWS
├── dashboard_v5.html        # Interface dashboard web (6 pages)
├── login.html               # Page authentification sécurisée
└── README.md                # Ce fichier
```

---

## ⚙️ Installation

### Prérequis

| Composant | Environnement | Python |
|-----------|--------------|--------|
| Agent | Windows 10/11 ou Linux | 3.8+ |
| Serveur | Linux / Ubuntu / AWS EC2 | 3.8+ |
| Dashboard | Tout navigateur moderne | — |

### Serveur (Linux / AWS EC2)

```bash
# Cloner le projet
git clone https://github.com/TON_USERNAME/12ak-forteresse-soc.git
cd 12ak-forteresse-soc

# Installer les dépendances
pip install websockets colorama

# Ouvrir les ports AWS Security Group
# TCP 9998 — WebSocket
# TCP 9999 — Agents HTTP
# TCP 31337 — Dashboard (ton IP seulement)

# Lancer le serveur
python3 server_v5.py
```

L'URL d'accès sécurisée avec token s'affiche au démarrage :
```
http://TON_IP:31337/?token=XXXXXXXXXXXXXXXXXXXX
```

### Agent (Windows — lancer en Administrateur)

```cmd
:: Installer les dépendances
pip install psutil requests colorama websockets

:: Modifier SERVER_IP dans agent_v6.py
:: SERVER_IP = "TON_IP_EC2"

:: Lancer (clic droit → Exécuter en tant qu'administrateur)
python agent_v6.py
```

Au démarrage tu verras :
```
[+] Thread ws_commands démarré
[WS] Connexion → ws://TON_IP:9998/agent?name=TON_PC
[WS] Canal de commandes ouvert
```

### Activer les alertes Telegram (optionnel)

Dans `agent_v6.py` :
```python
TELEGRAM_ENABLED = True
TELEGRAM_TOKEN   = "123456789:ABCDEF..."   # Depuis @BotFather
TELEGRAM_CHAT_ID = "123456789"             # Depuis @userinfobot
```

---

## 🔧 Configuration

### Whitelist — Ne jamais bloquer

```python
# Dans agent_v6.py

# IPs jamais bloquées par l'IPS
WHITELIST_IPS = {
    "TON_IP_SERVEUR",    # Serveur EC2
    "127.0.0.1",
}

# Ports jamais signalés comme suspects
WHITELIST_PORTS = {
    9998,   # WebSocket
    9999,   # Agents HTTP
    31337,  # Dashboard
    80, 443, 53, 123,
}
```

### Changer les mots de passe

```bash
# Générer un hash SHA-256
python3 -c "import hashlib; print(hashlib.sha256(b'MON_MOT_DE_PASSE').hexdigest())"
```

Puis dans `server_v5.py` :
```python
CREDENTIALS = {
    "12ak":  "HASH_ICI",
    "admin": "HASH_ICI",
}
```

### Ajuster les fenêtres de corrélation SIEM

```python
# Dans server_v5.py
WINDOW_REVERSE_SHELL = 30    # secondes
WINDOW_DROPPER       = 60    # secondes
WINDOW_KILL_CHAIN    = 120   # secondes (2 min)
WINDOW_LATERAL       = 60    # secondes
CORR_THROTTLE        = 60    # anti-spam entre deux alertes identiques
```

### Ajuster les intervalles agent

```python
# Dans agent_v6.py
INTERVAL_SYSINFO      = 5    # CPU/RAM/Disk
INTERVAL_PROCS        = 5    # Processus
INTERVAL_NETWORK      = 3    # Réseau
INTERVAL_FILES        = 10   # Fichiers utilisateur
ALERT_THROTTLE_SEC    = 30   # Anti-spam alertes
```

---

## 🛡️ Tableau de détection complet

| Catégorie | Technique | Niveau | Action |
|-----------|-----------|--------|--------|
| Processus | Nom malveillant (mimikatz, meterpreter...) | CRITICAL | Auto-kill |
| Processus | Parent Process Spoofing (Office→Shell) | CRITICAL | Alerte |
| Processus | Process Hollowing | CRITICAL | Alerte |
| Mémoire | Région RWX — shellcode in-memory | CRITICAL | Alerte |
| Mémoire | Processus fileless (deleted on disk) | CRITICAL | Alerte |
| Réseau | Port suspect (4444, 1337, 50050...) | CRITICAL | IPS Block |
| Réseau | C2 Beacon heuristique | CRITICAL | Alerte |
| Réseau | Latéralisation SMB | WARNING | Alerte |
| PowerShell | `-ep bypass -w hidden -Command` | CRITICAL | Alerte |
| PowerShell | IEX + DownloadString | CRITICAL | Alerte |
| PowerShell | LOLBins (certutil, mshta, regsvr32...) | CRITICAL | Alerte |
| PowerShell | AMSI Bypass (AmsiUtils, AmsiScanBuffer) | CRITICAL | Alerte |
| PowerShell | Injection mémoire (VirtualAlloc, RThread) | CRITICAL | Alerte |
| PowerShell | Obfuscation (char codes, tick, reverse) | CRITICAL | Alerte |
| PowerShell | Persistence (Registry, Scheduled Tasks) | CRITICAL | Alerte |
| PowerShell | Credential dumping (sekurlsa, lsadump) | CRITICAL | Alerte |
| PowerShell | Désactivation Defender/Firewall | CRITICAL | Alerte |
| Fichiers | Signature Metasploit (bytes) | CRITICAL | Alerte |
| Fichiers | Double extension (.pdf.exe) | CRITICAL | Alerte |
| Fichiers | Nom déguisé (svch0st.exe) | CRITICAL | Alerte |
| Fichiers | Extension suspecte (.ps1, .bat, .hta...) | WARNING | Alerte |
| Fichiers | Nouveau téléchargement | INFO | Dashboard |
| Fichiers | Modification détectée (hash MD5) | WARNING | Alerte |
| Defender | Protection temps réel désactivée | CRITICAL | Telegram |
| SIEM | Reverse Shell (process + C2 < 30s) | CRITICAL | Corrélation |
| SIEM | Dropper (process + fichier < 60s) | CRITICAL | Corrélation |
| SIEM | Kill Chain complète (< 2 min) | CRITICAL | Bannière |
| SIEM | Mouvement latéral (SMB + process < 60s) | CRITICAL | Corrélation |

---

## 📡 Architecture WebSocket

```
Dashboard ──── ws://SERVER:9998/dashboard?session=TOKEN
                        │
                 [Serveur Central]
                        │
Agent Windows ── ws://SERVER:9998/agent?name=HOSTNAME
```

**Messages serveur → dashboard :**
- `init` — état complet au démarrage
- `sysinfo_update` — CPU/RAM/Disk mis à 