# 12ak-FORTERESS

Blue Team 


# ⚔️ 12ak_H4ck Tools — Forteresse SOC 🛡️

> **Système EDR (Endpoint Detection & Response) Blue Team**  
> Architecture Agent / Serveur / Dashboard — Surveillance temps réel, IPS automatique, détection fileless & payloads

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-6.0-red?style=flat-square)

---

## 📖 Présentation

**12ak_H4ck Forteresse SOC** est un outil de surveillance de sécurité complet développé dans un contexte Blue Team / CTF. Il permet de **monitorer en temps réel** un ou plusieurs endpoints Windows/Linux depuis un dashboard web centralisé hébergé sur un serveur Linux.

Le projet repose sur une architecture **3 couches** :

```
┌─────────────────────────────────────────────────────────────────┐
│  PC Windows / Linux — Agent v6.0  (agent_v6.py)                │
│  Surveillance : CPU, RAM, Disk, Processus, Réseau, Fichiers     │
│  IPS local : blocage firewall automatique                       │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP POST /alert  (port 9999)
                         │ WebSocket /agent  (port 9998)
┌────────────────────────▼────────────────────────────────────────┐
│  Serveur Linux / AWS EC2 — Serveur v5.0  (server_v5.py)        │
│  Collecte les alertes, gère les sessions, pousse via WebSocket  │
└────────────────────────┬────────────────────────────────────────┘
                         │ WebSocket /dashboard  (port 9998)
                         │ HTTP REST API  (port 31337)
┌────────────────────────▼────────────────────────────────────────┐
│  Navigateur Web — Dashboard  (dashboard_v5.html)                │
│  Interface SOC temps réel : alertes, réseau, processus, carte   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Fonctionnalités

### 🖥️ Agent (endpoint surveillé)

#### Surveillance Système
- **CPU / RAM / Disque** — métriques temps réel toutes les 5 secondes
- Alertes automatiques si CPU > 85% ou RAM > 90% de manière prolongée
- Détection disque plein (> 95%)
- Statistiques réseau I/O (bytes envoyés / reçus)

#### Surveillance Processus — Détection Avancée
- Liste complète des processus actifs avec PID réel, CPU%, RAM%, User, chemin exe
- **Noms malveillants connus** : mimikatz, meterpreter, lazagne, bloodhound, rubeus, psexec, netcat, procdump, winpeas, linpeas, cobaltstrike, empire et +20 autres
- **Parent Process Spoofing** : détecte Word/Excel qui lance cmd.exe ou powershell (macro malveillante)
- **Process Hollowing** : détecte les processus système avec enfants shells suspects
- **CPU anormal** : alerte si un processus consomme > 95% (crypto-minage possible)
- **Kill automatique** des outils de credential dumping avérés (mimikatz, lazagne, wce...)

#### Surveillance Réseau — Connexions Actives
- Toutes les connexions TCP/UDP en temps réel (IP locale, IP distante, port, protocole, PID, processus)
- **Nouvelle connexion externe** → alerte immédiate avec géolocalisation
- **Ports suspects** : 4444, 1337, 5555, 9001, 50050 (Cobalt Strike), 9050 (TOR) et +30 autres
- **C2 Beacon heuristique** : processus système (svchost, lsass) qui contactent internet sur des ports non-standard
- **Latéralisation SMB** : processus non-système qui se connecte à SMB (port 445)
- **Whitelist infrastructure** : l'IP du serveur et les ports de l'outil ne génèrent jamais d'alerte

#### Surveillance Fichiers — Dossiers Utilisateur Uniquement
- Dossiers surveillés : **Downloads, Desktop, Documents, AppData/Temp, AppData/Roaming, Music, Videos**
- Aucun dossier système (System32, Windows) — uniquement les fichiers personnels
- **Tous les nouveaux fichiers** signalés dans les 5 dernières minutes (téléchargements inclus)
- **Double extension** : `document.pdf.exe` → CRITICAL
- **Nom déguisé** : `svch0st.exe`, `explorer32.exe` → CRITICAL
- **Signatures Metasploit** dans le contenu binaire des fichiers :
  - Prologue Meterpreter x64 (`\xfc\x48\x83\xe4\xf0`)
  - Prologue Meterpreter x86 (`\xfc\xe8\x82\x00\x00`)
  - PE header dans fichier non-exe
  - Strings `ReflectiveDll`, `stdapi_`, `meterpreter`
- **Modification détectée** via hash MD5 (fichier modifié = nouvelle alerte)
- Label clair dans le dashboard : TELECHARGEMENT / BUREAU / DOCUMENTS / TEMP

#### Détection PowerShell & Commandes Malveillantes
Plus de **60 signatures** couvrant toutes les techniques d'attaque connues :

**Obfuscation :**
- `-EncodedCommand` / `-enc` (base64)
- Char codes : `[char]73+[char]69+[char]88`
- Tick obfuscation : `i\`e\`x`
- Reverse string : `-join('abc'[5..0])`
- Variable env : `$env:comspec[4,15,25]-join''`
- `[ScriptBlock]::Create(...)`

**Commande classique payload :**
- `-ExecutionPolicy Bypass -WindowStyle Hidden -Command`
- `-ep bypass -w h`
- `-NoProfile -NonInteractive`

**Download & Execute :**
- `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- `Invoke-WebRequest`, `wget`, `curl` vers HTTP
- `Start-BitsTransfer`

**LOLBins (Living off the Land) :**
- `certutil -decode / -urlcache` — décode/télécharge des payloads
- `mshta http://...` — exécute des HTA depuis internet
- `regsvr32 /s /i:http://...` — Squiblydoo bypass AppLocker
- `wmic process call create` — exécution distante
- `rundll32 javascript:` — exécute JS via rundll32
- `msiexec /i http://...` — installe MSI distant
- `bitsadmin /transfer` — téléchargement discret
- `cmstp /ni /s http://...` — bypass AppLocker
- `forfiles /c cmd` — bypass restrictions

**AMSI Bypass :**
- Patch `AmsiUtils` / `AmsiInitFailed`
- Patch `AmsiScanBuffer` via `Marshal.Copy`
- Accès par réflexion `System.Management.Automation.Amsi`

**Injection Mémoire :**
- `VirtualAlloc` avec protection RWX (0x40)
- `WriteProcessMemory`, `CreateRemoteThread`
- `NtCreateThread`, `NtCreateThreadEx`
- P/Invoke via `Add-Type -TypeDefinition`
- Résolution API : `GetProcAddress`, `LoadLibrary`

**Persistence :**
- Registry Run key (`CurrentVersion\Run`)
- Scheduled Tasks (`schtasks /create`, `New-ScheduledTask`)
- Startup folder (`.lnk`)

**Désactivation défenses :**
- `Set-MpPreference -DisableRealTimeMonitoring`
- `Add-MpPreference -ExclusionPath`
- `sc stop/delete WinDefend`
- `netsh advfirewall set allprofiles state off`
- `Clear-EventLog`, `wevtutil cl`

**Credential Dumping :**
- `Invoke-Mimikatz`
- `sekurlsa::`, `kerberos::ptt`, `lsadump::`, `dpapi::`
- LSASS minidump

#### Module Mémoire — Détection Fileless & In-Memory
- **Régions mémoire RWX** (Read+Write+Execute) : signe de shellcode injecté en mémoire
- **Processus fileless** : processus dont le fichier exe a été supprimé après exécution (payload in-memory)
- **Processus système mal placés** : svchost, lsass, csrss lancés depuis un chemin non-System32
- Scan toutes les 10 secondes, whitelist automatique des browsers et JIT runtimes (Chrome, Firefox, Python, Java...)

#### IPS — Intrusion Prevention System
- **Blocage firewall automatique** des IPs sur ports suspects (Windows Firewall / Linux iptables)
- Isolation complète : règles entrée ET sortie créées simultanément
- **Kill automatique** des outils de credential dumping avérés
- **Whitelist immuable** : IP du serveur, ports de l'infrastructure jamais bloqués
- Déblocage possible depuis le dashboard

#### Audit PowerShell (Windows — Event Log)
- Lecture du **Script Block Logging** (`Microsoft-Windows-PowerShell/Operational`)
- Détection des patterns malveillants dans les 30 derniers événements
- Toutes les 60 secondes

#### Vérification Windows Defender
- Statut `AntivirusEnabled`, `RealTimeProtectionEnabled`, `AMServiceEnabled`
- Alerte CRITICAL si la protection temps réel est désactivée
- Vérification toutes les 60 secondes

#### Alertes Telegram (optionnel)
- Notifications immédiates sur toutes les alertes CRITICAL
- Activation/désactivation sans redémarrer l'agent
- Configuration : token BotFather + chat_id

#### Throttle Anti-Spam
- Même alerte envoyée **maximum 1 fois toutes les 30 secondes**
- Évite l'inondation du dashboard par des alertes répétées

---

### 🖧 Serveur Central

- **3 serveurs en parallèle** : HTTP agents (9999), WebSocket (9998), Dashboard (31337)
- **WebSocket bidirectionnel** : push temps réel vers le dashboard + canal de commandes vers les agents
- **Watchdog agents** : détecte les agents offline (> 30s sans message) → indicateur rouge
- **Stockage mémoire** : 5000 alertes en RAM + log fichier JSON
- **Authentification** : token URL secret + session cookie HttpOnly SHA-256
- **API REST complète** : `/api/alerts`, `/api/stats`, `/api/agents`, `/api/sysinfo`, `/api/procs`, `/api/conns`, `/api/blocked`, `/api/logs`
- **Propagation des ordres** : KILL/BLOCK/UNBLOCK envoyés à tous les agents connectés

---

### 📊 Dashboard Web

#### Overview (Page 1)
- Gauges circulaires CPU % et RAM % en temps réel
- Barres disque par partition avec couleurs (vert/orange/rouge)
- Carte mondiale Leaflet des connexions IP avec marqueurs géolocalisés
- Panneau Endpoints : statut **🟢 EN LIGNE / 🔴 OFFLINE** par agent
- Mini-barres CPU/RAM par agent
- Score de sécurité par agent (0-100)

#### Réseau (Page 2)
- Tableau IPs publiques avec géolocalisation (drapeau, pays, organisation)
- Tableau IPs privées (réseau local)
- Filtres : TOUT / CRITIQUE / WARN / TCP / UDP / SUSPECT
- Boutons **BLOQUER** et **DÉBLOQUER** par IP
- Statistiques en direct : Total / Publiques / Privées / TCP / UDP / Suspects

#### Processus (Page 3)
- Liste complète avec PID réel, CPU%, RAM%, Status, User, chemin exe
- Tri par CPU, RAM, PID, Nom
- Filtres : TOUT / SUSPECTS / ▲ CPU / ▲ RAM
- Bouton **KILL** par processus (exécution réelle sur l'agent)
- Panneau détail au clic
- Mise en évidence des processus malveillants connus (fond rouge)

#### Alertes (Page 4)
- Flux temps réel des alertes avec badges CRITICAL / WARNING / INFO
- Dédoublonnage intelligent (compteur × occurrences)
- Filtres : TOUT / CRITIQUE / WARNING / PROCESS / RÉSEAU / FICHIERS
- Clic → modal JSON détaillé
- Toast notifications pour les CRITICAL
- Statistiques et diagramme catégories

#### Logs (Page 5)
- Journal complet filtrable
- Journal WebSocket (connexions/déconnexions)
- Boutons : **ACTUALISER**, **EXPORTER JSON**, **IPs BLOQUÉES**

#### Header permanent
- Compteurs CRITIQUE / WARNING / ÉVÉNEMENTS / BLOQUÉS / AGENTS
- Indicateur niveau de menace (FAIBLE → CRITIQUE)
- Statut WebSocket (WS LIVE / WS OFF / WS ERR)
- Horloge temps réel
- Navigation par onglets
- Bouton logout

---

## 📁 Structure du projet

```
12ak-forteresse-soc/
│
├── agent_v6.py           # Agent endpoint (Windows/Linux)
├── server_v5.py          # Serveur central (Linux/Ubuntu/AWS)
├── dashboard_v5.html     # Interface dashboard web
├── login.html            # Page d'authentification
└── README.md             # Ce fichier
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

# Ouvrir les ports AWS Security Group :
# TCP 9998 (WebSocket), TCP 9999 (Agents), TCP 31337 (Dashboard)

# Lancer le serveur
python3 server_v5.py
```

L'URL d'accès sécurisée avec token est affichée au démarrage :
```
http://TON_IP:31337/?token=XXXXXXXXXXXX
```

### Agent (Windows — lancer en Administrateur)

```cmd
# Installer les dépendances
pip install psutil requests colorama websockets

# Modifier SERVER_IP dans agent_v6.py
# SERVER_IP = "TON_IP_EC2"

# Lancer l'agent (clic droit → Exécuter en tant qu'administrateur)
python agent_v6.py
```

### Activer les alertes Telegram (optionnel)

Dans `agent_v6.py`, modifier :
```python
TELEGRAM_ENABLED = True
TELEGRAM_TOKEN   = "123456789:ABCDEF..."   # Depuis @BotFather sur Telegram
TELEGRAM_CHAT_ID = "123456789"             # Depuis @userinfobot sur Telegram
```

---

## 🔧 Configuration

### Whitelist — Ne jamais bloquer

```python
# Dans agent_v6.py

# IPs jamais bloquées par l'IPS
WHITELIST_IPS = {
    "54.147.128.163",   # Ton IP serveur EC2
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
# Générer le hash d'un nouveau mot de passe
python3 -c "import hashlib; print(hashlib.sha256(b'NOUVEAU_MOT_DE_PASSE').hexdigest())"
```

Puis modifier dans `server_v5.py` :
```python
CREDENTIALS = {
    "12ak":  "HASH_ICI",
    "admin": "HASH_ICI",
}
```

### Ajuster les intervalles de scan

```python
# Dans agent_v6.py
INTERVAL_SYSINFO  = 5    # CPU/RAM/Disk (secondes)
INTERVAL_PROCS    = 5    # Processus
INTERVAL_NETWORK  = 3    # Réseau
INTERVAL_FILES    = 10   # Fichiers utilisateur
ALERT_THROTTLE_SEC = 30  # Anti-spam alertes
```

---

## 🛡️ Détections — Tableau récapitulatif

| Catégorie | Technique | Niveau |
|-----------|-----------|--------|
| Processus | Nom malveillant (mimikatz, meterpreter...) | CRITICAL |
| Processus | Parent Process Spoofing (Office → Shell) | CRITICAL |
| Processus | Process Hollowing | CRITICAL |
| Processus | Credential dumping (auto-kill) | CRITICAL |
| Mémoire | Région RWX — shellcode in-memory | CRITICAL |
| Mémoire | Processus fileless (deleted on disk) | CRITICAL |
| Réseau | Port suspect (4444, 1337, 50050...) | CRITICAL + IPS |
| Réseau | C2 Beacon heuristique | CRITICAL |
| Réseau | Latéralisation SMB | WARNING |
| PowerShell | `-ep bypass -w hidden` | CRITICAL |
| PowerShell | IEX + DownloadString | CRITICAL |
| PowerShell | LOLBins (certutil, mshta, regsvr32...) | CRITICAL |
| PowerShell | AMSI Bypass | CRITICAL |
| PowerShell | Injection mémoire (VirtualAlloc, RThread) | CRITICAL |
| PowerShell | Obfuscation (char codes, tick, reverse) | CRITICAL |
| PowerShell | Persistence (Registry, Scheduled Tasks) | CRITICAL |
| PowerShell | Credential dumping (sekurlsa, lsadump) | CRITICAL |
| PowerShell | Désactivation Defender/Firewall | CRITICAL |
| Fichiers | Signature Metasploit (bytes) | CRITICAL |
| Fichiers | Double extension (.pdf.exe) | CRITICAL |
| Fichiers | Nom déguisé (svch0st.exe) | CRITICAL |
| Fichiers | Extension suspecte (.ps1, .bat, .hta...) | WARNING |
| Fichiers | Nouveau téléchargement | INFO |
| Fichiers | Modification détectée (hash) | WARNING |
| Defender | Protection temps réel désactivée | CRITICAL |
| IPS | IP bloquée + isolée du réseau | ACTION |

---

## 🔌 API REST

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/alerts` | GET | Liste des alertes (params: limit, lvl, cat) |
| `/api/stats` | GET | Statistiques globales + agents |
| `/api/agents` | GET | Liste des agents et leur statut |
| `/api/sysinfo` | GET | CPU/RAM/Disk par agent |
| `/api/procs` | GET | Processus par agent |
| `/api/conns` | GET | Connexions réseau par agent |
| `/api/blocked` | GET | IPs actuellement bloquées |
| `/api/logs` | GET | Dernières lignes du log fichier |
| `/api/login` | POST | Authentification |
| `/api/logout` | POST | Déconnexion |
| `/api/kill` | POST | Tuer un processus sur un agent |
| `/api/block` | POST | Bloquer une IP (propagé à tous les agents) |
| `/api/unblock` | POST | Débloquer une IP |

---

## 📡 Architecture WebSocket

```
Dashboard ──────────────── ws://SERVER:9998/dashboard?session=TOKEN
                                    │
                              [Serveur Central]
                                    │
Agent Windows ──────────── ws://SERVER:9998/agent?name=HOSTNAME
```

**Messages serveur → dashboard :**
- `init` — état complet au démarrage (alertes, agents, sysinfo, procs, conns)
- `sysinfo_update` — CPU/RAM/Disk mis à jour
- `procs_update` — snapshot processus
- `conns_update` — snapshot connexions
- `agents_update` — statut agents (online/offline)
- `blocked_update` — liste IPs bloquées mise à jour
- Alertes directes (level, category, title, detail, extra)

**Messages dashboard → serveur → agent :**
- `KILL` — tuer un processus par PID
- `BLOCK` — bloquer une IP
- `UNBLOCK` — débloquer une IP

---

## ⚠️ Avertissement légal

Cet outil est développé à des fins **éducatives et défensives** dans le cadre de compétitions CTF (Capture The Flag) et d'audits de sécurité sur des systèmes dont vous êtes propriétaire ou avez l'autorisation explicite de surveiller.

**L'utilisation de cet outil sur des systèmes sans autorisation est illégale et contraire à l'éthique.**

L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

## 👤 Auteur

**12ak_H4ck** — Blue Team / CTF / Cybersécurité

> *"La meilleure défense c'est de voir tout ce que l'attaquant fait avant qu'il le fasse."*

---

## 📄 Licence

MIT License — Libre d'utilisation, de modification et de distribution avec attribution.

