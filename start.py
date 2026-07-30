#!/usr/bin/env python3
"""
start.py — SOC Automation Pipeline : lanceur universel
======================================================
Windows, Ubuntu, Debian, CentOS, Arch, macOS — une seule commande.

Ce script n'utilise QUE la bibliothèque standard : il fonctionne donc
avant même l'installation des dépendances.

Usage :
    python start.py                  → menu interactif
    python start.py install          → installer les dépendances Python
    python start.py init             → créer le .env depuis .env.example
    python start.py a                → Service A (webhook Splunk → TheHive)
    python start.py b                → Service B (Cortex + MISP + blocage)
    python start.py both             → A + B ensemble, avec redémarrage auto
    python start.py status           → état complet de l'intégration
    python start.py test             → tests end-to-end (services lancés)
    python start.py unit             → tests unitaires (hors ligne)
    python start.py telegram         → envoyer un message de test Telegram
    python start.py telegram-config  → configurer Telegram pas à pas
    python start.py list             → IPs actuellement bloquées
    python start.py unblock <ip>     → débloquer une IP
    python start.py cortex           → lister les analyseurs Cortex détectés
    python start.py logs             → afficher la fin des journaux
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

# ══════════════════════════════════════════════════════════════════
# CONSOLE — couleurs + UTF-8 (Windows compris)
# ══════════════════════════════════════════════════════════════════
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    os.system("")                       # active les séquences ANSI

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

C = {
    "g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
    "b": "\033[94m", "c": "\033[96m", "p": "\033[95m",
    "w": "\033[97m", "m": "\033[90m", "x": "\033[0m",
    "B": "\033[1m",
}


def c(color, text):
    return "{}{}{}".format(C[color], text, C["x"])


def ok(msg):
    print("  {} {}".format(c("g", "✓"), msg))


def warn(msg):
    print("  {} {}".format(c("y", "!"), msg))


def err(msg):
    print("  {} {}".format(c("r", "✗"), msg))


def hdr(msg):
    print("\n{}  {}  {}".format(c("c", "══"), c("B", msg), c("c", "═" * max(2, 50 - len(msg)))))


def sep():
    print(c("m", "  " + "─" * 60))


# ══════════════════════════════════════════════════════════════════
# CHEMINS
# ══════════════════════════════════════════════════════════════════
ROOT        = Path(__file__).resolve().parent
SRC_DIR     = ROOT / "src"
TESTS_DIR   = ROOT / "tests"
DATA_DIR    = ROOT / "data"
LOGS_DIR    = ROOT / "logs"
SERVICE_A   = SRC_DIR / "service_a_splunk_to_thehive.py"
SERVICE_B   = SRC_DIR / "service_b_thehive_responder.py"
UNIT_TESTS  = TESTS_DIR / "run_tests.py"
E2E_TESTS   = TESTS_DIR / "test_integration.py"
ENV_FILE    = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
REQ_FILE    = ROOT / "requirements.txt"

PYTHON = sys.executable or "python"


# ══════════════════════════════════════════════════════════════════
# .env
# ══════════════════════════════════════════════════════════════════
def load_env() -> dict:
    """Lit le .env et retourne un dictionnaire clé → valeur."""
    cfg = {}
    if not ENV_FILE.exists():
        return cfg
    try:
        with open(ENV_FILE, encoding="utf-8-sig") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                key, _, value = line.partition("=")
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                cfg[key.strip()] = value
    except OSError as exc:
        err("Lecture de .env impossible : {}".format(exc))
    return cfg


def save_env_key(key: str, value: str) -> None:
    """Met à jour une clé du .env sans toucher au reste du fichier."""
    lines, found = [], False
    if ENV_FILE.exists():
        try:
            with open(ENV_FILE, encoding="utf-8-sig") as fh:
                for raw in fh:
                    stripped = raw.strip()
                    if stripped.startswith(key + "=") or stripped.startswith(key + " ="):
                        lines.append("{}={}\n".format(key, value))
                        found = True
                    else:
                        lines.append(raw)
        except OSError as exc:
            err("Lecture de .env impossible : {}".format(exc))
            return
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append("{}={}\n".format(key, value))
    try:
        with open(ENV_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except OSError as exc:
        err("Écriture de .env impossible : {}".format(exc))


def init_env() -> bool:
    hdr("Création du fichier .env")
    if ENV_FILE.exists():
        ok(".env existe déjà — rien à faire ({})".format(ENV_FILE))
        return True
    if not ENV_EXAMPLE.exists():
        err(".env.example introuvable dans {}".format(ROOT))
        return False
    try:
        ENV_FILE.write_text(ENV_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError as exc:
        err("Copie impossible : {}".format(exc))
        return False
    ok(".env créé depuis .env.example")
    print(c("m", "  → Édite-le pour renseigner THEHIVE_URL, THEHIVE_APIKEY, etc."))
    return True


# ══════════════════════════════════════════════════════════════════
# HTTP (stdlib)
# ══════════════════════════════════════════════════════════════════
def http_json(url: str, payload=None, timeout: int = 8):
    """GET/POST JSON simple. Retourne le dict décodé ou None."""
    data    = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:            # 4xx/5xx : le corps reste utile
        try:
            body = exc.read()
        except OSError:
            return None
    except (urllib.error.URLError, OSError, ValueError):
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def webhook_port(cfg: dict) -> int:
    raw = str(cfg.get("LISTEN_PORT", "5000")).strip()
    digits = ""
    for char in raw:
        if char.isdigit():
            digits += char
        elif digits:
            break
    return int(digits) if digits else 5000


# ══════════════════════════════════════════════════════════════════
# DÉPENDANCES
# ══════════════════════════════════════════════════════════════════
def install_deps() -> bool:
    hdr("Installation des dépendances Python")

    if not REQ_FILE.exists():
        err("requirements.txt introuvable dans {}".format(ROOT))
        return False

    print(c("m", "  Python : {}".format(sys.version.split()[0])))
    print(c("m", "  OS     : {} {}".format(platform.system(), platform.release())))
    print(c("m", "  Binaire: {}".format(PYTHON)))
    sep()
    print("  Installation en cours...\n")

    base = [PYTHON, "-m", "pip", "install", "-r", str(REQ_FILE), "--upgrade"]
    try:
        if subprocess.run(base).returncode == 0:
            ok("Toutes les dépendances sont installées")
            return True
        warn("Première tentative échouée — nouvel essai avec --break-system-packages")
        if subprocess.run(base + ["--break-system-packages"]).returncode == 0:
            ok("Dépendances installées (--break-system-packages)")
            return True
        err("Échec. Lance manuellement : {} -m pip install -r requirements.txt".format(PYTHON))
        return False
    except OSError as exc:
        err("Erreur : {}".format(exc))
        return False


def check_deps(verbose: bool = True) -> bool:
    missing = []
    for module, package in (("flask", "flask"), ("requests", "requests"),
                            ("urllib3", "urllib3")):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing and verbose:
        err("Modules Python manquants : {}".format(", ".join(missing)))
        print("    {}".format(c("c", "python start.py install")))
    return not missing


# ══════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════
def configure_telegram() -> None:
    hdr("Configuration Telegram")
    cfg = load_env()

    print("""
  Créer le bot :
  {}  1. Telegram → chercher @BotFather
  {}  2. Envoyer : /newbot
  {}  3. Choisir un nom, puis un username finissant par « bot »
  {}  4. Copier le TOKEN renvoyé par BotFather
""".format(c("c", "→"), c("c", "→"), c("c", "→"), c("c", "→")))

    current_token = cfg.get("TELEGRAM_TOKEN", "")
    if current_token:
        print("  Token actuel : {}{}".format(
            c("y", current_token[:12] + "…"), c("m", "  (Entrée pour garder)")))
    token = input("  {} Colle ton TOKEN BotFather : ".format(c("c", "→"))).strip() or current_token
    if not token:
        err("Token requis")
        return

    bot_name = "ton_bot"
    print("\n  Vérification du token...")
    data = http_json("https://api.telegram.org/bot{}/getMe".format(token))
    if data and data.get("ok"):
        bot_name = data.get("result", {}).get("username", "?")
        ok("Bot valide : @{}".format(bot_name))
    else:
        err("Token invalide ou pas de connexion Internet")
        if input("  Continuer quand même ? (o/N) : ").strip().lower() != "o":
            return

    print("""
  Récupérer le Chat ID :
  {}  1. Envoyer /start au bot @{} dans Telegram
  {}  2. Ouvrir dans un navigateur :
       {}
  {}  3. Repérer « "chat":{{"id": ... }} » dans le JSON
""".format(c("c", "→"), bot_name, c("c", "→"),
           c("y", "https://api.telegram.org/bot{}/getUpdates".format(token)),
           c("c", "→")))

    current_chat = cfg.get("TELEGRAM_CHAT_ID", "")
    if current_chat:
        print("  Chat ID actuel : {}{}".format(c("y", current_chat),
                                               c("m", "  (Entrée pour garder)")))
    chat_id = input("  {} Colle ton Chat ID : ".format(c("c", "→"))).strip() or current_chat
    if not chat_id:
        err("Chat ID requis")
        return

    if not ENV_FILE.exists():
        init_env()
    save_env_key("TELEGRAM_TOKEN", token)
    save_env_key("TELEGRAM_CHAT_ID", chat_id)
    save_env_key("TELEGRAM_ENABLED", "true")
    ok("Sauvegardé dans {}".format(ENV_FILE))

    print("\n  Envoi d'un message de test...")
    sent = http_json(
        "https://api.telegram.org/bot{}/sendMessage".format(token),
        {"chat_id": chat_id,
         "text": "🧪 <b>SOC Telegram configuré</b>\n✅ Connexion OK\n📅 {}".format(
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
         "parse_mode": "HTML"})
    if sent and sent.get("ok"):
        ok("Message envoyé — vérifie Telegram")
    else:
        description = (sent or {}).get("description", "pas de réponse")
        err("Échec de l'envoi : {}".format(description))
        if "chat not found" in str(description).lower():
            warn("Envoie d'abord /start au bot dans Telegram")


def test_telegram() -> None:
    hdr("Test Telegram")
    cfg = load_env()

    enabled = cfg.get("TELEGRAM_ENABLED", "false").strip().lower() == "true"
    token   = cfg.get("TELEGRAM_TOKEN", "")
    chat_id = cfg.get("TELEGRAM_CHAT_ID", "")

    sep()
    print("  TELEGRAM_ENABLED : {}".format(c("g", "true ✓") if enabled else c("r", "false ✗")))
    print("  TELEGRAM_TOKEN   : {}".format(
        c("g", token[:12] + "…") if token else c("r", "VIDE ✗")))
    print("  TELEGRAM_CHAT_ID : {}".format(c("g", chat_id) if chat_id else c("r", "VIDE ✗")))
    sep()

    if not enabled:
        err("TELEGRAM_ENABLED=false → lance : python start.py telegram-config")
        return
    if not token or not chat_id:
        err("Token ou Chat ID manquant → python start.py telegram-config")
        return

    print("  Vérification du token...")
    data = http_json("https://api.telegram.org/bot{}/getMe".format(token))
    if not (data and data.get("ok")):
        err("Token invalide ou pas de connexion Internet")
        return
    bot = data.get("result", {})
    ok("Bot @{} (id={})".format(bot.get("username", "?"), bot.get("id", "?")))

    print("  Envoi du message de test...")
    sent = http_json(
        "https://api.telegram.org/bot{}/sendMessage".format(token),
        {"chat_id": chat_id,
         "text": ("🧪 <b>TEST SOC — pipeline</b>\n\n✅ Telegram fonctionne\n⏰ {}\n\n"
                  "<b>TheHive :</b> {}\n"
                  "<i>Les alertes High/Critical arriveront ici.</i>").format(
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             cfg.get("THEHIVE_URL", "non défini")),
         "parse_mode": "HTML"})
    if sent and sent.get("ok"):
        ok("Message envoyé — vérifie Telegram")
        return
    description = str((sent or {}).get("description", "pas de réponse"))
    err("Échec : {}".format(description))
    if "chat not found" in description.lower():
        warn("Envoie /start au bot dans Telegram, puis relance ce test")
    elif "blocked" in description.lower():
        warn("Débloque le bot dans Telegram")


# ══════════════════════════════════════════════════════════════════
# LANCEMENT DES SERVICES
# ══════════════════════════════════════════════════════════════════
def service_env() -> dict:
    env = os.environ.copy()
    env.update({k: str(v) for k, v in load_env().items()})
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_service(script: Path, name: str):
    if not script.exists():
        err("Script introuvable : {}".format(script))
        return None
    print("  Lancement de {}...".format(c("b", name)))
    try:
        return subprocess.Popen([PYTHON, str(script)], cwd=str(ROOT), env=service_env())
    except OSError as exc:
        err("Lancement impossible : {}".format(exc))
        return None


def run_service_command(args: list) -> int:
    """Exécute le Service B en mode CLI (list, unblock, status, cortex)."""
    if not SERVICE_B.exists():
        err("Script introuvable : {}".format(SERVICE_B))
        return 1
    if not check_deps():
        return 1
    try:
        return subprocess.run([PYTHON, str(SERVICE_B)] + args,
                              cwd=str(ROOT), env=service_env()).returncode
    except OSError as exc:
        err("Exécution impossible : {}".format(exc))
        return 1


def _wait_for(proc, name: str) -> None:
    print("")
    ok("{} lancé (PID {})".format(name, proc.pid))
    print(c("m", "  Ctrl+C pour arrêter\n"))
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        ok("{} arrêté".format(name))


def launch_service_a() -> None:
    hdr("Service A — Splunk → TheHive (webhook)")
    if not preflight():
        return
    proc = run_service(SERVICE_A, "Service A")
    if proc:
        _wait_for(proc, "Service A")


def launch_service_b() -> None:
    hdr("Service B — Responder (Cortex + MISP + blocage)")
    if not preflight():
        return
    proc = run_service(SERVICE_B, "Service B")
    if proc:
        _wait_for(proc, "Service B")


def launch_both() -> None:
    hdr("Services A + B — lancement simultané")
    if not preflight():
        return

    proc_a = run_service(SERVICE_A, "Service A (webhook)")
    time.sleep(2)
    proc_b = run_service(SERVICE_B, "Service B (responder)")
    if not proc_a or not proc_b:
        for proc in (proc_a, proc_b):
            if proc and proc.poll() is None:
                proc.terminate()
        return

    print("")
    ok("Service A — PID {}".format(proc_a.pid))
    ok("Service B — PID {}".format(proc_b.pid))
    print(c("m", "\n  Les deux services tournent. Ctrl+C pour tout arrêter.\n"))

    try:
        while True:
            if proc_a.poll() is not None:
                warn("Service A s'est arrêté (code {}) — redémarrage".format(proc_a.returncode))
                proc_a = run_service(SERVICE_A, "Service A") or proc_a
            if proc_b.poll() is not None:
                warn("Service B s'est arrêté (code {}) — redémarrage".format(proc_b.returncode))
                proc_b = run_service(SERVICE_B, "Service B") or proc_b
            time.sleep(5)
    except KeyboardInterrupt:
        print("")
        ok("Arrêt demandé...")
        for proc, name in ((proc_a, "Service A"), (proc_b, "Service B")):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                ok("{} arrêté".format(name))


# ══════════════════════════════════════════════════════════════════
# VÉRIFICATIONS
# ══════════════════════════════════════════════════════════════════
def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:                     # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def elevate(args: list) -> int:
    """Relance start.py avec les privilèges administrateur / root."""
    if is_admin():
        ok("Déjà administrateur — rien à faire")
        return 0

    command = " ".join(args) or "both"
    if IS_WINDOWS:
        hdr("Relance en tant qu'administrateur")
        print(c("m", "  Une fenêtre de confirmation Windows va s'ouvrir (UAC)."))
        try:
            import ctypes
            params = '"{}" {}'.format(Path(__file__).resolve(), command)
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", PYTHON, params, str(ROOT), 1)
            if int(result) > 32:
                ok("Nouvelle fenêtre lancée en administrateur")
                print(c("m", "  Les services tournent désormais dans cette fenêtre."))
                return 0
            err("Élévation refusée ou impossible (code {})".format(result))
        except Exception as exc:              # noqa: BLE001 — API Windows
            err("Élévation impossible : {}".format(exc))
        print("\n  Solution manuelle :")
        print("    {}".format(c("c", "clic droit sur PowerShell → "
                                "« Exécuter en tant qu'administrateur »")))
        print("    {}".format(c("c", "cd {} ; python start.py {}".format(ROOT, command))))
        return 1

    hdr("Relance avec sudo")
    if not shutil.which("sudo"):
        err("sudo est introuvable — se connecter en root puis relancer")
        return 1
    try:
        return subprocess.run(
            ["sudo", PYTHON, str(Path(__file__).resolve())] + (args or ["both"]),
            cwd=str(ROOT)).returncode
    except OSError as exc:
        err("Relance impossible : {}".format(exc))
        return 1


def preflight() -> bool:
    """Contrôles avant lancement. Retourne False si un blocage est fatal."""
    DATA_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    if not check_deps():
        return False

    if not ENV_FILE.exists():
        warn(".env absent — création depuis .env.example")
        if not init_env():
            return False

    cfg    = load_env()
    issues = []
    if not cfg.get("THEHIVE_URL"):
        issues.append("THEHIVE_URL n'est pas défini dans .env")
    if not cfg.get("THEHIVE_APIKEY"):
        issues.append("THEHIVE_APIKEY n'est pas défini dans .env")
    if cfg.get("TELEGRAM_ENABLED", "false").strip().lower() == "true":
        if not cfg.get("TELEGRAM_TOKEN"):
            issues.append("TELEGRAM_ENABLED=true mais TELEGRAM_TOKEN est vide")
        if not cfg.get("TELEGRAM_CHAT_ID"):
            issues.append("TELEGRAM_ENABLED=true mais TELEGRAM_CHAT_ID est vide")
    active = cfg.get("ACTIVE_RESPONSE", "false").strip().lower() == "true"
    if active and not is_admin():
        issues.append("ACTIVE_RESPONSE=true mais le script n'est pas admin/root "
                      "— AUCUNE IP NE SERA BLOQUÉE. Relance : python start.py elevate")
    if not active:
        issues.append("ACTIVE_RESPONSE=false — mode simulation : les IP malveillantes "
                      "sont détectées et journalisées, mais PAS bloquées")

    mode = cfg.get("FILE_RESPONSE_MODE", "quarantine")
    if cfg.get("FILE_RESPONSE_ENABLED", "false").strip().lower() == "true":
        if not cfg.get("FILE_SCAN_PATHS", "").strip():
            issues.append("FILE_RESPONSE_ENABLED=true mais FILE_SCAN_PATHS est vide "
                          "— aucun fichier malveillant ne sera recherché")
        elif mode == "delete":
            issues.append("FILE_RESPONSE_MODE=delete — les fichiers malveillants seront "
                          "SUPPRIMÉS définitivement (mode « quarantine » réversible)")

    if issues:
        print("")
        for issue in issues:
            warn(issue)
        print("")
    return True


def check_status() -> None:
    hdr("État de l'intégration")
    cfg  = load_env()
    port = webhook_port(cfg)
    sep()

    print("  .env              : {}".format(
        c("g", "✓ " + str(ENV_FILE)) if ENV_FILE.exists() else c("r", "✗ manquant")))
    for name, path in (("Service A", SERVICE_A), ("Service B", SERVICE_B)):
        print("  {:<18}: {}".format(
            name, c("g", "✓ " + path.name) if path.exists() else c("r", "✗ manquant")))
    print("  Dépendances       : {}".format(
        c("g", "✓ installées") if check_deps(verbose=False) else c("r", "✗ manquantes")))
    print("  Privilèges        : {}".format(
        c("g", "✓ admin/root") if is_admin() else c("y", "utilisateur standard")))
    sep()

    def show(label, value, secret=False):
        if not value:
            print("  {:<18}: {}".format(label, c("r", "VIDE")))
        elif secret:
            print("  {:<18}: {}".format(label, c("g", value[:10] + "…")))
        else:
            print("  {:<18}: {}".format(label, c("c", value)))

    show("TheHive URL", cfg.get("THEHIVE_URL", ""))
    show("TheHive API Key", cfg.get("THEHIVE_APIKEY", ""), secret=True)
    show("Cortex URL", cfg.get("CORTEX_URL", ""))
    show("Cortex API Key", cfg.get("CORTEX_APIKEY", ""), secret=True)
    show("MISP URL", cfg.get("MISP_URL", ""))
    print("  {:<18}: {}".format("MISP activé", (
        c("g", "true ✓") if cfg.get("MISP_ENABLED", "false").lower() == "true"
        else c("y", "false"))))
    show("VirusTotal Key", cfg.get("VT_APIKEY", ""), secret=True)
    sep()

    telegram_on = cfg.get("TELEGRAM_ENABLED", "false").strip().lower() == "true"
    print("  {:<18}: {}".format("Telegram activé",
                                c("g", "true ✓") if telegram_on else c("y", "false")))
    show("Telegram Token", cfg.get("TELEGRAM_TOKEN", ""), secret=True)
    show("Telegram Chat ID", cfg.get("TELEGRAM_CHAT_ID", ""))
    sep()

    active = cfg.get("ACTIVE_RESPONSE", "false").strip().lower() == "true"
    print("  {:<18}: {}".format("Réponse active", (
        c("r", "true — blocage RÉEL") if active else c("y", "false — simulation"))))
    print("  {:<18}: {} min".format("Durée blocage", cfg.get("BLOCK_DURATION_MIN", "10")))
    sep()

    health = http_json("http://127.0.0.1:{}/health".format(port), timeout=4)
    if health:
        thehive_ok = bool(health.get("thehive") or health.get("thehive_ok"))
        print("  Webhook :{:<9}: {}".format(port, c(
            "g" if thehive_ok else "y",
            "ACTIF ✓ | TheHive : {}".format("OK ✓" if thehive_ok else "injoignable ✗"))))
        stats = health.get("stats") or {}
        if stats:
            print("  {:<18}: {}".format("Statistiques", ", ".join(
                "{}={}".format(k, v) for k, v in sorted(stats.items()))))
    else:
        print("  Webhook :{:<9}: {}".format(
            port, c("y", "non démarré (normal si le Service A n'est pas lancé)")))
    sep()

    run_service_command(["list"])

    if not telegram_on or not cfg.get("TELEGRAM_TOKEN") or not cfg.get("TELEGRAM_CHAT_ID"):
        print("\n  {} Configurer Telegram : {}".format(
            c("y", "!"), c("c", "python start.py telegram-config")))


# ══════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════
def run_unit_tests() -> int:
    hdr("Tests unitaires (hors ligne)")
    if not UNIT_TESTS.exists():
        err("Fichier de tests introuvable : {}".format(UNIT_TESTS))
        return 1
    if not check_deps():
        return 1
    return subprocess.run([PYTHON, str(UNIT_TESTS)], cwd=str(ROOT)).returncode


def run_e2e_tests() -> int:
    """Chaîne complète contre un faux TheHive : aucun serveur réel requis."""
    hdr("Test d'intégration bout en bout (TheHive simulé)")
    if not E2E_TESTS.exists():
        err("Fichier de test introuvable : {}".format(E2E_TESTS))
        return 1
    if not check_deps():
        return 1
    print(c("m", "  Démarre un faux TheHive, le vrai Service A et le vrai Service B."))
    print(c("m", "  Aucune connexion Internet, aucune règle pare-feu posée.\n"))
    return subprocess.run([PYTHON, str(E2E_TESTS)], cwd=str(ROOT)).returncode


def run_tests() -> None:
    hdr("Tests end-to-end de l'intégration")
    cfg  = load_env()
    port = webhook_port(cfg)

    passed = failed = 0

    def check(name, fn):
        nonlocal passed, failed
        try:
            if fn():
                ok(name)
                passed += 1
                return
        except Exception as exc:              # noqa: BLE001 — un test ne doit pas tout stopper
            err("{} — {}".format(name, exc))
            failed += 1
            return
        err(name)
        failed += 1

    def health():
        data = http_json("http://127.0.0.1:{}/health".format(port), timeout=6)
        return bool(data and (data.get("thehive") or data.get("thehive_ok")))

    def send_alert():
        data = http_json("http://127.0.0.1:{}/alert".format(port), {
            "search_name": "TEST AUTOMATIQUE start.py",
            "severity": "high",
            "result": {
                "host":   "test-host",
                "src_ip": "185.220.101.50",
                "user":   "root",
                "source": "/var/log/auth.log",
                "_time":  datetime.now().isoformat(),
            },
        }, timeout=60)
        return bool(data and data.get("status") in ("created", "duplicate", "rate_limited"))

    def telegram_ping():
        data = http_json("http://127.0.0.1:{}/telegram-test".format(port), timeout=15)
        return bool(data and data.get("status") in ("success", "disabled"))

    sep()
    check("Service A joignable sur :{} et TheHive OK".format(port), health)
    check("Alerte de test acceptée par TheHive", send_alert)
    check("Notification Telegram", telegram_ping)
    sep()

    total = passed + failed
    print("  Résultat : {}/{} tests OK".format(c("g" if not failed else "y", passed), total))
    if failed:
        print("")
        warn("Lance d'abord les services : python start.py both")


# ══════════════════════════════════════════════════════════════════
# LOGS
# ══════════════════════════════════════════════════════════════════
def show_logs(lines: int = 30) -> None:
    hdr("Derniers journaux")
    found = False
    for log_file in sorted(LOGS_DIR.glob("*.log")):
        found = True
        sep()
        print("  {}".format(c("B", str(log_file))))
        sep()
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            err("Lecture impossible : {}".format(exc))
            continue
        for line in content[-lines:]:
            print("  " + line)
    if not found:
        warn("Aucun journal dans {} — lance d'abord un service".format(LOGS_DIR))


# ══════════════════════════════════════════════════════════════════
# MENU
# ══════════════════════════════════════════════════════════════════
def _ask_and_test_block():
    ip = input("  {} IP à tester (ex. 203.0.113.10) : ".format(c("c", "→"))).strip()
    if not ip:
        warn("Aucune IP saisie")
        return 2
    return run_service_command(["test-block", ip])


MENU_ENTRIES = [
    ("1", "Installer les dépendances Python", install_deps),
    ("2", "Créer / réinitialiser le fichier .env", init_env),
    ("3", "Lancer le Service A (webhook Splunk → TheHive)", launch_service_a),
    ("4", "Lancer le Service B (Cortex + MISP + blocage)", launch_service_b),
    ("5", "Lancer A + B ensemble", launch_both),
    ("6", "Relancer en administrateur (blocage réel)", lambda: elevate(["both"])),
    ("7", "Configurer Telegram", configure_telegram),
    ("8", "Tester Telegram", test_telegram),
    ("9", "État de l'intégration", check_status),
    ("10", "Tester le blocage firewall sur une IP", _ask_and_test_block),
    ("11", "Réponse fichiers + quarantaine", lambda: run_service_command(["files"])),
    ("12", "Analyseurs Cortex détectés", lambda: run_service_command(["cortex"])),
    ("13", "IPs actuellement bloquées", lambda: run_service_command(["list"])),
    ("14", "Tests unitaires (hors ligne)", run_unit_tests),
    ("15", "Test d'intégration bout en bout (TheHive simulé)", run_e2e_tests),
    ("16", "Tests end-to-end (services réels lancés)", run_tests),
    ("17", "Afficher les journaux", show_logs),
]
BLOCKING_CHOICES = {"3", "4", "5"}


def menu() -> None:
    while True:
        os.system("cls" if IS_WINDOWS else "clear")
        cfg = load_env()
        telegram_ready = (cfg.get("TELEGRAM_ENABLED", "false").strip().lower() == "true"
                          and cfg.get("TELEGRAM_TOKEN") and cfg.get("TELEGRAM_CHAT_ID"))

        print("")
        print(c("c", "  ╔══════════════════════════════════════════════════════╗"))
        print(c("c", "  ║") + c("B", "   🛡️  SOC Automation Pipeline — SOAR                 ")
              + c("c", "║"))
        print(c("c", "  ║") + c("m", "        Réponse automatisée aux incidents  ·  12ak_H4ck")
              + c("c", "║"))
        print(c("c", "  ╚══════════════════════════════════════════════════════╝"))
        print("")
        print("  TheHive  : {}".format(c("c", cfg.get("THEHIVE_URL", "non défini"))))
        print("  Cortex   : {}".format(c("c", cfg.get("CORTEX_URL", "non défini"))))
        print("  MISP     : {}".format(c("c", cfg.get("MISP_URL", "non défini"))))
        print("  Telegram : {}".format(
            c("g", "✅ configuré") if telegram_ready else c("r", "❌ non configuré")))
        print("  Blocage  : {}".format(
            c("r", "🔴 RÉEL")
            if cfg.get("ACTIVE_RESPONSE", "false").strip().lower() == "true"
            else c("y", "⚠️ simulation")))
        print("")
        sep()
        print(c("B", "  Que veux-tu faire ?"))
        sep()
        for key, label, _ in MENU_ENTRIES:
            print("  {}  {}".format(c("y", "[{}]".format(key)).ljust(16), label))
        print("  {}  Quitter".format(c("m", "[0]").ljust(16)))
        sep()

        try:
            choice = input("  {} Choix : ".format(c("c", "→"))).strip()
        except (EOFError, KeyboardInterrupt):
            print("")
            return

        if choice == "0":
            return

        action = next((fn for key, _, fn in MENU_ENTRIES if key == choice), None)
        if action is None:
            warn("Choix invalide")
        else:
            try:
                action()
            except KeyboardInterrupt:
                print("")
                warn("Interrompu")

        if choice not in BLOCKING_CHOICES:
            try:
                input("\n  {} Entrée pour revenir au menu...".format(c("m", "→")))
            except (EOFError, KeyboardInterrupt):
                print("")
                return


# ══════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════
USAGE = """
Usage : python start.py [commande]

  Installation
    install            Installer les dépendances Python
    init               Créer le .env depuis .env.example

  Services
    a                  Service A — webhook Splunk → TheHive
    b                  Service B — Cortex + MISP + blocage + fichiers
    both               Lancer A + B avec redémarrage automatique
    elevate [cmd]      Relancer en administrateur / root (blocage réel)

  Réponse active — IP
    test-block <ip>    Prouver que le blocage firewall fonctionne
    list               Lister les IPs actuellement bloquées
    unblock <ip>       Débloquer une IP

  Réponse active — fichiers malveillants
    files              État de la réponse fichier + quarantaine
    scan <hash>        Chercher un hash et appliquer le mode configuré
    restore <id>       Restaurer un fichier mis en quarantaine
    purge <id>         Supprimer définitivement un élément en quarantaine

  Diagnostic
    status             État complet de l'intégration
    cortex             Analyseurs Cortex détectés
    unit               Tests unitaires (hors ligne)
    e2e                Test d'intégration bout en bout (TheHive simulé)
    test               Tests end-to-end (services réels lancés)
    telegram           Envoyer un message de test Telegram
    telegram-config    Configurer Telegram pas à pas
    logs               Afficher la fin des journaux

  (sans argument)      Menu interactif
"""


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    DATA_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    if not args:
        menu()
        return 0

    command = args[0].lower()

    if command == "install":
        return 0 if install_deps() else 1
    if command == "init":
        return 0 if init_env() else 1
    if command == "a":
        launch_service_a()
        return 0
    if command == "b":
        launch_service_b()
        return 0
    if command in ("both", "all"):
        launch_both()
        return 0
    if command in ("telegram", "tg"):
        test_telegram()
        return 0
    if command in ("telegram-config", "tg-config"):
        configure_telegram()
        return 0
    if command in ("status", "st"):
        check_status()
        return 0
    if command in ("test", "tests"):
        run_tests()
        return 0
    if command in ("unit", "unittest", "unit-tests"):
        return run_unit_tests()
    if command in ("e2e", "integration"):
        return run_e2e_tests()
    if command in ("list", "ls", "blocked"):
        return run_service_command(["list"])
    if command == "unblock":
        if len(args) < 2:
            err("Usage : python start.py unblock <ip>")
            return 2
        return run_service_command(["unblock", args[1]])
    if command in ("test-block", "testblock"):
        if len(args) < 2:
            err("Usage : python start.py test-block <ip>")
            return 2
        return run_service_command(["test-block", args[1]])
    if command in ("files", "quarantine"):
        return run_service_command(["files"])
    if command == "scan":
        if len(args) < 2:
            err("Usage : python start.py scan <hash md5|sha1|sha256>")
            return 2
        return run_service_command(["scan", args[1]])
    if command == "restore":
        if len(args) < 2:
            err("Usage : python start.py restore <id>  (voir python start.py files)")
            return 2
        return run_service_command(["restore", args[1]])
    if command == "purge":
        if len(args) < 2:
            err("Usage : python start.py purge <id>")
            return 2
        return run_service_command(["purge", args[1]])
    if command in ("elevate", "admin", "sudo"):
        return elevate(args[1:])
    if command in ("cortex", "analyzers"):
        return run_service_command(["cortex"])
    if command in ("logs", "log"):
        show_logs()
        return 0

    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
