#!/usr/bin/env python3
"""
start.py — SOC Automation Pipeline
====================================
Lanceur universel : Windows, Ubuntu, Debian, CentOS, Arch, macOS
Une seule commande pour tout installer et démarrer.

Usage :
    python start.py          → menu interactif
    python start.py install  → installer les dépendances
    python start.py a        → lancer Service A (webhook Splunk→TheHive)
    python start.py b        → lancer Service B (Cortex+MISP responder)
    python start.py both     → lancer A + B ensemble
    python start.py test     → tester toute l'intégration
    python start.py telegram → tester Telegram
    python start.py status   → état des services
"""

import os
import sys
import time
import json
import subprocess
import threading
import platform
from pathlib import Path
from datetime import datetime

# ══════════════════════════════════════════════════════════════════
# COULEURS — fonctionnent sur Windows 10+, Linux, macOS
# ══════════════════════════════════════════════════════════════════
if platform.system() == "Windows":
    os.system("")  # active ANSI sur Windows

C = {
    "g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
    "b": "\033[94m", "c": "\033[96m", "p": "\033[95m",
    "w": "\033[97m", "m": "\033[90m", "x": "\033[0m",
    "B": "\033[1m",
}

def c(color, text): return "{}{}{}".format(C[color], text, C["x"])
def ok(msg):   print("  {} {}".format(c("g", "✓"), msg))
def warn(msg): print("  {} {}".format(c("y", "!"), msg))
def err(msg):  print("  {} {}".format(c("r", "✗"), msg))
def hdr(msg):  print("\n{}  {}  {}".format(c("c", "═"*2), c("B", msg), c("c", "═"*(50-len(msg)))))
def sep():     print(c("m", "  " + "─"*58))

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════
SCRIPT_DIR   = Path(__file__).parent
SERVICE_A    = SCRIPT_DIR / "service_splunk_to_thehive.py"
SERVICE_B    = SCRIPT_DIR / "service_thehive_responder.py"
ENV_FILE     = SCRIPT_DIR / ".env"
REQ_FILE     = SCRIPT_DIR / "requirements.txt"
WEBHOOK_PORT = 5000

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

# Trouver le bon python
PYTHON = sys.executable  # utilise le même python que ce script


# ══════════════════════════════════════════════════════════════════
# LECTURE DU .env
# ══════════════════════════════════════════════════════════════════
def load_env() -> dict:
    """Lit le .env et retourne un dict."""
    cfg = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def save_env_key(key: str, value: str):
    """Met à jour une clé dans le .env sans toucher au reste."""
    lines = []
    found = False
    if ENV_FILE.exists():
        with open(ENV_FILE, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith(key + "=") or stripped.startswith(key + " ="):
                    lines.append("{}={}\n".format(key, value))
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append("{}={}\n".format(key, value))
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)


# ══════════════════════════════════════════════════════════════════
# INSTALLATION DES DÉPENDANCES
# ══════════════════════════════════════════════════════════════════
def install_deps():
    hdr("Installation des dépendances Python")

    if not REQ_FILE.exists():
        err("requirements.txt introuvable dans {}".format(SCRIPT_DIR))
        err("Crée-le avec : flask thehive4py requests urllib3")
        return False

    print(c("m", "  Python  : {}".format(sys.version.split()[0])))
    print(c("m", "  OS      : {} {}".format(platform.system(), platform.release())))
    print(c("m", "  Pip     : {}".format(PYTHON)))
    sep()

    cmd = [PYTHON, "-m", "pip", "install", "-r", str(REQ_FILE), "--quiet", "--upgrade"]
    print("  Installation en cours...\n")

    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
        if result.returncode == 0:
            ok("Toutes les dépendances installées")
            return True
        else:
            # Réessayer avec --break-system-packages (Ubuntu 22.04+)
            warn("Première tentative échouée — essai avec --break-system-packages")
            cmd2 = cmd + ["--break-system-packages"]
            result2 = subprocess.run(cmd2, capture_output=False, text=True)
            if result2.returncode == 0:
                ok("Dépendances installées (--break-system-packages)")
                return True
            else:
                err("Échec installation. Lance manuellement : pip install -r requirements.txt")
                return False
    except Exception as e:
        err("Erreur : {}".format(e))
        return False


# ══════════════════════════════════════════════════════════════════
# CONFIGURATION TELEGRAM INTERACTIVE
# ══════════════════════════════════════════════════════════════════
def configure_telegram():
    hdr("Configuration Telegram")
    cfg = load_env()

    print("""
  Pour créer ton bot Telegram :
  {}  1. Ouvre Telegram → cherche @BotFather
  {}  2. Envoie : /newbot
  {}  3. Donne un nom : {}
  {}  4. Donne un username : {} (doit finir par 'bot')
  {}  5. Copie le TOKEN donné par BotFather
""".format(
        c("c","→"), c("c","→"), c("c","→"), c("y","SOC_Rachad"),
        c("c","→"), c("y","SOC_Rachad_Bot"), c("c","→")
    ))

    # Token
    current_token = cfg.get("TELEGRAM_TOKEN", "")
    if current_token:
        print("  Token actuel : {}{}...".format(c("y", current_token[:12]), c("m", " (Entrée pour garder)")))
    token = input("  {} Colle ton TOKEN BotFather : ".format(c("c","→"))).strip()
    if not token and current_token:
        token = current_token
    if not token:
        err("Token requis")
        return

    # Vérifier le token
    print("\n  Vérification du token...")
    try:
        import urllib.request
        url = "https://api.telegram.org/bot{}/getMe".format(token)
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read())
        bot_name = data.get("result", {}).get("username", "?")
        ok("Bot valide : @{}".format(bot_name))
    except Exception as e:
        err("Token invalide ou pas de connexion : {}".format(e))
        if input("  Continuer quand même ? (o/N) : ").lower() != "o":
            return

    # Chat ID
    print("""
  Pour récupérer ton Chat ID :
  {}  1. Ouvre Telegram → envoie /start à ton bot @{}
  {}  2. Lance cette commande dans un autre terminal :
""".format(c("c","→"), bot_name if "bot_name" in dir() else "tonbot", c("c","→")))
    print("     {}".format(c("y", "curl https://api.telegram.org/bot{}/getUpdates".format(token[:20]+"..."))))
    print('  {}  3. Cherche "id" dans la réponse JSON\n'.format(c("c","→")))

    current_chat = cfg.get("TELEGRAM_CHAT_ID", "")
    if current_chat:
        print("  Chat ID actuel : {}{}".format(c("y", current_chat), c("m", " (Entrée pour garder)")))
    chat_id = input("  {} Colle ton Chat ID : ".format(c("c","→"))).strip()
    if not chat_id and current_chat:
        chat_id = current_chat
    if not chat_id:
        err("Chat ID requis")
        return

    # Sauvegarder
    save_env_key("TELEGRAM_TOKEN",   token)
    save_env_key("TELEGRAM_CHAT_ID", chat_id)
    save_env_key("TELEGRAM_ENABLED", "true")
    ok("Sauvegardé dans {}".format(ENV_FILE))

    # Envoyer message test
    print("\n  Envoi d'un message de test...")
    try:
        import urllib.request, urllib.parse
        msg = "🧪 <b>SOC Telegram configuré !</b>\n✅ Connexion OK\n📅 {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        payload = json.dumps({
            "chat_id":    chat_id,
            "text":       msg,
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(
            "https://api.telegram.org/bot{}/sendMessage".format(token),
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()
        ok("Message de test envoyé ! Vérifie Telegram.")
    except Exception as e:
        err("Erreur envoi test : {}".format(e))


# ══════════════════════════════════════════════════════════════════
# TEST TELEGRAM DIRECT
# ══════════════════════════════════════════════════════════════════
def test_telegram():
    hdr("Test Telegram")
    cfg = load_env()

    enabled  = cfg.get("TELEGRAM_ENABLED", "false").lower() == "true"
    token    = cfg.get("TELEGRAM_TOKEN", "")
    chat_id  = cfg.get("TELEGRAM_CHAT_ID", "")

    sep()
    print("  TELEGRAM_ENABLED  : {}".format(
        c("g","true ✓") if enabled else c("r","false ✗")
    ))
    print("  TELEGRAM_TOKEN    : {}".format(
        c("g", token[:12]+"...") if token else c("r","VIDE ✗")
    ))
    print("  TELEGRAM_CHAT_ID  : {}".format(
        c("g", chat_id) if chat_id else c("r","VIDE ✗")
    ))
    sep()

    if not enabled:
        err("TELEGRAM_ENABLED=false → lance : python start.py telegram-config")
        return
    if not token:
        err("TELEGRAM_TOKEN vide dans .env")
        return
    if not chat_id:
        err("TELEGRAM_CHAT_ID vide dans .env")
        return

    # Test getMe
    print("  Vérification du token...")
    try:
        import urllib.request
        with urllib.request.urlopen(
            "https://api.telegram.org/bot{}/getMe".format(token), timeout=8
        ) as resp:
            data = json.loads(resp.read())
        bot = data.get("result", {})
        ok("Bot @{} (id={})".format(bot.get("username","?"), bot.get("id","?")))
    except Exception as e:
        err("Token invalide : {}".format(e))
        warn("Solution : recrée le token via @BotFather ou vérifie la connexion internet")
        return

    # Envoyer message test
    print("  Envoi du message de test...")
    try:
        import urllib.request
        msg = (
            "🧪 <b>TEST SOC — Service A</b>\n\n"
            "✅ Telegram fonctionne !\n"
            "⏰ {}\n\n"
            "<b>TheHive :</b> {}\n"
            "<i>Les alertes Splunk High/Critical seront notifiées ici.</i>"
        ).format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cfg.get("THEHIVE_URL", "http://10.2.3.122:9000"),
        )
        payload = json.dumps({
            "chat_id":    chat_id,
            "text":       msg,
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(
            "https://api.telegram.org/bot{}/sendMessage".format(token),
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp_data = json.loads(resp.read())
        if resp_data.get("ok"):
            ok("Message envoyé ! Vérifie ton Telegram maintenant.")
        else:
            desc = resp_data.get("description", "?")
            err("Échec : {}".format(desc))
            if "chat not found" in desc.lower():
                warn("Solution : envoie /start au bot dans Telegram d'abord")
            elif "blocked" in desc.lower():
                warn("Solution : débloque le bot dans Telegram")
    except Exception as e:
        err("Erreur envoi : {}".format(e))


# ══════════════════════════════════════════════════════════════════
# LANCEMENT DES SERVICES
# ══════════════════════════════════════════════════════════════════
def run_service(script: Path, name: str) -> subprocess.Popen:
    """Lance un service dans un subprocess."""
    if not script.exists():
        err("Script introuvable : {}".format(script))
        return None

    env = os.environ.copy()

    # Charger le .env dans l'env du subprocess
    cfg = load_env()
    env.update(cfg)

    print("  Lancement de {}...".format(c("b", name)))

    proc = subprocess.Popen(
        [PYTHON, str(script)],
        cwd=str(SCRIPT_DIR),
        env=env,
        # Pas de capture — affiche directement dans le terminal
    )
    return proc


def launch_service_a():
    hdr("Service A — Splunk → TheHive (webhook :5000)")
    check_env()
    proc = run_service(SERVICE_A, "Service A")
    if proc:
        print("")
        ok("Service A lancé (PID {})".format(proc.pid))
        print(c("m", "  Ctrl+C pour arrêter\n"))
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            ok("Service A arrêté")


def launch_service_b():
    hdr("Service B — TheHive Responder (Cortex + MISP)")
    check_env()
    proc = run_service(SERVICE_B, "Service B")
    if proc:
        print("")
        ok("Service B lancé (PID {})".format(proc.pid))
        print(c("m", "  Ctrl+C pour arrêter\n"))
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            ok("Service B arrêté")


def launch_both():
    hdr("Service A + B — Lancement simultané")
    check_env()

    proc_a = run_service(SERVICE_A, "Service A (webhook :5000)")
    time.sleep(2)
    proc_b = run_service(SERVICE_B, "Service B (responder Cortex+MISP)")

    if not proc_a or not proc_b:
        return

    print("")
    ok("Service A PID {}".format(proc_a.pid))
    ok("Service B PID {}".format(proc_b.pid))
    print(c("m", "\n  Les deux services tournent. Ctrl+C pour arrêter.\n"))

    try:
        while True:
            # Vérifier que les deux sont toujours vivants
            if proc_a.poll() is not None:
                warn("Service A s'est arrêté (code {}) — redémarrage...".format(proc_a.returncode))
                proc_a = run_service(SERVICE_A, "Service A")
            if proc_b.poll() is not None:
                warn("Service B s'est arrêté (code {}) — redémarrage...".format(proc_b.returncode))
                proc_b = run_service(SERVICE_B, "Service B")
            time.sleep(5)
    except KeyboardInterrupt:
        print("")
        ok("Arrêt demandé...")
        for p, n in [(proc_a, "Service A"), (proc_b, "Service B")]:
            if p and p.poll() is None:
                p.terminate()
                ok("{} arrêté".format(n))


# ══════════════════════════════════════════════════════════════════
# VÉRIFICATION DE L'ENVIRONNEMENT
# ══════════════════════════════════════════════════════════════════
def check_env():
    cfg = load_env()
    issues = []

    if not cfg.get("THEHIVE_APIKEY") and not cfg.get("THEHIVE_URL"):
        issues.append("THEHIVE_URL et THEHIVE_APIKEY non définis")

    tg_enabled = cfg.get("TELEGRAM_ENABLED","false").lower() == "true"
    if tg_enabled:
        if not cfg.get("TELEGRAM_TOKEN"):
            issues.append("TELEGRAM_ENABLED=true mais TELEGRAM_TOKEN vide")
        if not cfg.get("TELEGRAM_CHAT_ID"):
            issues.append("TELEGRAM_ENABLED=true mais TELEGRAM_CHAT_ID vide")

    if issues:
        print("")
        for i in issues:
            warn(i)
        print("")


def check_status():
    hdr("État de l'intégration")
    cfg = load_env()
    sep()

    # .env
    env_status = c("g","✓ trouvé") if ENV_FILE.exists() else c("r","✗ manquant")
    print("  .env file         : {}".format(env_status))

    # Scripts
    for name, path in [("Service A", SERVICE_A), ("Service B", SERVICE_B)]:
        s = c("g","✓ trouvé") if path.exists() else c("r","✗ manquant")
        print("  {}  : {}".format(name, s))

    sep()

    # Config TheHive
    th_url = cfg.get("THEHIVE_URL","NON DEFINI")
    th_key = cfg.get("THEHIVE_APIKEY","")
    print("  TheHive URL       : {}".format(c("c", th_url)))
    print("  TheHive API Key   : {}".format(
        c("g", th_key[:10]+"...") if th_key else c("r","VIDE")
    ))

    # Config Cortex
    cx_url = cfg.get("CORTEX_URL","NON DEFINI")
    cx_key = cfg.get("CORTEX_APIKEY","")
    print("  Cortex URL        : {}".format(c("c", cx_url)))
    print("  Cortex API Key    : {}".format(
        c("g", cx_key[:10]+"...") if cx_key else c("r","VIDE")
    ))

    # Config MISP
    misp_url = cfg.get("MISP_URL","NON DEFINI")
    misp_key = cfg.get("MISP_APIKEY","")
    misp_en  = cfg.get("MISP_ENABLED","false")
    print("  MISP URL          : {}".format(c("c", misp_url)))
    print("  MISP Enabled      : {}".format(
        c("g","true ✓") if misp_en.lower()=="true" else c("y","false")
    ))

    sep()

    # Telegram
    tg_en   = cfg.get("TELEGRAM_ENABLED","false").lower() == "true"
    tg_tok  = cfg.get("TELEGRAM_TOKEN","")
    tg_chat = cfg.get("TELEGRAM_CHAT_ID","")
    print("  Telegram Enabled  : {}".format(c("g","true ✓") if tg_en else c("y","false")))
    print("  Telegram Token    : {}".format(
        c("g", tg_tok[:12]+"...") if tg_tok else c("r","VIDE — configurer!")
    ))
    print("  Telegram Chat ID  : {}".format(
        c("g", tg_chat) if tg_chat else c("r","VIDE — configurer!")
    ))

    sep()

    # Webhook accessible ?
    try:
        import urllib.request
        with urllib.request.urlopen(
            "http://localhost:{}/health".format(WEBHOOK_PORT), timeout=3
        ) as resp:
            data = json.loads(resp.read())
        status = data.get("status","?")
        th_ok  = data.get("thehive_ok", False)
        print("  Webhook :{}      : {}".format(
            WEBHOOK_PORT,
            c("g","ACTIF ✓ | TheHive: {}".format("OK ✓" if th_ok else "ERREUR ✗"))
        ))
    except Exception:
        print("  Webhook :{}      : {}".format(
            WEBHOOK_PORT, c("y","non démarré (normal si Service A pas lancé)")
        ))

    sep()

    if not tg_en or not tg_tok or not tg_chat:
        print("\n  {} Pour configurer Telegram :".format(c("y","!")))
        print("    {}".format(c("c","python start.py telegram-config")))
    if tg_en and tg_tok and tg_chat:
        print("\n  {} Pour tester Telegram :".format(c("g","✓")))
        print("    {}".format(c("c","python start.py telegram")))


# ══════════════════════════════════════════════════════════════════
# TEST COMPLET
# ══════════════════════════════════════════════════════════════════
def run_tests():
    hdr("Test complet de l'intégration")

    try:
        import urllib.request

        tests_ok = 0
        tests_ko = 0

        def test(name, fn):
            nonlocal tests_ok, tests_ko
            try:
                result = fn()
                if result:
                    ok(name)
                    tests_ok += 1
                else:
                    err(name)
                    tests_ko += 1
            except Exception as e:
                err("{} — {}".format(name, e))
                tests_ko += 1

        def health():
            with urllib.request.urlopen(
                "http://localhost:{}/health".format(WEBHOOK_PORT), timeout=5
            ) as r:
                d = json.loads(r.read())
            return d.get("thehive_ok", False)

        def send_test_alert():
            payload = json.dumps({
                "search_name": "TEST AUTOMATIQUE start.py",
                "severity": "high",
                "result": {
                    "host": "test-host",
                    "src_ip": "10.2.3.50",
                    "user": "root",
                    "source": "/var/log/auth.log",
                    "_time": datetime.utcnow().isoformat(),
                }
            }).encode()
            req = urllib.request.Request(
                "http://localhost:{}/alert".format(WEBHOOK_PORT),
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read())
            return d.get("status") in ("created", "duplicate")

        def tg_test():
            with urllib.request.urlopen(
                "http://localhost:{}/telegram-test".format(WEBHOOK_PORT), timeout=10
            ) as r:
                d = json.loads(r.read())
            return d.get("status") == "success"

        sep()
        test("Service A webhook actif sur :{}".format(WEBHOOK_PORT), health)
        test("Alerte test → TheHive", send_test_alert)
        test("Notification Telegram", tg_test)
        sep()

        total = tests_ok + tests_ko
        print("  Résultat : {}/{} tests OK".format(
            c("g" if tests_ko==0 else "y", tests_ok), total
        ))

        if tests_ko > 0:
            print("")
            warn("Service A doit être lancé d'abord : python start.py a")

    except Exception as e:
        err("Erreur tests : {}".format(e))
        warn("Lance Service A d'abord : python start.py a")


# ══════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════════
def menu():
    os.system("cls" if IS_WINDOWS else "clear")

    cfg = load_env()
    tg_ok = (cfg.get("TELEGRAM_ENABLED","false").lower()=="true"
             and cfg.get("TELEGRAM_TOKEN","")
             and cfg.get("TELEGRAM_CHAT_ID",""))

    print("")
    print(c("c","  ╔══════════════════════════════════════════════════════╗"))
    print(c("c","  ║") + c("B","   🛡️  SOC Automation Pipeline — Rachad Lab          ") + c("c","║"))
    print(c("c","  ╚══════════════════════════════════════════════════════╝"))
    print("")
    print("  TheHive  : {}".format(c("c", cfg.get("THEHIVE_URL","NON DEFINI"))))
    print("  Cortex   : {}".format(c("c", cfg.get("CORTEX_URL","NON DEFINI"))))
    print("  MISP     : {}".format(c("c", cfg.get("MISP_URL","NON DEFINI"))))
    print("  Telegram : {}".format(
        c("g","✅ Configuré") if tg_ok else c("r","❌ Non configuré")
    ))
    print("")
    sep()
    print(c("B","  Que veux-tu faire ?"))
    sep()
    print("  {}  Installer les dépendances Python".format(c("y","[1]")))
    print("  {}  Lancer Service A (webhook Splunk→TheHive)".format(c("y","[2]")))
    print("  {}  Lancer Service B (Cortex + MISP responder)".format(c("y","[3]")))
    print("  {}  Lancer A + B ensemble".format(c("y","[4]")))
    print("  {}  {} Configurer Telegram".format(
        c("y","[5]"),
        c("r","[REQUIS]") if not tg_ok else c("g","[OK]")
    ))
    print("  {}  Tester Telegram (envoyer message de test)".format(c("y","[6]")))
    print("  {}  État de l'intégration".format(c("y","[7]")))
    print("  {}  Lancer les tests complets".format(c("y","[8]")))
    print("  {}  Quitter".format(c("m","[0]")))
    sep()

    choice = input("  {} Choix : ".format(c("c","→"))).strip()

    actions = {
        "1": install_deps,
        "2": launch_service_a,
        "3": launch_service_b,
        "4": launch_both,
        "5": configure_telegram,
        "6": test_telegram,
        "7": check_status,
        "8": run_tests,
        "0": lambda: sys.exit(0),
    }

    fn = actions.get(choice)
    if fn:
        fn()
    else:
        warn("Choix invalide")

    if choice not in ("2", "3", "4"):
        input("\n  {} Appuie sur Entrée pour revenir au menu...".format(c("m","→")))
        menu()


# ══════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        menu()

    elif args[0] == "install":
        install_deps()

    elif args[0] == "a":
        launch_service_a()

    elif args[0] == "b":
        launch_service_b()

    elif args[0] in ("both", "all"):
        launch_both()

    elif args[0] in ("telegram", "tg"):
        test_telegram()

    elif args[0] in ("telegram-config", "tg-config"):
        configure_telegram()

    elif args[0] in ("status", "st"):
        check_status()

    elif args[0] in ("test", "tests"):
        run_tests()

    else:
        print("""
Usage : python start.py [commande]

  install          Installer les dépendances
  a                Lancer Service A (webhook Splunk→TheHive :5000)
  b                Lancer Service B (Cortex + MISP responder)
  both             Lancer A + B ensemble avec redémarrage auto
  telegram         Tester Telegram (envoyer un message de test)
  telegram-config  Configurer Telegram interactivement
  status           État de toute l'intégration
  test             Tests complets end-to-end

  (sans argument)  Menu interactif
""")
