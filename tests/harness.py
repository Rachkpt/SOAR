#!/usr/bin/env python3
"""
Mini-harnais de test — aucune dépendance externe (pas de pytest requis).

Rôle :
  - isoler complètement les tests du .env réel (SOC_SKIP_DOTENV=1)
  - rediriger logs / état / blacklist vers tests/.tmp
  - fournir un compteur de tests et un décorateur `check`
"""

import os
import shutil
import sys
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src"
TMP_DIR = Path(__file__).resolve().parent / ".tmp"

# La sortie des tests contient des accents et des flèches : sous Windows la
# console est en cp1252 et lèverait UnicodeEncodeError sans ce réglage.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass


def bootstrap(extra_env=None):
    """Prépare l'environnement de test et rend `src/` importable."""
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR, ignore_errors=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    os.environ["SOC_SKIP_DOTENV"] = "1"
    defaults = {
        "THEHIVE_URL":      "http://127.0.0.1:9000",
        "THEHIVE_APIKEY":   "clef_de_test",
        "CORTEX_ENABLED":   "false",
        "CORTEX_APIKEY":    "",
        "VT_ENABLED":       "false",
        "VT_APIKEY":        "",
        "MISP_ENABLED":     "false",
        "MISP_APIKEY":      "",
        "TELEGRAM_ENABLED": "false",
        "TELEGRAM_TOKEN":   "",
        "TELEGRAM_CHAT_ID": "",
        "GMAIL_ENABLED":    "false",
        "ACTIVE_RESPONSE":  "false",
        "RATE_LIMIT_SEC":   "0",
        "LOG_LEVEL":        "CRITICAL",
        "LOG_FILE":         str(TMP_DIR / "service_a.log"),
        "LOG_FILE_B":       str(TMP_DIR / "service_b.log"),
        "STATE_FILE":       str(TMP_DIR / "state.json"),
        "BLACKLIST_FILE":   str(TMP_DIR / "ip_blacklist.txt"),
    }
    defaults.update(extra_env or {})
    os.environ.update(defaults)

    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))


class Runner:
    """Compteur de tests + affichage."""

    def __init__(self, title: str):
        self.title  = title
        self.passed = 0
        self.failed = 0
        print("\n" + "=" * 60)
        print("  {}".format(title))
        print("=" * 60)

    def section(self, name: str) -> None:
        print("\n{}".format(name))

    def check(self, name: str, fn) -> None:
        try:
            fn()
        except AssertionError as exc:
            self.failed += 1
            print("  [ECHEC] {} — assertion : {}".format(name, exc))
        except Exception as exc:                # noqa: BLE001 — on veut le type de l'erreur
            self.failed += 1
            print("  [ECHEC] {} — {} : {}".format(name, type(exc).__name__, exc))
        else:
            self.passed += 1
            print("  [OK]    {}".format(name))

    def report(self) -> int:
        total = self.passed + self.failed
        print("\n" + "-" * 60)
        print("  {} : {}/{} tests passés".format(self.title, self.passed, total))
        if self.failed:
            print("  {} test(s) en échec".format(self.failed))
        print("-" * 60)
        return 0 if self.failed == 0 else 1
