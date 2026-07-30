#!/usr/bin/env python3
"""
Lance toute la suite de tests unitaires (hors ligne).

    python tests/run_tests.py
    python start.py unit

Chaque fichier de test est exécuté dans son propre processus : les
modules des services configurent des singletons au chargement, on évite
ainsi toute interférence entre les suites.
"""

import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SUITES = ["test_soc_common.py", "test_file_responder.py",
          "test_service_a.py", "test_service_b.py"]

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass


def main() -> int:
    failures = []
    for suite in SUITES:
        path = TESTS_DIR / suite
        if not path.exists():
            print("[IGNORÉ] {} introuvable".format(suite))
            continue
        code = subprocess.run([sys.executable, str(path)],
                              cwd=str(TESTS_DIR.parent)).returncode
        if code != 0:
            failures.append(suite)

    print("\n" + "=" * 60)
    if failures:
        print("  RÉSULTAT GLOBAL : ÉCHEC — {}".format(", ".join(failures)))
        print("=" * 60)
        return 1
    print("  RÉSULTAT GLOBAL : toutes les suites sont vertes")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
