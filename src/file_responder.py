#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Réponse sur fichiers malveillants ║
║  Recherche par hash → mise en quarantaine ou suppression     ║
╚══════════════════════════════════════════════════════════════╝

Quand VirusTotal, MISP ou Cortex confirment qu'un hash est malveillant,
ce module retrouve le fichier correspondant sur les chemins surveillés
et applique la réponse configurée.

Trois modes (FILE_RESPONSE_MODE) :
  report      — signale seulement l'emplacement du fichier (défaut)
  quarantine  — déplace le fichier dans un coffre, action RÉVERSIBLE
  delete      — supprime définitivement le fichier

Garde-fous, dans cet ordre :
  1. Le module est inactif tant que FILE_RESPONSE_ENABLED=false
  2. Aucun chemin n'est scanné tant que FILE_SCAN_PATHS est vide
  3. Les répertoires système sont refusés, même explicitement listés
  4. La racine d'un disque est refusée
  5. Les liens symboliques ne sont jamais suivis ni touchés
  6. Seuls les hashes CONFIRMÉS malveillants déclenchent une action
  7. Au-delà de FILE_MAX_SIZE_MB le fichier n'est pas lu

La quarantaine est le mode conseillé : un faux positif se restaure avec
`python start.py restore <id>`, une suppression est irréversible.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import uuid
from datetime import datetime
from pathlib import Path

from soc_common import DATA_DIR, now_str, utcnow_iso

# ──────────────────────────────────────────────────────────────────
# RÉPERTOIRES INTERDITS — jamais scannés, jamais modifiés
# ──────────────────────────────────────────────────────────────────
if os.name == "nt":
    PROTECTED_DIRS = [
        r"c:\windows", r"c:\program files", r"c:\program files (x86)",
        r"c:\programdata\microsoft", r"c:\$recycle.bin",
        r"c:\system volume information", r"c:\perflogs",
    ]
else:
    PROTECTED_DIRS = [
        "/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32",
        "/etc", "/boot", "/proc", "/sys", "/dev", "/run",
        "/var/lib/dpkg", "/var/lib/rpm", "/snap",
    ]

HASH_ALGOS = {32: "md5", 40: "sha1", 64: "sha256"}


class FileResponseError(Exception):
    """Erreur de configuration empêchant toute action sur les fichiers."""


# ──────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────
def normalize_hash(value) -> str:
    """Hash normalisé en minuscules, ou "" si ce n'est pas un hash connu."""
    text = str(value or "").strip().lower()
    if len(text) in HASH_ALGOS and all(c in "0123456789abcdef" for c in text):
        return text
    return ""


def is_protected(path: Path) -> bool:
    """Vrai si le chemin touche un répertoire système ou une racine de disque."""
    raw = str(path).strip().lower().rstrip("\\/")

    # « C: » seul désigne le dossier courant du disque C: une fois résolu :
    # il faut donc tester la forme brute AVANT resolve(), sinon une racine
    # de disque passerait au travers du filtre.
    if not raw:
        return True
    if os.name == "nt" and len(raw) == 2 and raw[1] == ":":
        return True
    if raw == "/":
        return True

    try:
        resolved = str(path.resolve()).lower().rstrip("\\/")
    except OSError:
        return True
    if not resolved:
        return True

    # Racine d'un disque (« c: » après rstrip) ou du système de fichiers
    if os.name == "nt" and len(resolved) == 2 and resolved[1] == ":":
        return True
    if resolved == "/":
        return True

    for candidate in (raw, resolved):
        for protected in PROTECTED_DIRS:
            if candidate == protected or candidate.startswith(protected + os.sep):
                return True
            # Séparateur alternatif : « C:/Windows » saisi à la main
            if candidate.startswith(protected.replace("\\", "/") + "/"):
                return True
    return False


def file_hashes(path: Path, max_bytes: int) -> dict:
    """Calcule md5 / sha1 / sha256 en une seule lecture du fichier."""
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    read = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            read += len(chunk)
            if read > max_bytes:
                return {}
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


# ══════════════════════════════════════════════════════════════════
# RESPONDER
# ══════════════════════════════════════════════════════════════════
class FileResponder:
    """Recherche des fichiers par hash et applique la réponse configurée."""

    VALID_MODES = ("report", "quarantine", "delete")

    def __init__(self, enabled=False, mode="report", scan_paths=None,
                 quarantine_dir=None, max_size_mb=200, max_files=200000,
                 logger=None, notifier=None):
        self.enabled  = bool(enabled)
        self.mode     = mode if mode in self.VALID_MODES else "report"
        self.max_size = max(1, int(max_size_mb)) * 1024 * 1024
        self.max_files = max(1000, int(max_files))
        self.log      = logger
        self.notify   = notifier or (lambda message: None)

        self.quarantine_dir = Path(quarantine_dir or (DATA_DIR / "quarantine"))
        self.manifest_path  = self.quarantine_dir / "manifest.json"

        self.scan_paths, self.rejected_paths = self._validate_paths(scan_paths or [])

    # ── configuration ────────────────────────────────────────────
    def _validate_paths(self, raw_paths) -> tuple:
        accepted, rejected = [], []
        for raw in raw_paths:
            text = str(raw).strip()
            if not text:
                continue
            path = Path(text).expanduser()
            if not path.exists():
                rejected.append((text, "chemin inexistant"))
                continue
            if not path.is_dir():
                rejected.append((text, "ce n'est pas un dossier"))
                continue
            if is_protected(path):
                rejected.append((text, "répertoire système protégé"))
                continue
            accepted.append(path.resolve())
        return accepted, rejected

    @property
    def ready(self) -> bool:
        return bool(self.enabled and self.scan_paths)

    def status(self) -> dict:
        return {
            "enabled":     self.enabled,
            "mode":        self.mode,
            "ready":       self.ready,
            "scan_paths":  [str(p) for p in self.scan_paths],
            "rejected":    self.rejected_paths,
            "quarantine":  str(self.quarantine_dir),
            "quarantined": len(self.load_manifest()),
        }

    def _info(self, message, *args):
        if self.log:
            self.log.info(message, *args)

    def _warn(self, message, *args):
        if self.log:
            self.log.warning(message, *args)

    def _error(self, message, *args):
        if self.log:
            self.log.error(message, *args)

    # ── manifeste de quarantaine ─────────────────────────────────
    def load_manifest(self) -> list:
        if not self.manifest_path.exists():
            return []
        try:
            with open(self.manifest_path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (OSError, ValueError) as exc:
            self._error("Manifeste de quarantaine illisible : %s", exc)
            return []

    def _save_manifest(self, entries) -> None:
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.manifest_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(entries, fh, indent=2, ensure_ascii=False)
            tmp.replace(self.manifest_path)
        except OSError as exc:
            self._error("Écriture du manifeste impossible : %s", exc)

    # ── recherche ────────────────────────────────────────────────
    def find_by_hashes(self, wanted) -> list:
        """Retourne [{path, size, hashes, matched_hash}] pour les fichiers trouvés."""
        targets = {normalize_hash(h) for h in wanted}
        targets.discard("")
        if not targets or not self.ready:
            return []

        matches, scanned = [], 0
        for root_path in self.scan_paths:
            for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
                current = Path(dirpath)
                if is_protected(current):
                    dirnames[:] = []
                    continue
                # ne jamais descendre dans la quarantaine elle-même
                try:
                    if current.resolve() == self.quarantine_dir.resolve():
                        dirnames[:] = []
                        continue
                except OSError:
                    dirnames[:] = []
                    continue

                for filename in filenames:
                    if scanned >= self.max_files:
                        self._warn("Analyse interrompue : %d fichiers parcourus (limite)",
                                   scanned)
                        return matches
                    candidate = current / filename
                    try:
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                        size = candidate.stat().st_size
                    except OSError:
                        continue
                    if size == 0 or size > self.max_size:
                        continue
                    scanned += 1
                    try:
                        digests = file_hashes(candidate, self.max_size)
                    except (OSError, PermissionError):
                        continue
                    if not digests:
                        continue
                    hit = next((h for h in digests.values() if h in targets), "")
                    if hit:
                        matches.append({"path": candidate, "size": size,
                                        "hashes": digests, "matched_hash": hit})
                        self._info("Fichier malveillant trouvé : %s (%s)", candidate, hit)
        self._info("Analyse terminée : %d fichier(s) lus, %d correspondance(s)",
                   scanned, len(matches))
        return matches

    # ── actions ──────────────────────────────────────────────────
    def respond(self, wanted_hashes, reason="hash malveillant confirmé") -> list:
        """Recherche puis applique la réponse. Retourne la liste des actions."""
        if not self.enabled:
            return []
        if not self.scan_paths:
            self._warn("Réponse fichier activée mais FILE_SCAN_PATHS est vide "
                       "— aucun dossier à analyser")
            return []

        actions = []
        for match in self.find_by_hashes(wanted_hashes):
            if self.mode == "report":
                actions.append(self._report(match, reason))
            elif self.mode == "quarantine":
                actions.append(self._quarantine(match, reason))
            elif self.mode == "delete":
                actions.append(self._delete(match, reason))
        return actions

    def _report(self, match, reason) -> dict:
        path = match["path"]
        self._warn("SIGNALEMENT : %s correspond à un hash malveillant (%s)", path, reason)
        self.notify("🔎 <b>Fichier malveillant localisé</b>\n"
                    "Chemin : <code>{}</code>\nSHA256 : <code>{}</code>\n"
                    "Raison : {}\n<i>Mode report — aucune action appliquée</i>".format(
                        path, match["hashes"]["sha256"][:32], reason))
        return {"action": "report", "path": str(path), "success": True,
                "hash": match["matched_hash"], "reason": reason}

    def _quarantine(self, match, reason) -> dict:
        path   = match["path"]
        sha256 = match["hashes"]["sha256"]

        # Deux fichiers identiques mis en quarantaine la même seconde
        # produiraient le même identifiant : le second écraserait le premier
        # dans le coffre et deviendrait irrécupérable. D'où le suffixe
        # aléatoire, et la boucle de sécurité sur le nom de destination.
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            while True:
                entry_id = "{}-{}-{}".format(
                    datetime.now().strftime("%Y%m%d%H%M%S"),
                    sha256[:12], uuid.uuid4().hex[:6])
                target = self.quarantine_dir / "{}.quarantine".format(entry_id)
                if not target.exists():
                    break
            shutil.move(str(path), str(target))
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except (OSError, shutil.Error) as exc:
            self._error("Quarantaine impossible pour %s : %s", path, exc)
            self.notify("❌ <b>Quarantaine échouée</b>\n<code>{}</code>\n{}".format(path, exc))
            return {"action": "quarantine", "path": str(path), "success": False,
                    "error": str(exc), "hash": match["matched_hash"]}

        entries = self.load_manifest()
        entries.append({
            "id":            entry_id,
            "original_path": str(path),
            "quarantined":   str(target),
            "size":          match["size"],
            "hashes":        match["hashes"],
            "matched_hash":  match["matched_hash"],
            "reason":        reason,
            "date":          utcnow_iso(),
            "restored":      False,
        })
        self._save_manifest(entries)

        self._warn("QUARANTAINE : %s → %s", path, target)
        self.notify("🔒 <b>Fichier mis en quarantaine</b>\n"
                    "Origine : <code>{}</code>\nSHA256 : <code>{}</code>\n"
                    "Raison : {}\nRestauration : <code>python start.py restore {}</code>".format(
                        path, sha256[:32], reason, entry_id))
        return {"action": "quarantine", "path": str(path), "success": True,
                "id": entry_id, "hash": match["matched_hash"], "reason": reason}

    def _delete(self, match, reason) -> dict:
        path = match["path"]
        try:
            path.unlink()
        except OSError as exc:
            self._error("Suppression impossible pour %s : %s", path, exc)
            return {"action": "delete", "path": str(path), "success": False,
                    "error": str(exc), "hash": match["matched_hash"]}

        self._warn("SUPPRESSION DÉFINITIVE : %s", path)
        self.notify("🗑 <b>Fichier malveillant supprimé</b>\n"
                    "Chemin : <code>{}</code>\nSHA256 : <code>{}</code>\n"
                    "Raison : {}\n<i>Action irréversible</i>".format(
                        path, match["hashes"]["sha256"][:32], reason))
        return {"action": "delete", "path": str(path), "success": True,
                "hash": match["matched_hash"], "reason": reason}

    # ── restauration ─────────────────────────────────────────────
    def restore(self, entry_id: str) -> dict:
        entries = self.load_manifest()
        for entry in entries:
            if entry.get("id") != entry_id:
                continue
            if entry.get("restored"):
                return {"success": False, "error": "déjà restauré"}
            source = Path(entry["quarantined"])
            target = Path(entry["original_path"])
            if not source.exists():
                return {"success": False, "error": "fichier de quarantaine introuvable"}
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(target))
            except (OSError, shutil.Error) as exc:
                return {"success": False, "error": str(exc)}
            entry["restored"]    = True
            entry["restored_at"] = utcnow_iso()
            self._save_manifest(entries)
            self._info("Fichier restauré : %s", target)
            return {"success": True, "path": str(target)}
        return {"success": False, "error": "identifiant inconnu"}

    def purge(self, entry_id: str) -> dict:
        """Supprime définitivement un élément mis en quarantaine."""
        entries = self.load_manifest()
        for entry in entries:
            if entry.get("id") != entry_id:
                continue
            source = Path(entry["quarantined"])
            if source.exists():
                try:
                    source.unlink()
                except OSError as exc:
                    return {"success": False, "error": str(exc)}
            entry["purged"]    = True
            entry["purged_at"] = utcnow_iso()
            self._save_manifest(entries)
            return {"success": True}
        return {"success": False, "error": "identifiant inconnu"}

    # ── rendu ────────────────────────────────────────────────────
    def summary_md(self, actions) -> str:
        if not actions:
            return ""
        labels = {"report": "🔎 Signalé", "quarantine": "🔒 Mis en quarantaine",
                  "delete": "🗑 Supprimé"}
        lines = ["### 📁 Réponse sur fichiers", "",
                 "| Fichier | Action | Résultat |", "|---------|--------|----------|"]
        for action in actions:
            lines.append("| `{}` | {} | {} |".format(
                action.get("path", "?"),
                labels.get(action.get("action"), action.get("action")),
                "✅ OK" if action.get("success") else
                "❌ {}".format(action.get("error", "échec"))))
        restorable = [a for a in actions if a.get("action") == "quarantine"
                      and a.get("success")]
        if restorable:
            lines += ["", "Restauration en cas de faux positif :", "```"]
            lines += ["python start.py restore {}".format(a["id"]) for a in restorable]
            lines.append("```")
        return "\n".join(lines)

    def print_status(self) -> None:
        info = self.status()
        print("\n=== Réponse sur fichiers malveillants ===")
        print("Activée          :", "✅ oui" if info["enabled"] else "❌ non "
              "(FILE_RESPONSE_ENABLED=false)")
        print("Mode             :", info["mode"])
        print("Opérationnelle   :", "✅ oui" if info["ready"] else
              "❌ non (aucun dossier valide dans FILE_SCAN_PATHS)")
        print("Dossiers surveillés :")
        for path in info["scan_paths"] or ["  (aucun)"]:
            print("   ", path)
        for path, why in info["rejected"]:
            print("    [REFUSÉ] {} — {}".format(path, why))
        print("Coffre quarantaine :", info["quarantine"])
        print("Éléments en quarantaine :", info["quarantined"])

    def print_quarantine(self) -> None:
        entries = self.load_manifest()
        if not entries:
            print("Aucun fichier en quarantaine.")
            return
        print("\nFichiers en quarantaine ({}) :".format(len(entries)))
        for entry in entries:
            state = ("restauré" if entry.get("restored")
                     else "purgé" if entry.get("purged") else "en quarantaine")
            print("  {}  [{}]".format(entry["id"], state))
            print("      origine : {}".format(entry["original_path"]))
            print("      sha256  : {}".format(entry["hashes"]["sha256"]))
            print("      raison  : {}  ({})".format(
                entry.get("reason", "?"), entry.get("date", "?")[:19]))


# ══════════════════════════════════════════════════════════════════
# TEST MANUEL — python src/file_responder.py <dossier> <hash>
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage : python src/file_responder.py <dossier> <hash> [mode]")
        print("Modes : report (défaut), quarantine, delete")
        sys.exit(2)
    responder = FileResponder(
        enabled=True,
        mode=sys.argv[3] if len(sys.argv) > 3 else "report",
        scan_paths=[sys.argv[1]])
    responder.print_status()
    print("\nRecherche de {} — {}".format(sys.argv[2], now_str()))
    for action in responder.respond([sys.argv[2]], reason="test manuel"):
        print("  ", action)
