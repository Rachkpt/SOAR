#!/usr/bin/env python3
"""
Tests unitaires — réponse sur fichiers malveillants

Lancement :
    python tests/test_file_responder.py

Ces tests créent de vrais fichiers dans tests/.tmp/ et vérifient que la
quarantaine, la restauration et la suppression fonctionnent — ainsi que,
surtout, que les garde-fous empêchent de toucher aux répertoires système.
"""

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import TMP_DIR, Runner, bootstrap             # noqa: E402

bootstrap()

from file_responder import (                               # noqa: E402
    FileResponder, file_hashes, is_protected, normalize_hash,
)

r = Runner("Tests unitaires — réponse sur fichiers")

WORK  = TMP_DIR / "fichiers"
VAULT = TMP_DIR / "coffre"
WORK.mkdir(parents=True, exist_ok=True)

EICAR_LIKE = b"contenu-de-test-simulant-un-fichier-malveillant"
BAD_MD5    = hashlib.md5(EICAR_LIKE).hexdigest()
BAD_SHA256 = hashlib.sha256(EICAR_LIKE).hexdigest()
GOOD       = b"un fichier parfaitement legitime"


def make(name: str, content: bytes = EICAR_LIKE) -> Path:
    path = WORK / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def responder(mode="report", paths=None, **kwargs) -> FileResponder:
    return FileResponder(enabled=True, mode=mode,
                         scan_paths=paths if paths is not None else [str(WORK)],
                         quarantine_dir=str(VAULT), **kwargs)


# ══════════════════════════════════════════════════════════════════
# Hashes
# ══════════════════════════════════════════════════════════════════
r.section("Normalisation et calcul des hashes")


def t_normalize():
    assert normalize_hash("D41D8CD98F00B204E9800998ECF8427E") == \
        "d41d8cd98f00b204e9800998ecf8427e"
    assert normalize_hash("  " + "a" * 40 + " ") == "a" * 40
    assert normalize_hash("c" * 64) == "c" * 64


def t_normalize_rejects():
    for bad in ("", None, "pas-un-hash", "z" * 32, "a" * 31, "a" * 33, 12345):
        assert normalize_hash(bad) == "", repr(bad)


def t_file_hashes():
    path = make("echantillon.bin")
    digests = file_hashes(path, 10 * 1024 * 1024)
    assert digests["md5"] == BAD_MD5
    assert digests["sha256"] == BAD_SHA256
    assert digests["sha1"] == hashlib.sha1(EICAR_LIKE).hexdigest()


def t_file_hashes_size_limit():
    path = make("gros.bin", b"x" * 5000)
    assert file_hashes(path, 1000) == {}, "au-delà de la limite le fichier est ignoré"


r.check("normalize_hash — MD5/SHA1/SHA256", t_normalize)
r.check("normalize_hash — rejette tout le reste", t_normalize_rejects)
r.check("file_hashes — les 3 algorithmes en une lecture", t_file_hashes)
r.check("file_hashes — limite de taille respectée", t_file_hashes_size_limit)


# ══════════════════════════════════════════════════════════════════
# Garde-fous
# ══════════════════════════════════════════════════════════════════
r.section("Garde-fous — répertoires système")


def t_protected_system_dirs():
    if os.name == "nt":
        candidates = [r"C:\Windows", r"C:\Windows\System32",
                      r"C:\Program Files", "C:\\", "C:"]
    else:
        candidates = ["/", "/etc", "/usr", "/usr/bin", "/bin", "/boot", "/dev"]
    for candidate in candidates:
        assert is_protected(Path(candidate)), candidate


def t_not_protected_workdir():
    assert not is_protected(WORK)


def t_scan_paths_rejects_system():
    system = r"C:\Windows" if os.name == "nt" else "/etc"
    fr = responder(paths=[system])
    assert fr.scan_paths == [], "un répertoire système ne doit jamais être accepté"
    assert fr.rejected_paths and "protégé" in fr.rejected_paths[0][1]
    assert fr.ready is False


def t_scan_paths_rejects_missing():
    fr = responder(paths=[str(TMP_DIR / "nexiste-pas")])
    assert fr.scan_paths == [] and fr.rejected_paths


def t_scan_paths_rejects_file():
    target = make("pas-un-dossier.txt", GOOD)
    fr = responder(paths=[str(target)])
    assert fr.scan_paths == [] and fr.rejected_paths


def t_disabled_by_default():
    fr = FileResponder()
    assert fr.enabled is False and fr.ready is False
    assert fr.respond([BAD_MD5]) == []


def t_enabled_without_paths_does_nothing():
    fr = FileResponder(enabled=True, mode="delete", scan_paths=[],
                       quarantine_dir=str(VAULT))
    assert fr.ready is False
    assert fr.respond([BAD_MD5]) == [], "sans dossier configuré, aucune action"


def t_invalid_mode_falls_back():
    fr = responder(mode="formatage-du-disque")
    assert fr.mode == "report", "un mode inconnu doit retomber sur le plus sûr"


r.check("répertoires système reconnus comme protégés", t_protected_system_dirs)
r.check("dossier de travail non protégé", t_not_protected_workdir)
r.check("FILE_SCAN_PATHS refuse les répertoires système", t_scan_paths_rejects_system)
r.check("FILE_SCAN_PATHS refuse un chemin inexistant", t_scan_paths_rejects_missing)
r.check("FILE_SCAN_PATHS refuse un fichier", t_scan_paths_rejects_file)
r.check("désactivé par défaut → aucune action", t_disabled_by_default)
r.check("activé sans dossier → aucune action", t_enabled_without_paths_does_nothing)
r.check("mode inconnu → repli sur « report »", t_invalid_mode_falls_back)


# ══════════════════════════════════════════════════════════════════
# Recherche
# ══════════════════════════════════════════════════════════════════
r.section("Recherche par hash")


def t_find_by_md5():
    target = make("trouve-moi.exe")
    matches = responder().find_by_hashes([BAD_MD5])
    assert any(m["path"] == target for m in matches), [str(m["path"]) for m in matches]


def t_find_by_sha256():
    make("trouve-moi-aussi.dll")
    assert responder().find_by_hashes([BAD_SHA256])


def t_find_in_subdirectory():
    target = make("profond/plus/profond/cache.bin")
    matches = responder().find_by_hashes([BAD_SHA256])
    assert any(m["path"] == target for m in matches)


def t_find_ignores_clean_files():
    make("propre.txt", GOOD)
    matches = responder().find_by_hashes([BAD_MD5])
    assert all(m["path"].name != "propre.txt" for m in matches)


def t_find_unknown_hash():
    assert responder().find_by_hashes(["f" * 64]) == []


def t_find_ignores_invalid_hashes():
    assert responder().find_by_hashes(["pas-un-hash", "", None]) == []


def t_find_respects_size_limit():
    make("volumineux.bin", EICAR_LIKE)
    fr = responder(max_size_mb=1)
    fr.max_size = 10          # 10 octets : notre échantillon est plus gros
    assert fr.find_by_hashes([BAD_MD5]) == []


r.check("recherche par MD5", t_find_by_md5)
r.check("recherche par SHA256", t_find_by_sha256)
r.check("recherche récursive dans les sous-dossiers", t_find_in_subdirectory)
r.check("les fichiers sains sont ignorés", t_find_ignores_clean_files)
r.check("hash inconnu → aucun résultat", t_find_unknown_hash)
r.check("hashes invalides ignorés", t_find_ignores_invalid_hashes)
r.check("fichiers trop gros ignorés", t_find_respects_size_limit)


# ══════════════════════════════════════════════════════════════════
# Mode report
# ══════════════════════════════════════════════════════════════════
r.section("Mode report")


def t_report_keeps_file():
    target = make("report-moi.exe")
    actions = responder(mode="report").respond([BAD_MD5])
    assert actions and all(a["action"] == "report" for a in actions)
    assert target.exists(), "le mode report ne doit RIEN supprimer"


r.check("le fichier reste intact", t_report_keeps_file)


# ══════════════════════════════════════════════════════════════════
# Quarantaine
# ══════════════════════════════════════════════════════════════════
r.section("Quarantaine et restauration")


def t_quarantine_moves_file():
    target = make("a-mettre-au-coffre.exe")
    fr = responder(mode="quarantine")
    actions = [a for a in fr.respond([BAD_MD5]) if a["path"] == str(target)]
    assert actions and actions[0]["success"] is True, actions
    assert not target.exists(), "le fichier doit avoir quitté son emplacement"
    entry = next(e for e in fr.load_manifest() if e["id"] == actions[0]["id"])
    assert Path(entry["quarantined"]).exists(), "il doit être dans le coffre"


def t_quarantine_manifest_content():
    target = make("manifeste.exe")
    fr = responder(mode="quarantine")
    action = next(a for a in fr.respond([BAD_SHA256]) if a["path"] == str(target))
    entry  = next(e for e in fr.load_manifest() if e["id"] == action["id"])
    assert entry["original_path"] == str(target)
    assert entry["hashes"]["sha256"] == BAD_SHA256
    assert entry["restored"] is False and entry["reason"]


def t_restore_puts_file_back():
    target = make("a-restaurer.exe")
    fr = responder(mode="quarantine")
    action = next(a for a in fr.respond([BAD_MD5]) if a["path"] == str(target))
    assert not target.exists()
    result = fr.restore(action["id"])
    assert result["success"] is True, result
    assert target.exists(), "le fichier doit être revenu à sa place"
    assert target.read_bytes() == EICAR_LIKE, "le contenu doit être identique"


def t_restore_twice_refused():
    target = make("double-restauration.exe")
    fr = responder(mode="quarantine")
    action = next(a for a in fr.respond([BAD_MD5]) if a["path"] == str(target))
    fr.restore(action["id"])
    assert fr.restore(action["id"])["success"] is False


def t_restore_unknown_id():
    assert responder().restore("identifiant-bidon")["success"] is False


def t_purge_removes_from_vault():
    target = make("a-purger.exe")
    fr = responder(mode="quarantine")
    action = next(a for a in fr.respond([BAD_MD5]) if a["path"] == str(target))
    entry  = next(e for e in fr.load_manifest() if e["id"] == action["id"])
    assert fr.purge(action["id"])["success"] is True
    assert not Path(entry["quarantined"]).exists()


def t_quarantine_not_rescanned():
    # Le coffre ne doit pas être ré-analysé, sinon on remettrait en
    # quarantaine un fichier déjà mis en quarantaine.
    make("boucle.exe")
    fr = responder(mode="quarantine", paths=[str(WORK), str(VAULT)])
    fr.respond([BAD_MD5])
    before = len(fr.load_manifest())
    fr.respond([BAD_MD5])
    assert len(fr.load_manifest()) == before, "le coffre a été ré-analysé"


r.check("le fichier est déplacé dans le coffre", t_quarantine_moves_file)
r.check("le manifeste conserve l'origine et les hashes", t_quarantine_manifest_content)
r.check("restauration : le fichier revient intact", t_restore_puts_file_back)
r.check("double restauration refusée", t_restore_twice_refused)
r.check("restauration d'un id inconnu refusée", t_restore_unknown_id)
r.check("purge : suppression définitive depuis le coffre", t_purge_removes_from_vault)
r.check("le coffre n'est jamais ré-analysé", t_quarantine_not_rescanned)


# ══════════════════════════════════════════════════════════════════
# Suppression
# ══════════════════════════════════════════════════════════════════
r.section("Mode delete")


def t_delete_removes_file():
    target = make("a-supprimer.exe")
    actions = [a for a in responder(mode="delete").respond([BAD_MD5])
               if a["path"] == str(target)]
    assert actions and actions[0]["success"] is True
    assert not target.exists(), "le fichier doit être supprimé"


def t_delete_spares_clean_files():
    good = make("innocent.txt", GOOD)
    make("coupable.exe")
    responder(mode="delete").respond([BAD_MD5])
    assert good.exists(), "un fichier sain ne doit JAMAIS être supprimé"


r.check("le fichier malveillant est supprimé", t_delete_removes_file)
r.check("les fichiers sains sont épargnés", t_delete_spares_clean_files)


# ══════════════════════════════════════════════════════════════════
# Rendu et état
# ══════════════════════════════════════════════════════════════════
r.section("Rendu et état")


def t_summary_md():
    make("resume.exe")
    fr = responder(mode="quarantine")
    markdown = fr.summary_md(fr.respond([BAD_MD5]))
    assert "Réponse sur fichiers" in markdown
    assert "quarantaine" in markdown.lower()
    assert "python start.py restore" in markdown


def t_summary_md_empty():
    assert responder().summary_md([]) == ""


def t_status():
    info = responder(mode="quarantine").status()
    assert info["enabled"] is True and info["ready"] is True
    assert info["mode"] == "quarantine"
    assert str(WORK) in info["scan_paths"]


def t_manifest_corrupted():
    VAULT.mkdir(parents=True, exist_ok=True)
    (VAULT / "manifest.json").write_text("{ pas du json", encoding="utf-8")
    assert responder().load_manifest() == [], "un manifeste corrompu ne doit pas planter"


r.check("summary_md contient la commande de restauration", t_summary_md)
r.check("summary_md vide si aucune action", t_summary_md_empty)
r.check("status expose la configuration", t_status)
r.check("manifeste corrompu → liste vide sans exception", t_manifest_corrupted)


if __name__ == "__main__":
    sys.exit(r.report())
