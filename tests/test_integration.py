#!/usr/bin/env python3
"""
Test d'integration bout en bout — sans TheHive reel.

    python tests/test_integration.py
    python start.py e2e

Demarre un faux serveur TheHive 5 (tests/stub_thehive.py), lance le vrai
Service A, lui envoie une alerte Splunk, puis fait tourner un cycle du vrai
Service B. Verifie ensuite dans le stub que toute la chaine a bien eu lieu :

    alerte -> cas -> observables -> analyseurs Cortex lances -> verdicts
          -> commentaires -> tags -> quarantaine du fichier malveillant

Aucune connexion Internet requise, aucune regle pare-feu posee, aucun
fichier touche en dehors de tests/.tmp-e2e/.
"""
import json, os, subprocess, sys, time, urllib.request
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT      = TESTS_DIR.parent
SCRATCH   = TESTS_DIR / ".tmp-e2e"
SCRATCH.mkdir(parents=True, exist_ok=True)
STUB_PORT = int(os.environ.get("E2E_STUB_PORT", "9911"))
WEB_PORT  = int(os.environ.get("E2E_WEB_PORT", "5099"))

for s in (sys.stdout, sys.stderr):
    try:
        s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get(url, payload=None, timeout=20):
    data = json.dumps(payload).encode() if payload is not None else None
    hdr = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, None


env = os.environ.copy()
env.update({
    "SOC_ENV_FILE": str(SCRATCH / "integration.env"),
    "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8",
    "SOC_SKIP_DOTENV": "",
})
(SCRATCH / "integration.env").write_text(
    "\n".join([
        "THEHIVE_URL=http://127.0.0.1:{}".format(STUB_PORT),
        "THEHIVE_APIKEY=clef-integration",
        "LISTEN_HOST=127.0.0.1",
        "LISTEN_PORT={}".format(WEB_PORT),
        "VT_ENABLED=false",
        "MISP_ENABLED=false",
        "TELEGRAM_ENABLED=false",
        "GMAIL_ENABLED=false",
        "CORTEX_ENABLED=true",
        "CORTEX_JOB_TIMEOUT=30",
        "ACTIVE_RESPONSE=false",
        "RATE_LIMIT_SEC=0",
        "POLL_INTERVAL=5",
        "LOG_LEVEL=INFO",
        "LOG_FILE={}".format(SCRATCH / "a.log"),
        "LOG_FILE_B={}".format(SCRATCH / "b.log"),
        "STATE_FILE={}".format(SCRATCH / "state.json"),
        "BLACKLIST_FILE={}".format(SCRATCH / "bl.txt"),
    ]), encoding="utf-8")
for f in ("state.json", "a.log", "b.log", "ip_blacklist.json"):
    p = SCRATCH / f
    if p.exists():
        p.unlink()

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("  [OK]    " if cond else "  [ECHEC] ") + name + (
        "" if cond or not detail else "  -> " + str(detail)[:300]))


print("=" * 66)
print("  TEST D'INTEGRATION BOUT EN BOUT")
print("=" * 66)

# Faux partage reseau : un fichier "malveillant" et un fichier sain.
# Son hash sert de bout en bout : alerte Splunk -> TheHive -> reponse fichier.
import hashlib as _hl
import shutil as _sh

share = SCRATCH / "partage_integration"
vault = SCRATCH / "coffre_integration"
_sh.rmtree(share, ignore_errors=True)
_sh.rmtree(vault, ignore_errors=True)
(share / "docs").mkdir(parents=True)
bad_file = share / "docs" / "facture.exe"
bad_file.write_bytes(b"CHARGE-UTILE-SIMULEE-POUR-TEST-INTEGRATION")
clean_file = share / "docs" / "rapport.txt"
clean_file.write_bytes(b"document legitime a ne pas toucher")
bad_hash = _hl.sha256(bad_file.read_bytes()).hexdigest()

stub = subprocess.Popen([sys.executable, str(TESTS_DIR / "stub_thehive.py"), str(STUB_PORT)])
svc_a = None
try:
    for _ in range(40):
        code, _ = get("http://127.0.0.1:{}/api/v1/user/current".format(STUB_PORT))
        if code == 200:
            break
        time.sleep(0.25)
    check("stub TheHive demarre", code == 200)

    # ── Service A ────────────────────────────────────────────────
    print("\nService A - webhook")
    svc_a = subprocess.Popen(
        [sys.executable, str(ROOT / "src" / "service_a_splunk_to_thehive.py")],
        cwd=str(ROOT), env=env,
        stdout=open(SCRATCH / "a.out", "w", encoding="utf-8"), stderr=subprocess.STDOUT)
    health = None
    for _ in range(60):
        code, health = get("http://127.0.0.1:{}/health".format(WEB_PORT), timeout=5)
        if code in (200, 503):
            break
        time.sleep(0.5)
    check("GET /health repond", code == 200, health)
    check("/health voit TheHive", bool(health and health.get("thehive")), health)

    code, body = get("http://127.0.0.1:{}/alert".format(WEB_PORT), {
        "search_name": "SSH Brute Force + POSSBL PORT SCAN (NMAP -sS)",
        "severity": "high",
        "result": {
            "host": "srv-prod-01", "source": "/var/log/auth.log",
            "index": "linux_logs", "src_ip": "185.220.101.50",
            "dest_ip": "192.168.1.10", "user": "root",
            "file_hash": bad_hash,
            "domain": "malware-c2.xyz", "process_name": "sshd",
        }})
    check("POST /alert -> 201 created", code == 201 and body.get("status") == "created", body)
    check("observables extraits", (body or {}).get("artifacts_count", 0) >= 4, body)
    check("severite High", (body or {}).get("severity") == "High", body)

    code, state = get("http://127.0.0.1:{}/__state".format(STUB_PORT))
    alerts = list(state["alerts"].values())
    check("alerte creee dans TheHive", len(alerts) == 1, len(alerts))
    alert = alerts[0]
    check("titre prefixe [SPLUNK]", alert["title"].startswith("[SPLUNK]"), alert["title"])
    check("sourceRef genere", alert["sourceRef"].startswith("splunk-"), alert.get("sourceRef"))
    tags = alert.get("tags", [])
    check("tags brute_force + port_scan + linux",
          {"brute_force", "port_scan", "linux"}.issubset(set(tags)), tags)
    types = {o["dataType"] for o in alert["observables"]}
    check("observables ip/hash/domain", {"ip", "hash", "domain"}.issubset(types), types)

    code, body2 = get("http://127.0.0.1:{}/alert".format(WEB_PORT), {
        "search_name": "SSH Brute Force + POSSBL PORT SCAN (NMAP -sS)",
        "severity": "high",
        "result": {"host": "srv-prod-01", "src_ip": "185.220.101.50",
                   "_time": "fixe"}})
    check("2e alerte acceptee", code == 201, body2)

    # ── Service B ────────────────────────────────────────────────
    print("\nService B - responder")

    env.update({
        "FILE_RESPONSE_ENABLED": "true",
        "FILE_RESPONSE_MODE": "quarantine",
        "FILE_SCAN_PATHS": str(share),
        "QUARANTINE_DIR": str(vault),
    })

    runner = SCRATCH / "run_b.py"
    runner.write_text(
        "import sys, time\n"
        "sys.path.insert(0, r'{src}')\n"
        "import service_b_thehive_responder as b\n"
        "\n"
        "# VirusTotal bouchonne : le hash de test est declare malveillant,\n"
        "# ce qui doit declencher la reponse fichier par le vrai chemin de code.\n"
        "BAD = '{bad_hash}'\n"
        "def fake_check(datatype, value):\n"
        "    if datatype == 'hash' and value.lower() == BAD:\n"
        "        return {{'malicious': 58, 'suspicious': 0, 'total': 72,\n"
        "                'reputation': -80, 'type': 'hash', 'value': value,\n"
        "                'country': '', 'as_owner': '', 'file_name': 'facture.exe'}}\n"
        "    return {{}}\n"
        "b.VT.check = staticmethod(fake_check)\n"
        "b.cfg.VT_ENABLED = True\n"
        "b.cfg.VT_APIKEY = 'bouchon'\n"
        "\n"
        "b.cortex_registry.load()\n"
        "print('ANALYZERS', len(b.cortex_registry.analyzers))\n"
        "print('FILERESP', b.file_responder.ready, b.file_responder.mode)\n"
        "p = b.Poller()\n"
        "print('PROCESSED', p.run_once())\n"
        "time.sleep(14)\n".format(src=ROOT / "src", bad_hash=bad_hash),
        encoding="utf-8")
    out = subprocess.run([sys.executable, str(runner)], cwd=str(ROOT), env=env,
                         capture_output=True, text=True, timeout=180, encoding="utf-8",
                         errors="replace")
    (SCRATCH / "b.out").write_text((out.stdout or "") + (out.stderr or ""), encoding="utf-8")
    combined = (out.stdout or "") + (out.stderr or "")
    check("Service B termine sans erreur", out.returncode == 0, combined[-500:])
    check("analyseurs Cortex decouverts", "ANALYZERS 3" in combined,
          [l for l in combined.splitlines() if "ANALYZERS" in l])
    check("2 alertes traitees", "PROCESSED 2" in combined,
          [l for l in combined.splitlines() if "PROCESSED" in l])

    code, state = get("http://127.0.0.1:{}/__state".format(STUB_PORT))
    check("cas crees dans TheHive", len(state["cases"]) == 2, list(state["cases"]))
    obs = list(state["observables"].values())
    check("observables ajoutes aux cas", len(obs) >= 4, len(obs))
    obs_types = {o["dataType"] for o in obs}
    check("ip + hash + domain ajoutes au cas",
          {"ip", "hash", "domain"}.issubset(obs_types), obs_types)

    jobs = list(state["jobs"].values())
    check("jobs Cortex lances automatiquement", len(jobs) >= 3, len(jobs))
    launched = {j["analyzer"] for j in jobs}
    check("AbuseIPDB lance sur l'IP", "AbuseIPDB_1_0" in launched, launched)
    check("VirusTotal_GetReport lance", "VirusTotal_GetReport_3_1" in launched, launched)

    comments = [c["message"] for c in state["comments"]]
    check("commentaire de rapport ecrit",
          any("Rapport automatique" in m for m in comments), len(comments))
    check("commentaire Cortex ecrit",
          any("Cortex" in m for m in comments), len(comments))
    check("verdict Cortex malicious remonte",
          any("Records=42" in m for m in comments),
          [m[:120] for m in comments if "Cortex" in m])
    check("menaces listees dans le rapport",
          any("port scan" in m for m in comments),
          [m[:200] for m in comments if "Rapport" in m])
    check("simulation de blocage tracee",
          any("SIMULATION" in m for m in comments),
          [m[:200] for m in comments if "Rapport" in m])

    all_tags = set()
    for case in state["cases"].values():
        all_tags.update(case.get("tags") or [])
    check("cas tagues auto-processed", "auto-processed" in all_tags, all_tags)
    check("cas tagues port_scan", "port_scan" in all_tags, all_tags)
    check("cas tagues cortex-malicious", "cortex-malicious" in all_tags, all_tags)

    alert_patches = [p for p in state["patches"] if "/alert/" in p["path"]]
    check("alertes passees en InProgress",
          any(p["body"].get("status") == "InProgress" for p in alert_patches),
          alert_patches[:3])

    # ── Reponse sur fichiers malveillants ────────────────────────
    print("\nReponse sur fichiers malveillants")
    check("reponse fichier active dans le service",
          "FILERESP True quarantine" in combined,
          [l for l in combined.splitlines() if "FILERESP" in l])
    check("fichier malveillant retire du partage", not bad_file.exists(),
          "toujours present" if bad_file.exists() else "")
    check("fichier sain intact", clean_file.exists()
          and clean_file.read_bytes() == b"document legitime a ne pas toucher")

    manifest = vault / "manifest.json"
    check("coffre de quarantaine cree", manifest.exists(), str(vault))
    entries = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else []
    check("entree de quarantaine enregistree", len(entries) == 1, entries)
    if entries:
        entry = entries[0]
        check("origine du fichier conservee",
              entry["original_path"] == str(bad_file), entry.get("original_path"))
        check("hash SHA256 conserve",
              entry["hashes"]["sha256"] == bad_hash, entry["hashes"]["sha256"])
        check("fichier present dans le coffre",
              Path(entry["quarantined"]).exists(), entry["quarantined"])
        check("contenu du fichier preserve",
              Path(entry["quarantined"]).read_bytes()
              == b"CHARGE-UTILE-SIMULEE-POUR-TEST-INTEGRATION")

    comments = [c["message"] for c in state["comments"]]
    check("commentaire de reponse fichier dans le cas",
          any("Réponse sur fichiers" in m for m in comments),
          [m[:120] for m in comments if "fichier" in m.lower()])
    check("commande de restauration proposee",
          any("python start.py restore" in m for m in comments))
    all_tags = set()
    for case in state["cases"].values():
        all_tags.update(case.get("tags") or [])
    check("cas tague malicious-file", "malicious-file" in all_tags, all_tags)
    check("cas tague file-neutralized", "file-neutralized" in all_tags, all_tags)
    check("cas tague vt-malicious", "vt-malicious" in all_tags, all_tags)

finally:
    for proc in (svc_a, stub):
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()

print("\n" + "=" * 66)
failed = [n for n, ok, _ in results if not ok]
print("  {}/{} verifications OK".format(len(results) - len(failed), len(results)))
if failed:
    print("  ECHECS : " + ", ".join(failed))
print("=" * 66)
sys.exit(1 if failed else 0)
