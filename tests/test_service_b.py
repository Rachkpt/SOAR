#!/usr/bin/env python3
"""
Tests unitaires — Service B (responder TheHive + Cortex + MISP + blocage)

Lancement :
    python tests/test_service_b.py

Aucun accès réseau, aucune règle firewall posée : ACTIVE_RESPONSE=false
et CORTEX_ENABLED=false dans le harnais de test.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Runner, bootstrap                      # noqa: E402

bootstrap()

import service_b_thehive_responder as svc                  # noqa: E402

cfg = svc.cfg
r   = Runner("Tests unitaires — Service B v{}".format(svc.VERSION))


# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════
r.section("Configuration")


def t_cfg_paths_absolute():
    assert cfg.STATE_FILE.is_absolute()
    assert cfg.BLACKLIST_FILE.is_absolute()
    assert cfg.BLACKLIST_JSON.is_absolute()


def t_cfg_safe_defaults():
    assert cfg.ACTIVE_RESPONSE is False, "la simulation doit être le défaut en test"
    assert cfg.vt_ready is False
    assert cfg.misp_ready is False


r.check("chemins d'état absolus", t_cfg_paths_absolute)
r.check("valeurs par défaut sûres", t_cfg_safe_defaults)


# ══════════════════════════════════════════════════════════════════
# Utilitaires réseau
# ══════════════════════════════════════════════════════════════════
r.section("Utilitaires")


def t_is_internal():
    for private in ("10.0.0.1", "192.168.1.10", "172.16.5.5", "127.0.0.1", "169.254.1.1"):
        assert svc.is_internal(private), private
    for public in ("8.8.8.8", "185.220.101.50"):
        assert not svc.is_internal(public), public
    assert not svc.is_internal("pas-une-ip")


def t_is_valid_ip():
    assert svc.is_valid_ip("1.2.3.4") and svc.is_valid_ip("::1")
    assert not svc.is_valid_ip("999.1.1.1") and not svc.is_valid_ip("")


r.check("is_internal — privées vs publiques", t_is_internal)
r.check("is_valid_ip", t_is_valid_ip)


# ══════════════════════════════════════════════════════════════════
# Extraction des IoCs
# ══════════════════════════════════════════════════════════════════
r.section("Extraction des IoCs")

OBSERVABLES = [
    {"dataType": "ip", "data": "185.220.101.50"},
    {"dataType": "ip", "data": "10.0.0.5"},
    {"dataType": "hash", "data": "d41d8cd98f00b204e9800998ecf8427e"},
    {"dataType": "domain", "data": "evil.com"},
    {"dataType": "other", "data": "root"},
]


def t_extract_ips():
    ips = svc.extract_ips({}, OBSERVABLES)
    assert ips == ["185.220.101.50", "10.0.0.5"]


def t_extract_ips_from_description():
    ips = svc.extract_ips({"description": "connexion depuis 1.2.3.4 vers 5.6.7.8"}, [])
    assert ips == ["1.2.3.4", "5.6.7.8"]


def t_extract_ips_rejects_garbage():
    # Régression : 999.1.1.1 passait le filtre regex de l'ancienne version
    assert svc.extract_ips({"description": "faux 999.1.1.1 vrai 8.8.8.8"}, []) == ["8.8.8.8"]


def t_extract_ips_dedupe():
    doubles = OBSERVABLES + [{"dataType": "ip", "data": "185.220.101.50"}]
    assert svc.extract_ips({}, doubles).count("185.220.101.50") == 1


def t_extract_hashes():
    assert svc.extract_hashes({}, OBSERVABLES) == ["d41d8cd98f00b204e9800998ecf8427e"]


def t_extract_hashes_lengths():
    description = "md5 {} sha1 {} sha256 {} bruit {}".format(
        "a" * 32, "b" * 40, "c" * 64, "d" * 12)
    found = svc.extract_hashes({"description": description}, [])
    assert found == ["c" * 64, "b" * 40, "a" * 32] or set(found) == {"a" * 32, "b" * 40, "c" * 64}
    assert "d" * 12 not in found


def t_extract_domains():
    assert svc.extract_domains({}, OBSERVABLES) == ["evil.com"]


def t_extract_handles_junk():
    assert svc.extract_ips({}, [None, "texte", {"dataType": "ip"}]) == []


r.check("extract_ips depuis les observables", t_extract_ips)
r.check("extract_ips depuis la description", t_extract_ips_from_description)
r.check("extract_ips rejette les fausses IP", t_extract_ips_rejects_garbage)
r.check("extract_ips déduplique", t_extract_ips_dedupe)
r.check("extract_hashes depuis les observables", t_extract_hashes)
r.check("extract_hashes — longueurs 32/40/64 uniquement", t_extract_hashes_lengths)
r.check("extract_domains", t_extract_domains)
r.check("observables malformés tolérés", t_extract_handles_junk)


# ══════════════════════════════════════════════════════════════════
# VirusTotal
# ══════════════════════════════════════════════════════════════════
r.section("VirusTotal")


def t_vt_disabled():
    assert svc.VT.check("ip", "8.8.8.8") == {}
    assert svc.VT.check("type-inconnu", "x") == {}


def t_vt_is_malicious():
    assert svc.VT.is_malicious({"malicious": 5, "total": 70})
    assert svc.VT.is_malicious({"reputation": -30})
    assert not svc.VT.is_malicious({"malicious": 1, "total": 70, "reputation": 0})
    assert not svc.VT.is_malicious({})


def t_vt_verdict():
    assert "MALVEILLANT" in svc.VT.verdict({"malicious": 9, "total": 70})
    assert "Suspect" in svc.VT.verdict({"malicious": 0, "suspicious": 1, "total": 70})
    assert "Propre" in svc.VT.verdict({"malicious": 0, "suspicious": 0, "total": 70})
    assert "Non indexé" in svc.VT.verdict({})


def t_vt_summary_md():
    md = svc.VT.summary_md({"malicious": 9, "total": 70, "country": "RU"}, "1.2.3.4")
    assert "VirusTotal" in md and "1.2.3.4" in md and "RU" in md
    assert "non indexé" in svc.VT.summary_md({}, "1.2.3.4")


r.check("désactivé → {}", t_vt_disabled)
r.check("is_malicious — seuils", t_vt_is_malicious)
r.check("verdict — quatre états", t_vt_verdict)
r.check("summary_md", t_vt_summary_md)


# ══════════════════════════════════════════════════════════════════
# Cortex
# ══════════════════════════════════════════════════════════════════
r.section("Cortex")


def t_job_report_taxonomies():
    parsed = svc._parse_job_report({"report": {"summary": {"taxonomies": [
        {"namespace": "AbuseIPDB", "predicate": "Records", "value": "12", "level": "suspicious"},
        {"namespace": "VT", "predicate": "GetReport", "value": "9/70", "level": "malicious"},
    ]}}})
    assert parsed["level"] == "malicious"
    assert "AbuseIPDB/Records=12" in parsed["verdicts"]


def t_job_report_string():
    # TheHive renvoie parfois le rapport sous forme de chaîne JSON
    parsed = svc._parse_job_report(
        {"report": '{"summary": {"taxonomies": [{"level": "safe", '
                   '"namespace": "N", "predicate": "P", "value": "V"}]}}'})
    assert parsed["level"] == "safe" and parsed["verdicts"] == ["N/P=V"]


def t_job_report_empty():
    parsed = svc._parse_job_report({})
    assert parsed["level"] == "info" and parsed["verdicts"] == []


def t_job_report_broken():
    assert svc._parse_job_report({"report": "pas du json"})["level"] == "info"


def t_level_order():
    assert svc.LEVEL_ORDER["malicious"] > svc.LEVEL_ORDER["suspicious"]
    assert svc.LEVEL_ORDER["suspicious"] > svc.LEVEL_ORDER["safe"]
    assert set(svc.LEVEL_EMOJI) == set(svc.LEVEL_ORDER)


def t_registry_priority():
    registry = svc.CortexRegistry.__new__(svc.CortexRegistry)   # sans appel réseau
    registry.by_type = {"ip": [("Zzz_Other", "id1", "local"),
                              ("MaxMind_GeoIP_4_0", "id2", "local"),
                              ("AbuseIPDB_1_0", "id3", "local")]}
    registry.analyzers = {}
    ordered = [name for name, _, _ in registry.get_for("ip")]
    assert ordered[0] == "AbuseIPDB_1_0", ordered
    assert ordered[1] == "MaxMind_GeoIP_4_0", ordered


def t_registry_limit():
    registry = svc.CortexRegistry.__new__(svc.CortexRegistry)
    registry.by_type = {"ip": [("A{}".format(i), str(i), "") for i in range(20)]}
    registry.analyzers = {}
    assert len(registry.get_for("ip")) == cfg.CORTEX_MAX_ANALYZERS


r.check("_parse_job_report — niveau le plus grave retenu", t_job_report_taxonomies)
r.check("_parse_job_report — rapport en chaîne JSON", t_job_report_string)
r.check("_parse_job_report — rapport vide", t_job_report_empty)
r.check("_parse_job_report — JSON invalide", t_job_report_broken)
r.check("ordre des niveaux cohérent", t_level_order)
r.check("registre — tri par priorité", t_registry_priority)
r.check("registre — nombre d'analyseurs plafonné", t_registry_limit)


# ══════════════════════════════════════════════════════════════════
# Firewall & blacklist
# ══════════════════════════════════════════════════════════════════
r.section("Firewall et blacklist")


def t_rule_name():
    assert svc.Firewall._rule_name("1.2.3.4", "IN") == "SOC_BLOCK_1_2_3_4_IN"
    assert ":" not in svc.Firewall._rule_name("fe80::1", "OUT")


def t_block_is_simulation():
    result = svc.blacklist.block("203.0.113.10", "test unitaire")
    assert result.get("dry_run") is True and result.get("success") is False
    assert not svc.blacklist.is_blocked("203.0.113.10"), \
        "aucune IP ne doit être marquée bloquée en simulation"


def t_unblock_unknown():
    assert svc.blacklist.unblock("203.0.113.99") is False


def t_list_blocked_shape():
    assert isinstance(svc.blacklist.list_blocked(), list)


def t_blacklist_manual_entry():
    # On simule une entrée déjà bloquée pour valider list_blocked / info
    now = datetime.now()
    svc.blacklist._blocked["198.51.100.7"] = {
        "blocked_at": now, "reason": "test", "timer": None}
    try:
        entries = {entry["ip"]: entry for entry in svc.blacklist.list_blocked()}
        assert "198.51.100.7" in entries
        assert entries["198.51.100.7"]["remaining_min"] <= cfg.BLOCK_DURATION_MIN
        assert svc.blacklist.is_blocked("198.51.100.7")
        assert svc.blacklist.info("198.51.100.7")["reason"] == "test"
        expected = (now + timedelta(minutes=cfg.BLOCK_DURATION_MIN)).strftime("%H:%M:%S")
        assert entries["198.51.100.7"]["expires_at"] == expected
    finally:
        svc.blacklist._blocked.pop("198.51.100.7", None)


def t_block_already_blocked():
    svc.blacklist._blocked["198.51.100.8"] = {
        "blocked_at": datetime.now(), "reason": "test", "timer": None}
    try:
        assert svc.blacklist.block("198.51.100.8").get("already_blocked") is True
    finally:
        svc.blacklist._blocked.pop("198.51.100.8", None)


r.check("nom de règle firewall normalisé", t_rule_name)


# ══════════════════════════════════════════════════════════════════
# Détection des menaces et décision de blocage
# ══════════════════════════════════════════════════════════════════
r.section("Détection des menaces")


def t_threat_bruteforce():
    threats = svc.detect_threats("SSH Brute Force detected", ["splunk", "brute_force"])
    assert "brute_force" in threats


def t_threat_portscan_from_suricata():
    # Message typique de la règle Suricata fournie dans suricata/soc-custom.rules
    threats = svc.detect_threats("POSSBL PORT SCAN (NMAP -sS)", ["splunk"])
    assert "port_scan" in threats


def t_threat_metasploit():
    threats = svc.detect_threats("POSSBL SCAN SHELL M-SPLOIT TCP", ["trojan-activity"])
    assert "exploitation" in threats


def t_threat_from_description():
    threats = svc.detect_threats("Alerte", [], "mimikatz a accédé à lsass")
    assert "credential_dumping" in threats


def t_threat_none():
    assert svc.detect_threats("Rapport hebdomadaire", ["splunk"]) == []


def t_block_reasons_portscan():
    reasons = svc.AlertProcessor._block_reasons("1.2.3.4", ["port_scan"], {}, [])
    assert any("scan" in reason for reason in reasons)


def t_block_reasons_vt():
    vt = {"1.2.3.4": {"malicious": 9, "total": 70}}
    reasons = svc.AlertProcessor._block_reasons("1.2.3.4", [], vt, [])
    assert any("VirusTotal" in reason for reason in reasons)


def t_block_reasons_misp():
    assert svc.AlertProcessor._block_reasons("1.2.3.4", [], {}, ["1.2.3.4"]) == ["MISP hit"]


def t_block_reasons_clean():
    assert svc.AlertProcessor._block_reasons("1.2.3.4", [], {}, []) == []


def t_block_reasons_cumulative():
    vt = {"1.2.3.4": {"malicious": 9, "total": 70}}
    reasons = svc.AlertProcessor._block_reasons("1.2.3.4", ["brute_force", "port_scan"], vt, ["1.2.3.4"])
    assert len(reasons) >= 4


r.check("brute force détecté", t_threat_bruteforce)
r.check("scan de ports Suricata/NMAP détecté", t_threat_portscan_from_suricata)
r.check("shell Metasploit détecté", t_threat_metasploit)
r.check("menace détectée depuis la description", t_threat_from_description)
r.check("alerte anodine → aucune menace", t_threat_none)
r.check("raison de blocage — scan de ports", t_block_reasons_portscan)
r.check("raison de blocage — VirusTotal", t_block_reasons_vt)
r.check("raison de blocage — MISP", t_block_reasons_misp)
r.check("aucune raison → pas de blocage", t_block_reasons_clean)
r.check("raisons cumulées", t_block_reasons_cumulative)
r.check("ACTIVE_RESPONSE=false → simulation, aucune règle posée", t_block_is_simulation)
r.check("unblock d'une IP inconnue → False", t_unblock_unknown)
r.check("list_blocked renvoie une liste", t_list_blocked_shape)
r.check("list_blocked / info sur une entrée", t_blacklist_manual_entry)
r.check("blocage d'une IP déjà bloquée", t_block_already_blocked)


# ══════════════════════════════════════════════════════════════════
# État
# ══════════════════════════════════════════════════════════════════
r.section("StateManager")


def t_state_roundtrip():
    state = svc.StateManager()
    assert state.is_done("alerte-x") is False
    state.mark_done("alerte-x")
    assert state.is_done("alerte-x") is True
    # relecture depuis le disque
    assert svc.StateManager().is_done("alerte-x") is True


def t_state_unmark():
    state = svc.StateManager()
    state.mark_done("alerte-y")
    state.unmark("alerte-y")
    assert state.is_done("alerte-y") is False


def t_state_idempotent():
    state = svc.StateManager()
    state.mark_done("alerte-z")
    state.mark_done("alerte-z")
    bucket = state._data["processed_alerts"]
    assert bucket.count("alerte-z") == 1


def t_state_corrupted_file():
    cfg.STATE_FILE.write_text("{ ceci n'est pas du json", encoding="utf-8")
    state = svc.StateManager()
    assert state.is_done("quoi que ce soit") is False
    state.mark_done("apres-corruption")
    assert svc.StateManager().is_done("apres-corruption") is True


r.check("mark_done / is_done persistés", t_state_roundtrip)
r.check("unmark", t_state_unmark)
r.check("mark_done idempotent", t_state_idempotent)
r.check("fichier d'état corrompu → repart proprement", t_state_corrupted_file)


# ══════════════════════════════════════════════════════════════════
# MISP
# ══════════════════════════════════════════════════════════════════
r.section("MISP")


def t_misp_disabled():
    assert svc.MISP.lookup("1.2.3.4", "ip") is False
    assert svc.MISP.push("1.2.3.4", "ip") is False
    assert svc.MISP._request("/attributes/restSearch", {}) is None


def t_misp_type_map():
    assert svc.MISP.TYPE_MAP["ip"] == "ip-dst"
    assert svc.MISP.TYPE_MAP["hash"] == "md5"
    assert svc.MISP.TYPE_MAP.get("inconnu", "text") == "text"


r.check("désactivé → aucune requête", t_misp_disabled)
r.check("correspondance des types MISP", t_misp_type_map)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
r.section("CLI")


def t_cli_unblock_invalid_ip():
    assert svc.cli_unblock("pas-une-ip") == 2


def t_cli_list():
    assert svc.cli_list() == 0


def t_cli_bad_command():
    assert svc.main(["commande-inexistante"]) == 2


r.check("unblock avec une IP invalide → code 2", t_cli_unblock_invalid_ip)
r.check("list → code 0", t_cli_list)
r.check("commande inconnue → code 2", t_cli_bad_command)


if __name__ == "__main__":
    sys.exit(r.report())
