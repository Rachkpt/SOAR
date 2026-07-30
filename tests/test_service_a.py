#!/usr/bin/env python3
"""
Tests unitaires — Service A (webhook Splunk → TheHive)

Lancement :
    python tests/test_service_a.py
    python start.py unit          (lance aussi le Service B et soc_common)

Aucun accès réseau : VirusTotal, Telegram et TheHive sont désactivés
ou remplacés par des bouchons.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Runner, bootstrap                      # noqa: E402

bootstrap()

import service_a_splunk_to_thehive as svc                  # noqa: E402
from soc_common import Observable                          # noqa: E402

AlertEnricher      = svc.AlertEnricher
SplunkParser       = svc.SplunkParser
VirusTotalClient   = svc.VirusTotalClient
cfg                = svc.cfg

r = Runner("Tests unitaires — Service A v{}".format(svc.VERSION))


# ══════════════════════════════════════════════════════════════════
# SplunkParser
# ══════════════════════════════════════════════════════════════════
r.section("SplunkParser — les 4 formats de payload")


def t_format_result_dict():
    name, sev, result = SplunkParser.parse(
        {"search_name": "SSH", "severity": "high", "result": {"src_ip": "1.2.3.4"}})
    assert name == "SSH" and sev == "high" and result["src_ip"] == "1.2.3.4"


def t_format_results_list():
    _, _, result = SplunkParser.parse(
        {"search_name": "T", "severity": "medium", "results": [{"src_ip": "5.6.7.8"}]})
    assert result["src_ip"] == "5.6.7.8"


def t_format_flat():
    _, _, result = SplunkParser.parse(
        {"search_name": "T", "severity": "low", "src_ip": "9.9.9.9", "host": "h"})
    assert result["src_ip"] == "9.9.9.9" and result["host"] == "h"


def t_format_json_string():
    _, _, result = SplunkParser.parse(
        {"search_name": "T", "severity": "high", "result": json.dumps({"src_ip": "1.1.1.1"})})
    assert result["src_ip"] == "1.1.1.1"


def t_format_fallback():
    _, _, result = SplunkParser.parse({"search_name": "T", "severity": "medium", "host": "myhost"})
    assert result.get("host") == "myhost"


def t_format_default_name():
    name, _, _ = SplunkParser.parse({"severity": "high", "result": {}})
    assert name == "Alerte Splunk"


def t_format_empty_payload():
    name, sev, result = SplunkParser.parse({})
    assert name == "Alerte Splunk" and sev == "medium" and "host" in result


def t_format_results_not_dict():
    # Régression : une liste de chaînes ne doit pas être prise pour un résultat
    _, _, result = SplunkParser.parse(
        {"search_name": "T", "severity": "low", "results": ["ligne brute"], "host": "h2"})
    assert result.get("host") == "h2"


r.check("format 1 — result dict", t_format_result_dict)
r.check("format 2 — results list", t_format_results_list)
r.check("format 3 — payload plat", t_format_flat)
r.check("format 4 — result JSON encodé", t_format_json_string)
r.check("repli — payload minimal", t_format_fallback)
r.check("nom par défaut si search_name absent", t_format_default_name)
r.check("payload vide n'explose pas", t_format_empty_payload)
r.check("results non-dict ignoré", t_format_results_not_dict)


# ══════════════════════════════════════════════════════════════════
# Sévérité / sourceRef
# ══════════════════════════════════════════════════════════════════
r.section("AlertEnricher — sévérité et sourceRef")


def t_severity():
    f = AlertEnricher.normalize_severity
    assert f("critical") == 4 and f("high") == 3 and f("medium") == 2
    assert f("low") == 1 and f("info") == 1 and f("CRITICAL") == 4
    assert f("banane") == 2 and f("") == 2
    assert f(4) == 4 and f("3") == 3


def t_ref_deterministic():
    result = {"src_ip": "1.2.3.4", "_time": "2026-01-01T00:00:00"}
    assert (AlertEnricher.generate_source_ref("X", result)
            == AlertEnricher.generate_source_ref("X", result))


def t_ref_format():
    ref = AlertEnricher.generate_source_ref("SSH", {"src_ip": "1.2.3.4"})
    assert ref.startswith("splunk-") and len(ref) == 23


def t_ref_unique():
    assert (AlertEnricher.generate_source_ref("A", {"src_ip": "1.1.1.1"})
            != AlertEnricher.generate_source_ref("B", {"src_ip": "2.2.2.2"}))


def t_ref_unicode():
    # Régression : un nom d'alerte accentué ne doit pas lever d'exception
    assert AlertEnricher.generate_source_ref("Détection é✓", {"host": "srv"})


r.check("normalize_severity — tous les niveaux", t_severity)
r.check("generate_source_ref — déterministe", t_ref_deterministic)
r.check("generate_source_ref — préfixe + longueur", t_ref_format)
r.check("generate_source_ref — refs distinctes", t_ref_unique)
r.check("generate_source_ref — accents et emojis", t_ref_unicode)


# ══════════════════════════════════════════════════════════════════
# Tags
# ══════════════════════════════════════════════════════════════════
r.section("AlertEnricher — tags")


def t_tags_base():
    tags = AlertEnricher.extract_tags("test", {}, {})
    assert "splunk" in tags and "auto-ingested" in tags


def t_tags_ssh_linux():
    tags = AlertEnricher.extract_tags("SSH Brute Force", {"source": "/var/log/auth.log"}, {})
    assert "brute_force" in tags and "ssh" in tags and "linux" in tags


def t_tags_windows():
    tags = AlertEnricher.extract_tags("4625", {"index": "windows_logs", "EventCode": "4625"}, {})
    assert "windows" in tags and "brute_force" in tags and "ec-4625" in tags


def t_tags_vt_malicious():
    vt = {"1.2.3.4": {"malicious": 10, "suspicious": 0, "total": 72, "reputation": -50}}
    assert "vt-malicious" in AlertEnricher.extract_tags("test", {}, vt)


def t_tags_vt_suspicious():
    vt = {"1.2.3.4": {"malicious": 0, "suspicious": 1, "total": 72, "reputation": 0}}
    assert "vt-suspicious" in AlertEnricher.extract_tags("test", {}, vt)


def t_tags_no_duplicates():
    tags = AlertEnricher.extract_tags("SSH Brute Force SSH", {}, {})
    assert len(tags) == len(set(tags))


def t_tags_non_string_source():
    # Régression : un champ `source` numérique faisait planter .lower()
    tags = AlertEnricher.extract_tags("test", {"source": 42, "index": None}, {})
    assert "splunk" in tags


r.check("tags de base", t_tags_base)
r.check("SSH brute force Linux", t_tags_ssh_linux)
r.check("EventCode Windows 4625", t_tags_windows)
r.check("tag vt-malicious", t_tags_vt_malicious)
r.check("tag vt-suspicious", t_tags_vt_suspicious)
r.check("pas de doublons", t_tags_no_duplicates)
r.check("champs non textuels tolérés", t_tags_non_string_source)


# ══════════════════════════════════════════════════════════════════
# Observables
# ══════════════════════════════════════════════════════════════════
r.section("AlertEnricher — observables")


def t_obs_all_types():
    observables = AlertEnricher.extract_observables({
        "src_ip":    "1.2.3.4",
        "user":      "root",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "domain":    "evil.com",
        "url":       "http://bad.com/payload",
    }, {})
    assert {o.dataType for o in observables} == {"ip", "other", "hash", "domain", "url"}


def t_obs_is_observable():
    observables = AlertEnricher.extract_observables({"src_ip": "1.2.3.4"}, {})
    assert isinstance(observables[0], Observable)
    payload = observables[0].to_dict()
    assert payload["dataType"] == "ip" and payload["data"] == "1.2.3.4"
    assert payload["ioc"] is True and "splunk" in payload["tags"]


def t_obs_vt_marks_ioc():
    vt = {"1.2.3.4": {"malicious": 10, "suspicious": 0, "total": 72, "reputation": -50}}
    observables = AlertEnricher.extract_observables({"src_ip": "1.2.3.4"}, vt)
    ip_obs = [o for o in observables if o.dataType == "ip"][0]
    assert ip_obs.ioc is True and "vt-malicious" in ip_obs.tags


def t_obs_skip_placeholders():
    observables = AlertEnricher.extract_observables(
        {"src_ip": "N/A", "user": "-", "domain": "", "file_hash": "none"}, {})
    assert observables == []


def t_obs_fallback_host():
    observables = AlertEnricher.extract_observables({"host": "myserver"}, {})
    assert len(observables) == 1 and observables[0].data == "myserver"


def t_obs_hash_lengths():
    assert len(AlertEnricher.extract_observables({"file_hash": "d" * 32}, {})) == 1
    assert len(AlertEnricher.extract_observables({"file_hash": "a" * 40}, {})) == 1
    assert len(AlertEnricher.extract_observables({"file_hash": "b" * 64}, {})) == 1
    assert AlertEnricher.extract_observables({"file_hash": "c" * 10}, {}) == []


def t_obs_cmdline_truncated():
    long_cmd = "powershell -enc " + "A" * 900
    observables = AlertEnricher.extract_observables({"CommandLine": long_cmd}, {})
    cmd_obs = [o for o in observables if "cmdline" in o.tags][0]
    assert len(cmd_obs.data) == 500


r.check("tous les types d'observables", t_obs_all_types)
r.check("objets Observable sérialisables", t_obs_is_observable)
r.check("IoC marqué si VT malveillant", t_obs_vt_marks_ioc)
r.check("valeurs N/A, -, none ignorées", t_obs_skip_placeholders)
r.check("repli sur host si aucun IoC", t_obs_fallback_host)
r.check("hashes MD5/SHA1/SHA256 acceptés", t_obs_hash_lengths)
r.check("ligne de commande tronquée à 500", t_obs_cmdline_truncated)


# ══════════════════════════════════════════════════════════════════
# VirusTotal
# ══════════════════════════════════════════════════════════════════
r.section("VirusTotalClient")


def t_vt_disabled():
    assert cfg.VT_ENABLED is False
    assert VirusTotalClient.check_ip("8.8.8.8") == {}
    assert VirusTotalClient.check_hash("a" * 32) == {}
    assert VirusTotalClient.check_domain("x.com") == {}
    assert VirusTotalClient.check_url("http://x") == {}
    assert VirusTotalClient.enrich_observables({"src_ip": "8.8.8.8"}) == {}


def t_vt_is_malicious():
    assert VirusTotalClient.is_malicious(
        {"malicious": 3, "suspicious": 0, "total": 70, "reputation": 0})
    assert VirusTotalClient.is_malicious(
        {"malicious": 0, "suspicious": 0, "total": 70, "reputation": -15})
    assert VirusTotalClient.is_malicious(
        {"malicious": 0, "suspicious": 4, "total": 70, "reputation": 0})
    assert not VirusTotalClient.is_malicious(
        {"malicious": 1, "suspicious": 0, "total": 70, "reputation": 0})
    assert not VirusTotalClient.is_malicious({})
    assert not VirusTotalClient.is_malicious(None)


def t_vt_format_summary():
    summary = VirusTotalClient.format_summary(
        {"malicious": 10, "suspicious": 0, "total": 72, "reputation": -20, "country": "RU"})
    assert "MALVEILLANT" in summary and "10/72" in summary and "RU" in summary
    assert "SUSPECT" in VirusTotalClient.format_summary(
        {"malicious": 0, "suspicious": 3, "total": 72, "reputation": 0})
    assert "non analysé" in VirusTotalClient.format_summary({})


def t_vt_parse_stats_empty():
    assert VirusTotalClient._parse_stats({})["total"] == 0


r.check("désactivé → {} sur tous les types", t_vt_disabled)
r.check("is_malicious — seuils et cas limites", t_vt_is_malicious)
r.check("format_summary — verdicts", t_vt_format_summary)
r.check("_parse_stats — réponse vide", t_vt_parse_stats_empty)


# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════
r.section("Fonctions utilitaires")


def t_is_ip():
    assert svc._is_ip("1.2.3.4") and svc._is_ip("::1")
    assert not svc._is_ip("evil.com") and not svc._is_ip("") and not svc._is_ip("256.0.0.1")


def t_public_ip():
    assert svc._is_valid_public_ip("8.8.8.8")
    assert svc._is_valid_public_ip("185.220.101.50")
    for private in ("10.2.3.50", "192.168.1.1", "127.0.0.1", "172.16.0.1", "169.254.1.1"):
        assert not svc._is_valid_public_ip(private), private


def t_clean():
    assert svc._clean("  1.2.3.4 ") == "1.2.3.4"
    for empty in ("N/A", "-", "none", "null", "unknown", "", None):
        assert svc._clean(empty) == "", repr(empty)


def t_rate_limit_disabled():
    # RATE_LIMIT_SEC=0 dans le harnais : jamais de blocage
    assert svc.is_rate_limited("clef-a") is False
    assert svc.is_rate_limited("clef-a") is False


def t_rate_limit_enabled():
    original = cfg.RATE_LIMIT_SEC
    cfg.RATE_LIMIT_SEC = 10
    try:
        svc._rate_cache.pop("clef-b", None)
        assert svc.is_rate_limited("clef-b") is False, "1er passage doit passer"
        assert svc.is_rate_limited("clef-b") is True, "2e passage doit être bloqué"
    finally:
        cfg.RATE_LIMIT_SEC = original
        svc._rate_cache.pop("clef-b", None)


r.check("_is_ip", t_is_ip)
r.check("_is_valid_public_ip — publiques vs privées", t_public_ip)
r.check("_clean — normalisation des valeurs vides", t_clean)
r.check("anti-doublon désactivé (RATE_LIMIT_SEC=0)", t_rate_limit_disabled)
r.check("anti-doublon actif : 1er OK, 2e bloqué", t_rate_limit_enabled)


# ══════════════════════════════════════════════════════════════════
# Description
# ══════════════════════════════════════════════════════════════════
r.section("AlertEnricher — description markdown")


def t_desc_basic():
    desc = AlertEnricher.build_description(
        "SSH BF", {"host": "srv", "src_ip": "1.2.3.4", "user": "root"}, {})
    assert "## 🚨 Alerte Splunk : SSH BF" in desc
    assert "1.2.3.4" in desc and "root" in desc and "srv" in desc


def t_desc_with_vt():
    desc = AlertEnricher.build_description("SSH BF", {"src_ip": "1.2.3.4"}, {
        "1.2.3.4": {"malicious": 10, "suspicious": 0, "total": 72,
                    "reputation": -50, "country": "RU"}})
    assert "VirusTotal" in desc and "MALVEILLANT" in desc and "RU" in desc


def t_desc_vt_key_missing():
    original_key, original_enabled = cfg.VT_APIKEY, cfg.VT_ENABLED
    cfg.VT_APIKEY, cfg.VT_ENABLED = "", True
    try:
        assert "VT_APIKEY" in AlertEnricher.build_description("T", {}, {})
    finally:
        cfg.VT_APIKEY, cfg.VT_ENABLED = original_key, original_enabled


def t_desc_json_safe():
    # Un objet non sérialisable ne doit pas faire échouer la description
    desc = AlertEnricher.build_description("T", {"obj": object()}, {})
    assert "Données brutes Splunk" in desc


r.check("description basique", t_desc_basic)
r.check("description avec résultats VT", t_desc_with_vt)
r.check("avertissement si VT_APIKEY manquante", t_desc_vt_key_missing)
r.check("données non sérialisables tolérées", t_desc_json_safe)


# ══════════════════════════════════════════════════════════════════
# Création d'alerte TheHive (client bouchonné)
# ══════════════════════════════════════════════════════════════════
r.section("create_thehive_alert — interprétation des codes HTTP")


class FakeTheHive:
    def __init__(self, code, body=None):
        self.code, self.body, self.calls = code, body, 0

    def create_alert(self, payload):
        self.calls += 1
        return self.code, self.body

    def ping(self):
        return True


def _with_fake(code, body=None):
    original = svc.thehive
    svc.thehive = FakeTheHive(code, body)
    try:
        return svc.create_thehive_alert({"title": "x"})
    finally:
        svc.thehive = original


def t_alert_created():
    assert _with_fake(201, {"_id": "abc123"}) == ("created", "abc123", "")


def t_alert_conflict():
    assert _with_fake(409)[0] == "duplicate"


def t_alert_400_duplicate():
    assert _with_fake(400, {"type": "CreateError",
                            "message": "Alert already exists"})[0] == "duplicate"


def t_alert_400_error():
    outcome, _, detail = _with_fake(400, {"type": "BadRequest", "message": "champ invalide"})
    assert outcome == "error" and "invalide" in detail


def t_alert_unauthorized():
    outcome, _, detail = _with_fake(401)
    assert outcome == "error" and "APIKEY" in detail


def t_alert_unreachable():
    original_attempts = cfg.RETRY_ATTEMPTS
    cfg.RETRY_ATTEMPTS = 1
    try:
        raised = False
        try:
            _with_fake(0)
        except ConnectionError:
            raised = True
        assert raised, "TheHive injoignable doit lever ConnectionError"
    finally:
        cfg.RETRY_ATTEMPTS = original_attempts


r.check("HTTP 201 → created + id", t_alert_created)
r.check("HTTP 409 → duplicate", t_alert_conflict)
r.check("HTTP 400 « already exists » → duplicate", t_alert_400_duplicate)
r.check("HTTP 400 autre → error", t_alert_400_error)
r.check("HTTP 401 → message sur THEHIVE_APIKEY", t_alert_unauthorized)
r.check("injoignable → ConnectionError", t_alert_unreachable)


# ══════════════════════════════════════════════════════════════════
# Endpoints Flask
# ══════════════════════════════════════════════════════════════════
r.section("Endpoints Flask")

client = svc.app.test_client()


def t_endpoint_stats():
    response = client.get("/stats")
    assert response.status_code == 200 and "stats" in response.get_json()


def t_endpoint_debug():
    response = client.get("/debug")
    assert response.status_code == 200 and "last_payloads" in response.get_json()


def t_endpoint_health():
    original = svc.thehive
    svc.thehive = FakeTheHive(201)
    try:
        response = client.get("/health")
        body = response.get_json()
        assert response.status_code == 200
        assert body["thehive"] is True and body["version"] == svc.VERSION
    finally:
        svc.thehive = original


def t_endpoint_alert_empty():
    response = client.post("/alert", data="pas du json",
                           content_type="application/json")
    assert response.status_code == 400


def t_endpoint_alert_created():
    original = svc.thehive
    svc.thehive = FakeTheHive(201, {"_id": "id-42"})
    try:
        response = client.post("/alert", json={
            "search_name": "Test unitaire SSH",
            "severity": "high",
            "result": {"src_ip": "185.220.101.50", "host": "srv", "user": "root"},
        })
        body = response.get_json()
        assert response.status_code == 201, body
        assert body["status"] == "created" and body["alert_id"] == "id-42"
        assert body["severity"] == "High" and body["artifacts_count"] >= 1
    finally:
        svc.thehive = original


def t_endpoint_alert_duplicate():
    original = svc.thehive
    svc.thehive = FakeTheHive(409)
    try:
        response = client.post("/alert", json={
            "search_name": "Doublon", "severity": "low",
            "result": {"host": "srv-doublon"}})
        assert response.status_code == 200
        assert response.get_json()["status"] == "duplicate"
    finally:
        svc.thehive = original


def t_endpoint_telegram_disabled():
    response = client.get("/telegram-test")
    assert response.status_code == 200
    assert response.get_json()["status"] == "disabled"


def t_endpoint_vt_disabled():
    response = client.get("/vt-test")
    assert response.status_code == 200
    assert response.get_json()["status"] == "disabled"


r.check("GET /stats", t_endpoint_stats)
r.check("GET /debug", t_endpoint_debug)
r.check("GET /health", t_endpoint_health)
r.check("POST /alert — payload invalide → 400", t_endpoint_alert_empty)
r.check("POST /alert — alerte créée → 201", t_endpoint_alert_created)
r.check("POST /alert — doublon → 200", t_endpoint_alert_duplicate)
r.check("GET /telegram-test — désactivé", t_endpoint_telegram_disabled)
r.check("GET /vt-test — désactivé", t_endpoint_vt_disabled)


if __name__ == "__main__":
    sys.exit(r.report())
