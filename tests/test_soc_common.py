#!/usr/bin/env python3
"""
Tests unitaires — soc_common (briques partagées)

Lancement :
    python tests/test_soc_common.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import TMP_DIR, Runner, bootstrap             # noqa: E402

bootstrap()

import soc_common as sc                                    # noqa: E402

r = Runner("Tests unitaires — soc_common")


# ══════════════════════════════════════════════════════════════════
# Lecture des variables d'environnement
# ══════════════════════════════════════════════════════════════════
r.section("env_str / env_int / env_bool")


def t_env_str():
    os.environ["T_STR"] = '  "valeur entre guillemets"  '
    assert sc.env_str("T_STR") == "valeur entre guillemets"
    assert sc.env_str("T_ABSENTE", "défaut") == "défaut"
    assert sc.env_str("T_ABSENTE") == ""


def t_env_int_simple():
    os.environ["T_INT"] = "42"
    assert sc.env_int("T_INT", 0) == 42


def t_env_int_inline_comment():
    # Le bug historique : « invalid literal for int() » quand un
    # commentaire suivait la valeur dans le .env
    os.environ["T_INT_C"] = "10    # durée en minutes"
    assert sc.env_int("T_INT_C", 0) == 10


def t_env_int_suffix():
    os.environ["T_INT_S"] = "20s"
    assert sc.env_int("T_INT_S", 0) == 20


def t_env_int_invalid():
    os.environ["T_INT_BAD"] = "abc"
    assert sc.env_int("T_INT_BAD", 7) == 7
    os.environ["T_INT_EMPTY"] = ""
    assert sc.env_int("T_INT_EMPTY", 5) == 5


def t_env_int_negative():
    os.environ["T_INT_NEG"] = "-3"
    assert sc.env_int("T_INT_NEG", 0) == -3


def t_env_bool():
    for truthy in ("true", "TRUE", "1", "yes", "on", "oui"):
        os.environ["T_BOOL"] = truthy
        assert sc.env_bool("T_BOOL") is True, truthy
    for falsy in ("false", "0", "no", "n'importe quoi"):
        os.environ["T_BOOL"] = falsy
        assert sc.env_bool("T_BOOL") is False, falsy
    os.environ["T_BOOL"] = ""
    assert sc.env_bool("T_BOOL", True) is True


def t_env_bool_inline_comment():
    os.environ["T_BOOL_C"] = "true  # activer le blocage"
    assert sc.env_bool("T_BOOL_C") is True


r.check("env_str — guillemets et défauts", t_env_str)
r.check("env_int — valeur simple", t_env_int_simple)
r.check("env_int — commentaire en fin de ligne", t_env_int_inline_comment)
r.check("env_int — suffixe non numérique", t_env_int_suffix)
r.check("env_int — valeur illisible → défaut", t_env_int_invalid)
r.check("env_int — valeur négative", t_env_int_negative)
r.check("env_bool — toutes les formes", t_env_bool)
r.check("env_bool — commentaire en fin de ligne", t_env_bool_inline_comment)


# ══════════════════════════════════════════════════════════════════
# load_dotenv
# ══════════════════════════════════════════════════════════════════
r.section("load_dotenv")


def t_dotenv_skipped():
    # SOC_SKIP_DOTENV=1 est posé par le harnais : aucun .env ne doit être lu
    assert sc.load_dotenv() is None


def t_dotenv_reads_file():
    env_file = TMP_DIR / "exemple.env"
    env_file.write_text(
        "# commentaire\n"
        "\n"
        "export CLE_EXPORT=valeur1\n"
        'CLE_GUILLEMETS="valeur 2"\n'
        "CLE_SIMPLE=valeur3\n"
        "ligne_sans_egal\n",
        encoding="utf-8")
    saved = os.environ.pop("SOC_SKIP_DOTENV", None)
    try:
        loaded = sc.load_dotenv(env_file)
        assert loaded == str(env_file)
        assert os.environ["CLE_EXPORT"] == "valeur1"
        assert os.environ["CLE_GUILLEMETS"] == "valeur 2"
        assert os.environ["CLE_SIMPLE"] == "valeur3"
    finally:
        if saved is not None:
            os.environ["SOC_SKIP_DOTENV"] = saved
        for key in ("CLE_EXPORT", "CLE_GUILLEMETS", "CLE_SIMPLE"):
            os.environ.pop(key, None)


r.check("SOC_SKIP_DOTENV=1 désactive la lecture", t_dotenv_skipped)
r.check("lecture d'un .env (export, guillemets, commentaires)", t_dotenv_reads_file)


# ══════════════════════════════════════════════════════════════════
# Chemins
# ══════════════════════════════════════════════════════════════════
r.section("Chemins")


def t_resolve_relative():
    resolved = sc.resolve_path("fichier.log", TMP_DIR)
    assert resolved.is_absolute() and resolved.parent == TMP_DIR


def t_resolve_absolute():
    absolute = TMP_DIR / "ailleurs.log"
    assert sc.resolve_path(str(absolute), sc.DATA_DIR) == absolute


def t_resolve_creates_parent():
    resolved = sc.resolve_path("sous/dossier/x.log", TMP_DIR)
    assert resolved.parent.is_dir()


def t_project_root():
    assert (sc.PROJECT_ROOT / "start.py").exists()
    assert (sc.PROJECT_ROOT / "requirements.txt").exists()


r.check("resolve_path — chemin relatif", t_resolve_relative)
r.check("resolve_path — chemin absolu conservé", t_resolve_absolute)
r.check("resolve_path — crée le dossier parent", t_resolve_creates_parent)
r.check("PROJECT_ROOT pointe sur la racine du projet", t_project_root)


# ══════════════════════════════════════════════════════════════════
# Observable
# ══════════════════════════════════════════════════════════════════
r.section("Observable")


def t_observable_defaults():
    obs = sc.Observable(dataType="ip", data="1.2.3.4")
    payload = obs.to_dict()
    assert payload == {"dataType": "ip", "data": "1.2.3.4", "message": "",
                       "tags": [], "ioc": False, "tlp": 2}


def t_observable_tags_isolated():
    first  = sc.Observable(dataType="ip", data="1.1.1.1")
    second = sc.Observable(dataType="ip", data="2.2.2.2")
    first.tags.append("x")
    assert second.tags == [], "les tags par défaut ne doivent pas être partagés"


r.check("valeurs par défaut sérialisées", t_observable_defaults)
r.check("pas de liste de tags partagée entre instances", t_observable_tags_isolated)


# ══════════════════════════════════════════════════════════════════
# thehive_id
# ══════════════════════════════════════════════════════════════════
r.section("thehive_id")


def t_thehive_id():
    assert sc.thehive_id({"_id": "abc"}) == "abc"          # TheHive 5
    assert sc.thehive_id({"id": "def"}) == "def"           # TheHive 4
    assert sc.thehive_id({"_id": "a", "id": "b"}) == "a"   # _id prioritaire
    assert sc.thehive_id({}) == ""
    assert sc.thehive_id(None) == ""
    assert sc.thehive_id("chaîne") == ""


r.check("compatible TheHive 4 et 5", t_thehive_id)


# ══════════════════════════════════════════════════════════════════
# TheHiveClient (transport bouchonné)
# ══════════════════════════════════════════════════════════════════
r.section("TheHiveClient")


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload    = payload
        self.content     = b"x" if payload is not None else b""

    def json(self):
        if self._payload is None:
            raise ValueError("pas de JSON")
        return self._payload


def _client(responses):
    """Client dont `request` renvoie les réponses fournies, dans l'ordre."""
    client = sc.TheHiveClient("http://exemple:9000", "clef")
    queue  = list(responses)
    calls  = []

    def fake_request(method, path, payload=None, params=None, retries=None, timeout=None):
        calls.append((method, path, payload))
        return queue.pop(0) if queue else None

    client.request = fake_request
    client.calls   = calls
    return client


def t_client_headers():
    client = sc.TheHiveClient("http://exemple:9000/", "ma-clef")
    assert client.base == "http://exemple:9000"
    assert client.session.headers["Authorization"] == "Bearer ma-clef"


def t_client_ping():
    assert _client([FakeResponse(200, {"login": "x"})]).ping() is True
    assert _client([FakeResponse(401), FakeResponse(401)]).ping() is False


def t_client_create_alert():
    code, body = _client([FakeResponse(201, {"_id": "a1"})]).create_alert({"title": "t"})
    assert code == 201 and body["_id"] == "a1"


def t_client_create_alert_unreachable():
    assert _client([None]).create_alert({}) == (0, None)


def t_client_list_alerts():
    client = _client([FakeResponse(200, [{"_id": "1"}, {"_id": "2"}])])
    assert len(client.list_alerts()) == 2
    assert _client([FakeResponse(200, {"pas": "une liste"})]).list_alerts() == []


def t_client_add_observable():
    obs = sc.Observable(dataType="ip", data="1.2.3.4")
    assert _client([FakeResponse(201, [{"_id": "obs1"}])]).add_observable("c1", obs) == "obs1"
    assert _client([FakeResponse(201, {"_id": "obs2"})]).add_observable("c1", obs) == "obs2"
    assert _client([FakeResponse(400)]).add_observable("c1", obs) == ""


def t_client_add_tag_skips_existing():
    client = _client([FakeResponse(200, {"tags": ["deja"]})])
    assert client.add_tag("c1", "deja") is True
    assert len(client.calls) == 1, "aucun PATCH ne doit être émis si le tag existe"


def t_client_add_tag_appends():
    client = _client([FakeResponse(200, {"tags": ["a"]}), FakeResponse(200)])
    assert client.add_tag("c1", "b") is True
    assert client.calls[1][2] == {"tags": ["a", "b"]}


def t_client_promote_requires_id():
    assert _client([FakeResponse(201, {"_id": "case1"})]).promote_alert("a1")["_id"] == "case1"
    assert _client([FakeResponse(201, {})]).promote_alert("a1") is None


def t_client_run_cortex_job():
    client = _client([FakeResponse(201, {"cortexJobId": "job42"})])
    assert client.run_cortex_job("AbuseIPDB_1_0", "obs1", "local") == "job42"
    assert client.calls[0][2]["cortexId"] == "local"


def t_client_cortex_analyzers():
    payload = [{"id": "AbuseIPDB_1_0", "name": "AbuseIPDB", "dataTypeList": ["ip"]}]
    assert _client([FakeResponse(200, payload)]).cortex_analyzers() == payload
    assert _client([FakeResponse(404)]).cortex_analyzers() == []


r.check("URL normalisée et en-tête Bearer", t_client_headers)
r.check("ping — 200 puis repli", t_client_ping)
r.check("create_alert — code + corps", t_client_create_alert)
r.check("create_alert — serveur injoignable → (0, None)", t_client_create_alert_unreachable)
r.check("list_alerts — liste ou vide", t_client_list_alerts)
r.check("add_observable — liste, dict ou échec", t_client_add_observable)
r.check("add_tag — pas de PATCH si le tag existe déjà", t_client_add_tag_skips_existing)
r.check("add_tag — ajoute au tableau existant", t_client_add_tag_appends)
r.check("promote_alert — exige un identifiant", t_client_promote_requires_id)
r.check("run_cortex_job — renvoie l'id du job", t_client_run_cortex_job)
r.check("cortex_analyzers — liste ou vide", t_client_cortex_analyzers)


# ══════════════════════════════════════════════════════════════════
# Telegram
# ══════════════════════════════════════════════════════════════════
r.section("Telegram")


def t_telegram_disabled_without_token():
    assert sc.Telegram("", "", True).enabled is False
    assert sc.Telegram("token", "", True).enabled is False
    assert sc.Telegram("token", "chat", False).enabled is False
    assert sc.Telegram("token", "chat", True).enabled is True


def t_telegram_send_noop():
    # Désactivé → aucun appel réseau, retour False immédiat
    assert sc.Telegram("", "", False).send("coucou") is False
    assert sc.Telegram("", "", False).send_async("coucou") is None


r.check("activé seulement si token ET chat_id", t_telegram_disabled_without_token)
r.check("désactivé → aucun envoi", t_telegram_send_noop)


# ══════════════════════════════════════════════════════════════════
# Divers
# ══════════════════════════════════════════════════════════════════
r.section("Divers")


def t_utcnow_aware():
    assert sc.utcnow().tzinfo is not None, "datetime.utcnow() déprécié : il faut un tz-aware"
    assert "T" in sc.utcnow_iso()


def t_setup_logger_idempotent():
    first  = sc.setup_logger("test-logger", TMP_DIR / "logger.log", "INFO")
    second = sc.setup_logger("test-logger", TMP_DIR / "logger.log", "INFO")
    assert first is second
    assert len(first.handlers) == len(second.handlers)


def t_enable_utf8_console():
    sc.enable_utf8_console()          # ne doit jamais lever


r.check("utcnow — conscient du fuseau", t_utcnow_aware)
r.check("setup_logger — pas de handlers dupliqués", t_setup_logger_idempotent)
r.check("enable_utf8_console — sans exception", t_enable_utf8_console)


if __name__ == "__main__":
    sys.exit(r.report())
