#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Briques communes                 ║
║  Partagé par le Service A (webhook) et le Service B (auto)  ║
╚══════════════════════════════════════════════════════════════╝

Contenu :
  - Chemins projet (PROJECT_ROOT, resolve_path)
  - Console UTF-8 + couleurs ANSI (Windows compris)
  - Lecture .env robuste + helpers env_str / env_int / env_bool
  - Logger rotatif
  - Observable (remplace thehive4py.models.AlertArtifact)
  - TheHiveClient : client REST API v1 natif (TheHive 5)
  - Telegram : notifier synchrone / asynchrone

Pourquoi un client REST maison plutôt que thehive4py ?
  thehive4py 1.x est abandonné, cible TheHive 3/4, et dépend de
  `python-magic` (libmagic) qui plante à l'import sous Windows.
  L'API REST v1 de TheHive 5 couvre 100 % des besoins du pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests

# ══════════════════════════════════════════════════════════════════
# CHEMINS
# ══════════════════════════════════════════════════════════════════
SRC_DIR      = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
DATA_DIR     = PROJECT_ROOT / "data"
LOGS_DIR     = PROJECT_ROOT / "logs"


def resolve_path(value: str, default_dir: Path) -> Path:
    """Rend un chemin absolu : relatif → sous `default_dir`, absolu → tel quel."""
    p = Path(str(value).strip()).expanduser()
    if not p.is_absolute():
        p = default_dir / p
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return p


# ══════════════════════════════════════════════════════════════════
# CONSOLE
# ══════════════════════════════════════════════════════════════════
def enable_utf8_console() -> None:
    """Active l'UTF-8 et les couleurs ANSI (indispensable sous Windows).

    Sans ça, les emojis et les caractères de cadre plantent la console
    Windows avec UnicodeEncodeError (codepage cp1252).
    """
    if os.name == "nt":
        os.system("")  # active le traitement des séquences ANSI
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


# ══════════════════════════════════════════════════════════════════
# TEMPS
# ══════════════════════════════════════════════════════════════════
def utcnow() -> datetime:
    """datetime UTC conscient du fuseau (datetime.utcnow() est déprécié)."""
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ══════════════════════════════════════════════════════════════════
# .env
# ══════════════════════════════════════════════════════════════════
_QUOTES = ("'", '"')


def _clean_value(raw: str) -> str:
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in _QUOTES:
        return v[1:-1]
    return v


def load_dotenv(path: str | os.PathLike | None = None, override: bool = True) -> str | None:
    """Charge un fichier .env dans os.environ.

    Ordre de recherche : argument → $SOC_ENV_FILE → <racine projet>/.env → ./.env
    Mettre SOC_SKIP_DOTENV=1 désactive complètement le chargement (utilisé par les tests).
    Retourne le chemin chargé, ou None.
    """
    if os.environ.get("SOC_SKIP_DOTENV", "").strip().lower() in ("1", "true", "yes"):
        return None

    candidates = []
    if path:
        candidates.append(Path(path))
    if os.environ.get("SOC_ENV_FILE"):
        candidates.append(Path(os.environ["SOC_ENV_FILE"]))
    candidates += [PROJECT_ROOT / ".env", Path.cwd() / ".env"]

    for candidate in candidates:
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        count = 0
        with open(candidate, encoding="utf-8-sig") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                key, _, val = line.partition("=")
                key = key.strip()
                if not key:
                    continue
                if not override and key in os.environ:
                    continue
                os.environ[key] = _clean_value(val)
                count += 1
        print("[ENV] Chargé : {} ({} variables)".format(candidate, count))
        return str(candidate)

    print("[ENV] Aucun .env trouvé — variables système utilisées")
    return None


def env_str(key: str, default: str = "") -> str:
    return _clean_value(os.getenv(key, default) or "")


def env_int(key: str, default: int) -> int:
    """int() tolérant : « 10 », « 10 # minutes » et « 10s » donnent tous 10.

    C'est ce qui évite le fameux `invalid literal for int()` quand un
    commentaire traîne après la valeur dans le .env.
    """
    raw = env_str(key, "")
    if not raw:
        return default
    match = re.match(r"\s*([+-]?\d+)", raw)
    if not match:
        return default
    try:
        return int(match.group(1))
    except ValueError:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    raw = env_str(key, "").split("#")[0].strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "oui")


# ══════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════
def setup_logger(name: str, log_file: Path | str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:            # déjà configuré (ré-import)
        return logger
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as exc:                         # disque plein, droits, etc.
        print("[LOG] Fichier de log indisponible ({}) — sortie console seule".format(exc))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    return logger


# ══════════════════════════════════════════════════════════════════
# OBSERVABLE
# ══════════════════════════════════════════════════════════════════
@dataclass
class Observable:
    """Observable TheHive (ex-AlertArtifact de thehive4py)."""
    dataType: str
    data: str
    message: str = ""
    tags: list = field(default_factory=list)
    ioc: bool = False
    tlp: int = 2

    def to_dict(self) -> dict:
        return {
            "dataType": self.dataType,
            "data":     self.data,
            "message":  self.message,
            "tags":     list(self.tags),
            "ioc":      bool(self.ioc),
            "tlp":      self.tlp,
        }


# ══════════════════════════════════════════════════════════════════
# THEHIVE — CLIENT REST API v1
# ══════════════════════════════════════════════════════════════════
def thehive_id(obj) -> str:
    """TheHive 5 renvoie « _id », TheHive 4 « id ». Compatible les deux."""
    if not isinstance(obj, dict):
        return ""
    return str(obj.get("_id") or obj.get("id") or "").strip()


class TheHiveClient:
    """Client minimal et robuste pour l'API v1 de TheHive 5."""

    def __init__(self, url: str, apikey: str, timeout: int = 20,
                 retries: int = 3, retry_delay: int = 2,
                 verify: bool = True, logger: logging.Logger | None = None):
        self.base        = str(url or "").rstrip("/")
        self.apikey      = apikey or ""
        self.timeout     = timeout
        self.retries     = max(1, retries)
        self.retry_delay = max(0, retry_delay)
        self.verify      = verify
        self.log         = logger or logging.getLogger("thehive")
        self.session     = requests.Session()
        self.session.headers.update({
            "Authorization": "Bearer {}".format(self.apikey),
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        })

    # ── transport ────────────────────────────────────────────────
    def request(self, method: str, path: str, payload=None, params=None,
                retries: int | None = None, timeout: int | None = None):
        """Requête HTTP avec retry sur erreur réseau / 5xx. Retourne la Response ou None."""
        url      = "{}{}".format(self.base, path)
        attempts = self.retries if retries is None else max(1, retries)
        for attempt in range(1, attempts + 1):
            try:
                resp = self.session.request(
                    method, url, json=payload, params=params,
                    timeout=timeout or self.timeout, verify=self.verify,
                )
                if resp.status_code < 500:
                    return resp
                self.log.warning("%s %s → HTTP %d [%d/%d]",
                                 method, path, resp.status_code, attempt, attempts)
            except requests.RequestException as exc:
                self.log.warning("%s %s échec réseau [%d/%d] : %s",
                                 method, path, attempt, attempts, exc)
            if attempt < attempts:
                time.sleep(self.retry_delay * attempt)
        return None

    @staticmethod
    def _json(resp):
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    # ── santé ────────────────────────────────────────────────────
    def ping(self) -> bool:
        """Vrai si l'URL répond ET que la clé API est acceptée."""
        resp = self.request("GET", "/api/v1/user/current", retries=1, timeout=10)
        if resp is not None and resp.status_code == 200:
            return True
        resp = self.request("POST", "/api/v1/query?name=ping",
                            payload={"query": [{"_name": "listAlert"},
                                               {"_name": "page", "from": 0, "to": 1}]},
                            retries=1, timeout=10)
        return resp is not None and resp.status_code == 200

    # ── alertes ──────────────────────────────────────────────────
    def create_alert(self, payload: dict):
        """Crée une alerte. Retourne (status_code, body_json_ou_texte)."""
        resp = self.request("POST", "/api/v1/alert", payload=payload)
        if resp is None:
            return 0, None
        return resp.status_code, (self._json(resp) if resp.content else None)

    def list_alerts(self, statuses=("New", "Updated"), limit: int = 200) -> list:
        resp = self.request("POST", "/api/v1/query?name=list-alerts", payload={"query": [
            {"_name": "listAlert"},
            {"_name": "filter", "_in": {"_field": "status", "_values": list(statuses)}},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": limit},
        ]})
        data = self._json(resp)
        return data if isinstance(data, list) else []

    def alert_observables(self, alert_id: str) -> list:
        data = self._json(self.request("GET", "/api/v1/alert/{}/observable".format(alert_id)))
        return data if isinstance(data, list) else []

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        resp = self.request("PATCH", "/api/v1/alert/{}".format(alert_id),
                            payload={"status": status}, retries=1)
        return resp is not None and resp.status_code in (200, 204)

    def promote_alert(self, alert_id: str) -> dict | None:
        data = self._json(self.request("POST", "/api/v1/alert/{}/case".format(alert_id),
                                       payload={}, retries=1))
        return data if isinstance(data, dict) and thehive_id(data) else None

    def merge_alert_into_case(self, alert_id: str, case_id: str) -> bool:
        resp = self.request("POST", "/api/v1/alert/{}/merge/{}".format(alert_id, case_id),
                            retries=1)
        return resp is not None and resp.status_code in (200, 201)

    # ── cas ──────────────────────────────────────────────────────
    def create_case(self, payload: dict) -> dict | None:
        data = self._json(self.request("POST", "/api/v1/case", payload=payload))
        return data if isinstance(data, dict) and thehive_id(data) else None

    def get_case(self, case_id: str) -> dict | None:
        data = self._json(self.request("GET", "/api/v1/case/{}".format(case_id), retries=1))
        return data if isinstance(data, dict) else None

    def update_case(self, case_id: str, payload: dict) -> bool:
        resp = self.request("PATCH", "/api/v1/case/{}".format(case_id),
                            payload=payload, retries=1)
        return resp is not None and resp.status_code in (200, 204)

    def add_tag(self, case_id: str, tag: str) -> bool:
        case = self.get_case(case_id)
        if case is None:
            return False
        tags = list(case.get("tags") or [])
        if tag in tags:
            return True
        return self.update_case(case_id, {"tags": tags + [tag]})

    def add_comment(self, case_id: str, message: str) -> bool:
        resp = self.request("POST", "/api/v1/case/{}/comment".format(case_id),
                            payload={"message": message}, retries=2)
        return resp is not None and resp.status_code in (200, 201)

    def add_observable(self, case_id: str, observable: Observable) -> str:
        """Ajoute un observable au cas. Retourne son id, ou "" en cas d'échec."""
        data = self._json(self.request("POST", "/api/v1/case/{}/observable".format(case_id),
                                       payload=observable.to_dict(), retries=2))
        if isinstance(data, list) and data:
            return thehive_id(data[0])
        if isinstance(data, dict):
            return thehive_id(data)
        return ""

    # ── cortex (piloté par TheHive) ──────────────────────────────
    def cortex_analyzers(self) -> list:
        """Analyseurs connus de TheHive (tous serveurs Cortex connectés)."""
        data = self._json(self.request("GET", "/api/connector/cortex/analyzer",
                                       retries=1, timeout=15))
        return data if isinstance(data, list) else []

    def cortex_analyzers_for(self, datatype: str) -> list:
        """Analyseurs applicables à un dataType (ip, hash, domain, url...)."""
        data = self._json(self.request(
            "GET", "/api/connector/cortex/analyzer/type/{}".format(datatype),
            retries=1, timeout=15))
        return data if isinstance(data, list) else []

    def run_cortex_job(self, analyzer_id: str, observable_id: str,
                       cortex_id: str = "") -> str:
        """Lance un analyseur Cortex sur un observable. Retourne l'id du job."""
        payload = {"analyzerId": analyzer_id, "artifactId": observable_id}
        if cortex_id:
            payload["cortexId"] = cortex_id
        data = self._json(self.request("POST", "/api/connector/cortex/job",
                                       payload=payload, retries=1, timeout=30))
        if isinstance(data, dict):
            return str(data.get("cortexJobId") or thehive_id(data) or "")
        return ""

    def run_analyzer_on_observable(self, case_id: str, observable_id: str,
                                   analyzer_id: str) -> str:
        """Route alternative (API v1 par cas) si /api/connector/cortex/job échoue."""
        data = self._json(self.request(
            "POST", "/api/v1/case/{}/observable/{}/analyzer/{}".format(
                case_id, observable_id, analyzer_id), payload={}, retries=1, timeout=30))
        if isinstance(data, dict):
            return str(data.get("cortexJobId") or thehive_id(data) or "")
        return ""

    def get_cortex_job(self, job_id: str) -> dict | None:
        data = self._json(self.request("GET", "/api/connector/cortex/job/{}".format(job_id),
                                       retries=1, timeout=15))
        return data if isinstance(data, dict) else None


# ══════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════
class Telegram:
    """Notifier Telegram — silencieux et non bloquant si mal configuré."""

    API = "https://api.telegram.org/bot{}/{}"

    def __init__(self, token: str = "", chat_id: str = "", enabled: bool = False,
                 logger: logging.Logger | None = None, timeout: int = 10):
        self.token   = token or ""
        self.chat_id = chat_id or ""
        self.enabled = bool(enabled and self.token and self.chat_id)
        self.timeout = timeout
        self.log     = logger or logging.getLogger("telegram")

    def get_me(self) -> dict | None:
        if not self.token:
            return None
        try:
            r = requests.get(self.API.format(self.token, "getMe"), timeout=self.timeout)
            if r.status_code == 200:
                return r.json().get("result", {})
        except requests.RequestException as exc:
            self.log.error("Telegram getMe : %s", exc)
        return None

    def send(self, message: str, keyboard: dict | None = None) -> bool:
        """Envoi synchrone. Retourne True si Telegram a accepté le message."""
        if not self.enabled:
            return False
        payload = {"chat_id": self.chat_id, "text": message[:4096], "parse_mode": "HTML"}
        if keyboard:
            payload["reply_markup"] = json.dumps(keyboard)
        try:
            r = requests.post(self.API.format(self.token, "sendMessage"),
                              json=payload, timeout=self.timeout)
            if r.status_code == 200 and r.json().get("ok"):
                return True
            self.log.warning("Telegram HTTP %d : %s", r.status_code, r.text[:200])
        except requests.RequestException as exc:
            self.log.error("Telegram : %s", exc)
        return False

    def send_async(self, message: str, keyboard: dict | None = None) -> None:
        if not self.enabled:
            return
        threading.Thread(target=self.send, args=(message, keyboard), daemon=True).start()
