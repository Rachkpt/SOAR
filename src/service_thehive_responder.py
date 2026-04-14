#!/usr/bin/env python3
"""
SOC Pipeline — Service B  v8.1.0  ZERO PITIÉ
Toute IP qui brute force → BLOQUÉE 10 minutes
IPs internes ET externes bloquées sans exception
Cas TheHive créé automatiquement GARANTI
Déblocage auto après 10 min + manuel

FIXES v8.1.0:
  - TheHive v5 utilise "_id" et non "id" → toutes les alertes étaient ignorées
  - alert_data.get("_id") corrigé dans process()
  - promote() vérifie "_id" ET "id" pour compatibilité v4/v5
  - add_tag() utilise API v1 directement (plus fiable)
  - Telegram non-bloquant garanti (daemon thread)
"""

import os, json, logging, time, subprocess, re, sys, warnings, threading, smtplib, ipaddress
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

warnings.filterwarnings("ignore", category=DeprecationWarning)

def _load_env():
    for p in [Path(__file__).parent/".env", Path.cwd()/".env", Path.home()/".env"]:
        if p.exists():
            count = 0
            with open(p, encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line: continue
                    k, _, v = line.partition("=")
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")
                    count += 1
            print("[ENV] {} ({} vars)".format(p, count))
            return str(p)
    return None

_ENV_PATH = _load_env()

import requests
from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTaskLog

class Config:
    THEHIVE_URL        = os.getenv("THEHIVE_URL",        "http://10.2.3.119:9000")
    THEHIVE_APIKEY     = os.getenv("THEHIVE_APIKEY",     "")
    CORTEX_URL         = os.getenv("CORTEX_URL",         "http://10.2.3.119:9001")
    CORTEX_APIKEY      = os.getenv("CORTEX_APIKEY",      "")
    MISP_URL           = os.getenv("MISP_URL",           "https://10.2.3.121")
    MISP_APIKEY        = os.getenv("MISP_APIKEY",        "")
    MISP_ENABLED       = os.getenv("MISP_ENABLED",       "true").lower() == "true"
    VT_ENABLED         = os.getenv("VT_ENABLED",         "true").lower() == "true"
    VT_APIKEY          = os.getenv("VT_APIKEY",          "")
    VT_TIMEOUT         = int(os.getenv("VT_TIMEOUT",     "15").split()[0])
    VT_MIN_DETECTIONS  = int(os.getenv("VT_MIN_DETECTIONS","2").split()[0])
    POLL_INTERVAL_SEC  = int(os.getenv("POLL_INTERVAL",  "20").split()[0])
    STATE_FILE         = os.getenv("STATE_FILE",         "responder_state.json")
    BLACKLIST_FILE     = os.getenv("BLACKLIST_FILE",     "ip_blacklist.txt")
    LOG_FILE           = os.getenv("LOG_FILE_B",         "service_b.log")
    LOG_LEVEL          = os.getenv("LOG_LEVEL",          "INFO")
    ACTIVE_RESPONSE    = os.getenv("ACTIVE_RESPONSE",    "false").lower() == "true"
    BLOCK_DURATION_MIN = int(os.getenv("BLOCK_DURATION_MIN", "10").split()[0])
    BLOCK_ALL_IPS      = os.getenv("BLOCK_ALL_IPS",      "true").lower() == "true"
    BRUTE_FORCE_TAGS   = ["brute_force","ssh","failed_auth","brute-force"]
    TELEGRAM_ENABLED   = os.getenv("TELEGRAM_ENABLED",   "false").lower() == "true"
    TELEGRAM_TOKEN     = os.getenv("TELEGRAM_TOKEN",     "")
    TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "")
    GMAIL_ENABLED      = os.getenv("GMAIL_ENABLED",      "false").lower() == "true"
    GMAIL_USER         = os.getenv("GMAIL_USER",         "")
    GMAIL_PASS         = os.getenv("GMAIL_PASS",         "")
    GMAIL_TO           = os.getenv("GMAIL_TO",           "")

cfg = Config()

def _setup_log():
    logger = logging.getLogger("SOC-B")
    logger.setLevel(getattr(logging, cfg.LOG_LEVEL, logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    try:
        fh = RotatingFileHandler(cfg.LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt); logger.addHandler(fh)
    except Exception: pass
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt); logger.addHandler(ch)
    return logger

log = _setup_log()


def _get_id(obj: dict) -> str:
    """TheHive v5 utilise '_id', v4 utilise 'id'. Compatible les deux."""
    return obj.get("_id") or obj.get("id") or ""


class BlockManager:
    """Bloque/débloque les IPs avec timer automatique."""
    BLACKLIST_JSON = "ip_blacklist.json"

    def __init__(self):
        self._blocked = {}  # {ip: {"blocked_at":datetime,"timer":Timer,"reason":str}}
        self._lock    = threading.Lock()
        self._load()

    def _load(self):
        p = Path(self.BLACKLIST_JSON)
        if not p.exists(): return
        try:
            with open(p) as f: data = json.load(f)
            now = datetime.now()
            for ip, info in data.items():
                ba        = datetime.fromisoformat(info["blocked_at"])
                remaining = cfg.BLOCK_DURATION_MIN - (now-ba).total_seconds()/60
                if remaining > 0:
                    self._apply(ip)
                    t = threading.Timer(remaining*60, self._auto_unblock, args=[ip])
                    t.daemon = True; t.start()
                    self._blocked[ip] = {"blocked_at":ba,"reason":info.get("reason","restauré"),"timer":t}
                    log.info("IP %s restaurée (%.1f min restantes)", ip, remaining)
                else:
                    self._remove(ip)
        except Exception as e:
            log.error("Load blacklist: %s", e)

    def _save(self):
        try:
            data = {ip:{"blocked_at":v["blocked_at"].isoformat(),"reason":v["reason"]}
                    for ip,v in self._blocked.items()}
            with open(self.BLACKLIST_JSON,"w") as f: json.dump(data,f,indent=2)
            with open(cfg.BLACKLIST_FILE,"w") as f:
                f.write("# IPs bloquées — SOC Pipeline v8.1.0\n")
                f.write("# IP | bloquée_le | raison | expire_le\n\n")
                for ip,info in self._blocked.items():
                    exp = info["blocked_at"]+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                    f.write("{} | {} | {} | expire {}\n".format(
                        ip, info["blocked_at"].strftime("%Y-%m-%d %H:%M:%S"),
                        info["reason"], exp.strftime("%H:%M:%S")))
        except Exception as e:
            log.error("Save blacklist: %s", e)

    def _apply(self, ip: str) -> bool:
        if sys.platform == "win32":
            try:
                for direction, name_suffix in [("in","IN"),("out","OUT")]:
                    subprocess.run([
                        "netsh","advfirewall","firewall","add","rule",
                        "name=SOC_BLOCK_{}_{}".format(ip.replace(".","_"),name_suffix),
                        "dir={}".format(direction),"action=block","remoteip={}".format(ip)
                    ], capture_output=True, timeout=10)
                log.info("Windows Firewall: %s bloquée", ip)
                return True
            except Exception as e:
                log.error("Windows Firewall: %s", e)
                return False
        else:
            ok = True
            for cmd in [
                ["iptables","-I","INPUT","1","-s",ip,"-j","DROP"],
                ["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP"],
            ]:
                try:
                    r = subprocess.run(cmd, capture_output=True, timeout=10)
                    if r.returncode != 0:
                        log.error("iptables: %s", r.stderr.decode()[:80])
                        ok = False
                except FileNotFoundError:
                    log.error("iptables absent — apt install iptables")
                    return False
                except Exception as e:
                    log.error("iptables: %s", e); ok = False
            return ok

    def _remove(self, ip: str):
        if sys.platform == "win32":
            for suffix in ["IN","OUT"]:
                try:
                    subprocess.run([
                        "netsh","advfirewall","firewall","delete","rule",
                        "name=SOC_BLOCK_{}_{}".format(ip.replace(".","_"),suffix)
                    ], capture_output=True, timeout=10)
                except Exception: pass
        else:
            for cmd in [
                ["iptables","-D","INPUT","-s",ip,"-j","DROP"],
                ["iptables","-D","OUTPUT","-d",ip,"-j","DROP"],
            ]:
                try: subprocess.run(cmd, capture_output=True, timeout=10)
                except Exception: pass

    def _auto_unblock(self, ip: str):
        with self._lock:
            if ip not in self._blocked: return
            info = self._blocked.pop(ip)
            self._remove(ip)
            self._save()
        log.info("✅ %s débloquée (timer %d min)", ip, cfg.BLOCK_DURATION_MIN)
        Notifier.telegram(
            "✅ <b>IP DÉBLOQUÉE — Expirée</b>\n"
            "IP: <code>{}</code>\n"
            "Durée: {} minutes\n"
            "Raison initiale: {}".format(ip, cfg.BLOCK_DURATION_MIN, info.get("reason","?"))
        )

    def block(self, ip: str, reason: str = "brute force") -> dict:
        with self._lock:
            if ip in self._blocked:
                exp = self._blocked[ip]["blocked_at"]+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                return {"success":False,"already_blocked":True,"expires_at":exp.strftime("%H:%M:%S")}

            if not cfg.ACTIVE_RESPONSE:
                return {"success":False,"dry_run":True,
                        "message":"ACTIVE_RESPONSE=false — ajouter dans .env + relancer avec sudo"}

            ok  = self._apply(ip)
            now = datetime.now()
            exp = now + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
            if ok:
                t = threading.Timer(cfg.BLOCK_DURATION_MIN*60, self._auto_unblock, args=[ip])
                t.daemon = True; t.start()
                self._blocked[ip] = {"blocked_at":now,"reason":reason,"timer":t}
                self._save()
                log.warning("🚫 BLOQUÉ: %s | %s | expire %s", ip, reason, exp.strftime("%H:%M:%S"))
                return {"success":True,"expires_at":exp.strftime("%H:%M:%S"),
                        "blocked_at":now.strftime("%H:%M:%S"),"duration_min":cfg.BLOCK_DURATION_MIN}
            return {"success":False,"error":"firewall a échoué"}

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocked: return False
            info = self._blocked.pop(ip)
            if info.get("timer"): info["timer"].cancel()
            self._remove(ip); self._save()
            log.info("✅ %s débloquée manuellement", ip)
            return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock: return ip in self._blocked

    def list_blocked(self) -> list:
        with self._lock:
            now = datetime.now(); result = []
            for ip,info in self._blocked.items():
                rem = max(0,(cfg.BLOCK_DURATION_MIN-(now-info["blocked_at"]).total_seconds()/60))
                exp = info["blocked_at"]+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                result.append({"ip":ip,"reason":info["reason"],
                               "remaining_min":round(rem,1),"expires_at":exp.strftime("%H:%M:%S")})
            return result

block_manager = BlockManager()


class Notifier:
    @staticmethod
    def telegram(msg: str):
        if not cfg.TELEGRAM_ENABLED or not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID: return
        def _s():
            try:
                requests.post(
                    "https://api.telegram.org/bot{}/sendMessage".format(cfg.TELEGRAM_TOKEN),
                    json={"chat_id":cfg.TELEGRAM_CHAT_ID,"text":msg[:4096],"parse_mode":"HTML"},
                    timeout=10)
            except Exception as e: log.error("Telegram: %s", e)
        threading.Thread(target=_s, daemon=True).start()

    @staticmethod
    def email(subject: str, body: str, html: str = None):
        if not cfg.GMAIL_ENABLED or not all([cfg.GMAIL_USER,cfg.GMAIL_PASS,cfg.GMAIL_TO]): return
        def _s():
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"],msg["From"],msg["To"] = subject,cfg.GMAIL_USER,cfg.GMAIL_TO
                msg.attach(MIMEText(body,"plain","utf-8"))
                if html: msg.attach(MIMEText(html,"html","utf-8"))
                with smtplib.SMTP_SSL("smtp.gmail.com",465) as s:
                    s.login(cfg.GMAIL_USER,cfg.GMAIL_PASS)
                    s.sendmail(cfg.GMAIL_USER,cfg.GMAIL_TO,msg.as_string())
            except Exception as e: log.error("Gmail: %s", e)
        threading.Thread(target=_s, daemon=True).start()

    @classmethod
    def block_alert(cls, ip: str, reason: str, expires: str, case_num, title: str, vt: dict=None):
        vt_line = ""
        if vt:
            vt_line = "\n🦠 <b>VT:</b> {}/{} détect. (rep={})".format(
                vt.get("malicious",0),vt.get("total",0),vt.get("reputation",0))
        tg = ("🚫 <b>IP BLOQUÉE — {} min</b>\n\n"
              "IP: <code>{}</code>\n"
              "Raison: {}\n"
              "Bloquée: {}\n"
              "Déblocage auto: {}{}\n\n"
              "Cas TheHive: <b>#{}</b>\n"
              "{}"
              "\n\n<i>python start.py unblock {}</i>").format(
            cfg.BLOCK_DURATION_MIN, ip, reason,
            datetime.now().strftime("%H:%M:%S"), expires,
            vt_line, case_num, title[:60], ip)
        cls.telegram(tg)
        body = "IP BLOQUEE: {}\nRaison: {}\nDuree: {} min\nExpire: {}\nCas: #{}\nAlerte: {}".format(
            ip, reason, cfg.BLOCK_DURATION_MIN, expires, case_num, title)
        html = '''<html><body style="font-family:Arial;padding:20px">
<div style="background:#fff;border-radius:8px;padding:24px;max-width:600px;border-left:5px solid #ef4444">
  <h2 style="color:#ef4444">🚫 IP BLOQUÉE — SOC Pipeline v8.1</h2>
  <p><b>IP:</b> <code style="font-size:18px">{ip}</code></p>
  <p><b>Raison:</b> {reason}</p>
  <p><b>Durée:</b> {dur} minutes — expire à {exp}</p>
  <p><b>Cas TheHive:</b> #{case}</p>
  <p><b>Alerte:</b> {title}</p>
  <hr><code>python start.py unblock {ip}</code>
  <p style="color:#94a3b8;font-size:11px">SOC Pipeline v8.1.0</p>
</div></body></html>'''.format(ip=ip, reason=reason, dur=cfg.BLOCK_DURATION_MIN,
                               exp=expires, case=case_num, title=title[:60])
        cls.email("[SOC 🚫] IP BLOQUÉE: {}".format(ip), body, html)

    @classmethod
    def case_created(cls, case_num, title: str, ip: str, case_id: str):
        cls.telegram("📁 <b>Cas créé — #{}</b>\n{}\nIP: <code>{}</code>\n"
                     "\n<a href='{}/cases/{}/details'>→ TheHive</a>".format(
            case_num, title[:80], ip or "N/A", cfg.THEHIVE_URL, case_id))


class VTClient:
    BASE = "https://www.virustotal.com/api/v3"

    @classmethod
    def _get(cls, ep: str) -> dict:
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY: return {}
        try:
            r = requests.get("{}/{}".format(cls.BASE,ep),
                             headers={"x-apikey":cfg.VT_APIKEY}, timeout=cfg.VT_TIMEOUT)
            if r.status_code==200: return r.json()
            if r.status_code==429: time.sleep(60)
        except Exception as e: log.error("VT: %s", e)
        return {}

    @classmethod
    def _parse(cls, d: dict) -> dict:
        a = d.get("data",{}).get("attributes",{})
        s = a.get("last_analysis_stats",{})
        return {"malicious":s.get("malicious",0),"suspicious":s.get("suspicious",0),
                "total":sum(s.values()) if s else 0,"reputation":a.get("reputation",0),
                "country":a.get("country",""),"as_owner":a.get("as_owner","")}

    @classmethod
    def check_ip(cls, ip):
        d = cls._get("ip_addresses/{}".format(ip))
        if not d: return {}
        r = cls._parse(d); r.update({"type":"ip","value":ip})
        log.info("VT %s: mal=%d rep=%d country=%s", ip, r["malicious"], r["reputation"], r["country"])
        return r

    @classmethod
    def check_hash(cls, h):
        d = cls._get("files/{}".format(h))
        if not d: return {}
        r = cls._parse(d); a = d.get("data",{}).get("attributes",{})
        r.update({"type":"hash","value":h,"file_name":a.get("meaningful_name","")})
        return r

    @classmethod
    def check_domain(cls, dom):
        d = cls._get("domains/{}".format(dom))
        if not d: return {}
        r = cls._parse(d); r.update({"type":"domain","value":dom}); return r

    @classmethod
    def is_malicious(cls, r):
        if not r: return False
        return (r.get("malicious",0)>=cfg.VT_MIN_DETECTIONS or
                r.get("suspicious",0)>=cfg.VT_MIN_DETECTIONS*2 or
                r.get("reputation",0)<=-10)

    @classmethod
    def verdict(cls, r):
        if not r: return "⚪ Inconnu"
        m,s,t,rep = r.get("malicious",0),r.get("suspicious",0),r.get("total",0),r.get("reputation",0)
        if cls.is_malicious(r): return "🔴 MALVEILLANT ({}/{} rep={})".format(m,t,rep)
        if s>0: return "🟡 Suspect ({}/{})".format(s,t)
        if t>0: return "🟢 Propre (0/{})".format(t)
        return "⚪ Inconnu"


thehive = TheHiveApi(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY)

def _hdr():
    return {"Authorization":"Bearer {}".format(cfg.THEHIVE_APIKEY),
            "Content-Type":"application/json","Accept":"application/json"}


class StateManager:
    def __init__(self):
        self.path = Path(cfg.STATE_FILE); self._s = self._load(); self._lock = threading.Lock()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path) as f: return json.load(f)
            except Exception: pass
        return {"processed_alerts":[],"processed_cases":[]}

    def _save(self):
        try:
            with open(self.path,"w") as f: json.dump(self._s,f,indent=2)
        except Exception as e: log.error("State: %s", e)

    def is_done(self, eid, etype="alert"):
        with self._lock: return eid in self._s.get("processed_{}s".format(etype),[])

    def mark_done(self, eid, etype="alert"):
        with self._lock:
            k = "processed_{}s".format(etype)
            if k not in self._s: self._s[k] = []
            if eid not in self._s[k]:
                self._s[k].append(eid); self._s[k] = self._s[k][-20000:]; self._save()

state = StateManager()


class TH:
    """TheHive — toutes les opérations avec retry. Compatible v4 et v5."""

    @staticmethod
    def _post(path, data, retries=3):
        for i in range(1, retries+1):
            try:
                r = requests.post("{}{}".format(cfg.THEHIVE_URL,path),
                                  headers=_hdr(), json=data, timeout=20)
                if r.status_code in (200,201): return r.json()
                log.warning("POST %s HTTP %d [%d/%d]", path, r.status_code, i, retries)
            except Exception as e: log.warning("POST %s [%d/%d]: %s", path, i, retries, e)
            if i<retries: time.sleep(2*i)
        return None

    @staticmethod
    def _get(path):
        try:
            r = requests.get("{}{}".format(cfg.THEHIVE_URL,path), headers=_hdr(), timeout=15)
            if r.status_code==200: return r.json()
        except Exception as e: log.error("GET %s: %s", path, e)
        return None

    @staticmethod
    def _patch(path, data):
        try: requests.patch("{}{}".format(cfg.THEHIVE_URL,path), headers=_hdr(), json=data, timeout=10)
        except Exception as e: log.error("PATCH %s: %s", path, e)

    @classmethod
    def fetch_new_alerts(cls):
        r = cls._post("/api/v1/query?name=list-alerts",{"query":[
            {"_name":"listAlert"},
            {"_name":"filter","_in":{"_field":"status","_values":["New","Updated"]}},
            {"_name":"sort","_fields":[{"_createdAt":"desc"}]},
            {"_name":"page","from":0,"to":200}]})
        if r and isinstance(r,list): return r
        try:
            r2 = thehive.find_alerts(query={"_in":{"status":["New","Updated"]}},
                                     sort=["-createdAt"], range="0-200")
            if r2.status_code==200: return r2.json()
        except Exception as e: log.error("fetch_alerts: %s", e)
        return []

    @classmethod
    def promote(cls, alert_id: str, title: str, alert_data: dict):
        """Promotion alerte→cas GARANTIE (3 méthodes). Compatible v4/v5."""
        # Méthode 1: endpoint v5 natif
        c = cls._post("/api/v1/alert/{}/case".format(alert_id), {})
        if c and _get_id(c):
            log.info("Promotion v5 OK: alerte %s → cas #%s", alert_id, c.get("number", c.get("caseId","?")))
            return c
        # Méthode 2: API v4
        try:
            r = thehive.promote_alert_to_case(alert_id)
            if r and r.status_code in (200,201):
                log.info("Promotion v4 OK: alerte %s", alert_id)
                return r.json()
        except Exception as e: log.warning("Promote v4: %s", e)
        # Méthode 3: création manuelle
        log.warning("Création cas manuelle: alerte %s", alert_id)
        c = cls._post("/api/v1/case",{
            "title":       title,
            "description": alert_data.get("description","Promu depuis alerte Splunk\nAlert: {}".format(alert_id)),
            "severity":    alert_data.get("severity",2),
            "tags":        list(set(alert_data.get("tags",[])+["auto-promoted","from-splunk"])),
            "tlp":2,"pap":2,"status":"Open"})
        if c and _get_id(c):
            log.info("Cas manuel #%s créé", c.get("number", c.get("caseId","?")))
            try:
                requests.post("{}/api/v1/alert/{}/merge/{}".format(
                    cfg.THEHIVE_URL, alert_id, _get_id(c)), headers=_hdr(), timeout=10)
            except Exception: pass
            return c
        log.error("ÉCHEC TOTAL: impossible de créer le cas pour alerte %s", alert_id)
        return None

    @classmethod
    def get_alert_obs(cls, alert_id, alert_data):
        r = cls._get("/api/v1/alert/{}/observable".format(alert_id))
        if r and isinstance(r,list): return r
        return alert_data.get("artifacts", alert_data.get("observables",[]))

    @classmethod
    def add_comment(cls, case_id, msg):
        r = cls._post("/api/v1/case/{}/comment".format(case_id), {"message":msg})
        if not r:
            try: thehive.create_case_task_log(case_id, CaseTaskLog(message=msg))
            except Exception as e: log.error("comment: %s", e)

    @classmethod
    def add_tag(cls, case_id, tag):
        """Ajoute un tag via API v1 directement (plus fiable que thehive4py)."""
        try:
            # Récupérer les tags existants via API v1
            r = requests.get("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                             headers=_hdr(), timeout=10)
            if r.status_code == 200:
                existing = r.json().get("tags",[])
                if tag not in existing:
                    requests.patch("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                                   headers=_hdr(), json={"tags": existing+[tag]}, timeout=10)
        except Exception as e: log.error("add_tag: %s", e)

    @classmethod
    def update_status(cls, case_id, status):
        try:
            requests.patch("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                           headers=_hdr(), json={"status": status}, timeout=10)
        except Exception as e: log.error("update_status: %s", e)

    @classmethod
    def mark_inprogress(cls, alert_id):
        cls._patch("/api/v1/alert/{}".format(alert_id), {"status":"InProgress"})


class MISPClient:
    @staticmethod
    def _req(path, data=None):
        hdrs = {"Authorization":cfg.MISP_APIKEY,"Content-Type":"application/json","Accept":"application/json"}
        try:
            fn = requests.post if data else requests.get
            kw = {"headers":hdrs,"timeout":10,"verify":False}
            if data: kw["json"] = data
            r = fn("{}{}".format(cfg.MISP_URL,path), **kw)
            return r.json() if r.status_code in (200,201) else None
        except Exception as e: log.error("MISP: %s", e); return None

    @classmethod
    def lookup(cls, val, itype):
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY: return False
        try:
            r = cls._req("/attributes/restSearch", {"value":val,"type":itype,"limit":1})
            if r and r.get("response",{}).get("Attribute",[]):
                log.info("MISP hit: %s", val); return True
        except Exception as e: log.error("MISP lookup: %s", e)
        return False

    @classmethod
    def push(cls, val, itype, case_id=""):
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY: return False
        t = {"ip":"ip-dst","domain":"domain","hash":"md5","url":"url","other":"text"}
        try:
            r = cls._req("/events",{"Event":{
                "info":"SOC Auto {} {}".format(case_id,val),
                "distribution":0,"threat_level_id":1,"analysis":1,
                "Attribute":[{"type":t.get(itype,"text"),"category":"Network activity",
                              "value":val,"to_ids":True}]}})
            if r: log.info("MISP push OK: %s", val); return True
        except Exception as e: log.error("MISP push: %s", e)
        return False


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError: return False

def extract_ips(alert_data: dict, observables: list) -> list:
    ips = []
    for obs in observables:
        if obs.get("dataType") == "ip":
            ip = obs.get("data","").strip()
            if ip and ip not in ips: ips.append(ip)
    for art in alert_data.get("artifacts",[]):
        if art.get("dataType") == "ip":
            ip = art.get("data","").strip()
            if ip and ip not in ips: ips.append(ip)
    if not ips:
        found = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', alert_data.get("description",""))
        for ip in found:
            try:
                if all(0<=int(p)<=255 for p in ip.split(".")) and ip not in ips: ips.append(ip)
            except Exception: pass
    return ips


class AlertProcessor:
    def __init__(self):
        self.cortex_ok = self._get_cortex_analyzers()
        log.info("Cortex: %d analyseurs", len(self.cortex_ok))

    def _get_cortex_analyzers(self):
        if not cfg.CORTEX_APIKEY: return []
        try:
            r = requests.get("{}/api/analyzer".format(cfg.CORTEX_URL),
                             headers={"Authorization":"Bearer {}".format(cfg.CORTEX_APIKEY),
                                      "Accept":"application/json"}, timeout=10)
            if r.status_code==200: return [a["name"] for a in r.json()]
        except Exception as e: log.warning("Cortex analyzers: %s", e)
        return []

    def process(self, alert_data: dict):
        # FIX PRINCIPAL: TheHive v5 utilise "_id" et non "id"
        alert_id = _get_id(alert_data)
        title    = alert_data.get("title", alert_data.get("name","Alerte Splunk"))
        severity = alert_data.get("severity", 2)
        tags     = alert_data.get("tags",[])

        log.info("═══ ALERTE %s [sev=%d]: %s", alert_id, severity, title[:50])

        obs  = TH.get_alert_obs(alert_id, alert_data)
        ips  = extract_ips(alert_data, obs)
        log.info("IPs trouvées: %s", ips or "aucune")

        is_bf = (any(t in tags for t in cfg.BRUTE_FORCE_TAGS) or
                 any(k in title.lower() for k in ["brute","ssh","failed","auth","force","login"]))

        vt_results = {}
        misp_hits  = []
        blocked    = []
        summary    = []

        for ip in ips:
            internal = is_internal(ip)

            if not internal and cfg.VT_ENABLED and cfg.VT_APIKEY:
                vt = VTClient.check_ip(ip)
                if vt: vt_results[ip]=vt; summary.append("VT {} → {}".format(ip,VTClient.verdict(vt)))
                time.sleep(0.3)
            else:
                summary.append("IP {} ({}) — VT ignoré".format(ip,"interne" if internal else "pub sans clé"))

            if cfg.MISP_ENABLED and MISPClient.lookup(ip,"ip"):
                misp_hits.append(ip); summary.append("MISP HIT: {}".format(ip))

            should_block = (is_bf or
                           (ip in vt_results and VTClient.is_malicious(vt_results[ip])) or
                           ip in misp_hits)

            if should_block and not block_manager.is_blocked(ip):
                reasons = []
                if is_bf: reasons.append("brute force SSH/auth")
                if ip in vt_results and VTClient.is_malicious(vt_results[ip]):
                    reasons.append("VT {}/{}".format(vt_results[ip].get("malicious",0),
                                                     vt_results[ip].get("total",0)))
                if ip in misp_hits: reasons.append("MISP hit")
                r_str = " | ".join(reasons) or "menace"

                res = block_manager.block(ip, r_str)
                if res.get("success"):
                    blocked.append(ip)
                    summary.append("🚫 BLOQUÉ {} min: {} → expire {}".format(
                        cfg.BLOCK_DURATION_MIN, ip, res["expires_at"]))
                    log.warning("🚫 BLOQUÉ: %s (%s) expire %s", ip, r_str, res["expires_at"])
                elif res.get("dry_run"):
                    summary.append("⚠️ SIMULATION: {} serait bloquée ({})".format(ip,r_str))
                elif res.get("already_blocked"):
                    summary.append("⏳ Déjà bloquée: {} expire {}".format(ip,res.get("expires_at","?")))

        # CRÉER LE CAS THEHIVE — GARANTI
        log.info("Création cas TheHive pour alerte %s...", alert_id)
        case     = TH.promote(alert_id, title, alert_data)
        case_id  = _get_id(case) if case else ""
        case_num = case.get("number", case.get("caseId","?")) if case else "ERREUR"

        if case and case_id:
            log.info("✅ Cas #%s créé (id=%s)", case_num, case_id)
            TH.mark_inprogress(alert_id)
            Notifier.case_created(case_num, title, ips[0] if ips else "N/A", case_id)

            if is_bf:     TH.add_tag(case_id,"brute_force")
            if blocked:   TH.add_tag(case_id,"ip-blocked")
            if misp_hits: TH.add_tag(case_id,"misp-hit")
            for ip in ips:
                if ip in vt_results and VTClient.is_malicious(vt_results[ip]):
                    TH.add_tag(case_id,"vt-malicious")
            TH.add_tag(case_id,"auto-processed")

            for ip in ips:
                if ip in vt_results and VTClient.is_malicious(vt_results[ip]) and ip not in misp_hits:
                    MISPClient.push(ip,"ip",case_id=str(case_id))

            self._comment(case_id,case_num,alert_id,ips,summary,blocked,misp_hits,vt_results,is_bf)

            if blocked or misp_hits or any(VTClient.is_malicious(v) for v in vt_results.values()):
                TH.update_status(case_id,"InProgress")
        else:
            log.error("❌ ÉCHEC création cas pour alerte %s", alert_id)
            Notifier.telegram("❌ <b>CAS NON CRÉÉ</b>\n{}\n{}\nVérifier logs!".format(title[:60],alert_id))

        for ip in blocked:
            info = block_manager._blocked.get(ip,{})
            exp  = (info.get("blocked_at",datetime.now())+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                    ).strftime("%H:%M:%S") if info else "?"
            Notifier.block_alert(ip, info.get("reason","brute force"), exp,
                                 case_num, title, vt_results.get(ip,{}))

        log.info("═══ DONE alerte %s → cas #%s | IPs=%s | bloquées=%s",
                 alert_id, case_num, ips, blocked)

    def _comment(self,case_id,case_num,alert_id,ips,summary,blocked,misp_hits,vt_results,is_bf):
        lines=[
            "## 🤖 Rapport SOC Pipeline v8.1.0",
            "","**Date**: {} | **Alerte**: `{}`".format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),alert_id),
            "**Brute force**: **{}**".format("Oui 🔴" if is_bf else "Non 🟢"),"",
        ]
        if ips:
            lines+=["### 🌐 IPs","| IP | Interne | VT | Bloquée |","|---|---|---|---|"]
            for ip in ips:
                vt = vt_results.get(ip,{})
                lines.append("| `{}` | {} | {} | {} |".format(
                    ip,"✅" if is_internal(ip) else "Non",
                    VTClient.verdict(vt) if vt else "N/A",
                    "🚫 {} min".format(cfg.BLOCK_DURATION_MIN) if ip in blocked else "Non"))
        if blocked:
            lines+=["","### 🚫 Blocages actifs ({} min)".format(cfg.BLOCK_DURATION_MIN),""]
            for ip in blocked:
                info = block_manager._blocked.get(ip,{})
                exp  = (info.get("blocked_at",datetime.now())+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                        ).strftime("%H:%M:%S") if info else "?"
                lines.append("- `{}` → expire {} | `python start.py unblock {}`".format(ip,exp,ip))
        if summary:
            lines+=["","### 📊 Actions",""]
            lines+=["- {}".format(s) for s in summary]
        if misp_hits:
            lines+=["","### 🌐 MISP hits",""]
            lines+=["- `{}`".format(ip) for ip in misp_hits]
        lines+=["","---","> *SOC Pipeline v8.1.0 — Rachad Lab*"]
        TH.add_comment(case_id, "\n".join(lines))


class Poller:
    def __init__(self): self.proc = AlertProcessor()

    def run_once(self):
        alerts = TH.fetch_new_alerts()
        log.debug("Poll: %d alertes", len(alerts))
        n = 0
        for a in alerts:
            # FIX: TheHive v5 utilise "_id" et non "id"
            aid = _get_id(a)
            if not aid or state.is_done(aid,"alert"): continue
            state.mark_done(aid,"alert"); n+=1
            try: self.proc.process(a)
            except Exception as e: log.exception("process %s: %s", aid, e)
        if n: log.info("Cycle: %d alertes traitées", n)

    def run(self):
        mode = "ACTIF (internes+ext)" if cfg.ACTIVE_RESPONSE else "SIMULATION (ACTIVE_RESPONSE=false)"
        print("")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  SOC Pipeline — Service B  v8.1.0  ZERO PITIÉ           ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  TheHive  : {}".format(cfg.THEHIVE_URL).ljust(57)+"║")
        print("║  VT       : {}".format("Actif ✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "VT_APIKEY manquante ⚠️").ljust(57)+"║")
        print("║  Blocage  : {}".format(mode).ljust(57)+"║")
        print("║  Durée    : {} minutes → déblocage automatique".format(cfg.BLOCK_DURATION_MIN).ljust(57)+"║")
        print("║  Poll     : toutes les {}s".format(cfg.POLL_INTERVAL_SEC).ljust(57)+"║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  RÈGLE: toute IP brute force → BLOQUÉE {} min          ║".format(cfg.BLOCK_DURATION_MIN))
        print("║  IPs internes ET externes bloquées sans exception       ║")
        print("╚══════════════════════════════════════════════════════════╝")
        if not cfg.ACTIVE_RESPONSE:
            print("\n  ⚠️  SIMULATION — ajouter ACTIVE_RESPONSE=true dans .env")
            print("  ⚠️  Sur Linux: sudo python3 service_thehive_responder.py\n")
        Notifier.telegram(
            "🚀 <b>Service B v8.1.0 — ZERO PITIÉ</b>\n\n"
            "🦠 VT: {}\n🔬 Cortex: {} analyseurs\n🌐 MISP: {}\n"
            "🚫 Blocage: {} — {} min\n📡 Poll: {}s".format(
                "✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "⚠️ clé manquante",
                len(self.proc.cortex_ok),
                "✅" if cfg.MISP_ENABLED else "off",
                mode, cfg.BLOCK_DURATION_MIN, cfg.POLL_INTERVAL_SEC))
        while True:
            try: self.run_once()
            except KeyboardInterrupt: break
            except Exception as e: log.exception("Poll: %s", e)
            time.sleep(cfg.POLL_INTERVAL_SEC)


def cli_unblock(ip):
    if block_manager.unblock(ip):
        print("✅ {} débloquée".format(ip))
        Notifier.telegram("✅ <b>Débloquée manuellement</b>: <code>{}</code>".format(ip))
    else: print("⚠️ {} non bloquée".format(ip))

def cli_list():
    bl = block_manager.list_blocked()
    if not bl: print("Aucune IP bloquée."); return
    print("\nIPs bloquées:")
    for b in bl: print("  {} | expire {} | reste {}min | {}".format(
        b["ip"],b["expires_at"],b["remaining_min"],b["reason"]))


if __name__ == "__main__":
    if len(sys.argv)>=2:
        cmd = sys.argv[1].lower()
        if cmd=="unblock" and len(sys.argv)>=3: cli_unblock(sys.argv[2]); sys.exit(0)
        if cmd in ("list","status","ls"): cli_list(); sys.exit(0)
    if cfg.ACTIVE_RESPONSE:
        log.warning("RÉPONSE ACTIVE — toutes les IPs brute force seront bloquées")
    else:
        log.warning("SIMULATION — ACTIVE_RESPONSE=false")
    Poller().run()
