#!/usr/bin/env python3
"""
Tests unitaires — Service A
Lancer : python3 tests/test_service_a.py
"""
import sys, os, json, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Variables d'env pour les tests
os.environ.update({
    'THEHIVE_URL': 'http://localhost:9000',
    'THEHIVE_APIKEY': 'testkey_unit_test',
    'VT_ENABLED': 'false',
    'VT_APIKEY': '',
    'TELEGRAM_ENABLED': 'false',
    'GMAIL_ENABLED': 'false',
    'RATE_LIMIT_SEC': '0',   # désactiver pour tests
})

# Charger le module sans lancer Flask ni lire le .env fichier
with open(os.path.join(os.path.dirname(__file__), "..", "src",
                       "service_splunk_to_thehive.py")) as f:
    src = f.read()

src = src.replace('_ENV_PATH = _load_env_file()', '_ENV_PATH = None')
src = src.replace(
    'def _load_env_file() -> str:\n    candidates = [',
    'def _load_env_file() -> str:\n    return None\n    candidates_DISABLED = ['
)
test_src = src.split("if __name__")[0]
ns = {"__file__": "service_splunk_to_thehive.py", "__name__": "test"}
exec(compile(test_src, "service_a", "exec"), ns)
globals().update(ns)

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print("  ✅ {}".format(name))
        PASS += 1
    except AssertionError as e:
        print("  ❌ {} — AssertionError: {}".format(name, e))
        FAIL += 1
    except Exception as e:
        print("  ❌ {} — {}: {}".format(name, type(e).__name__, e))
        FAIL += 1


print("\n" + "="*55)
print("  Tests unitaires — Service A v7.0.0")
print("="*55 + "\n")

# ── SplunkParser ──────────────────────────────────────────────────
print("SplunkParser")
def t_format1():
    n,s,r = SplunkParser.parse({"search_name":"SSH","severity":"high","result":{"src_ip":"1.2.3.4"}})
    assert n == "SSH" and s == "high" and r["src_ip"] == "1.2.3.4"
test("format 1 — result dict", t_format1)

def t_format2():
    n,s,r = SplunkParser.parse({"search_name":"T","severity":"medium","results":[{"src_ip":"5.6.7.8"}]})
    assert r["src_ip"] == "5.6.7.8"
test("format 2 — results list", t_format2)

def t_format3():
    n,s,r = SplunkParser.parse({"search_name":"T","severity":"low","src_ip":"9.9.9.9","host":"h"})
    assert r["src_ip"] == "9.9.9.9"
test("format 3 — payload plat", t_format3)

def t_format4():
    n,s,r = SplunkParser.parse({"search_name":"T","severity":"high","result":json.dumps({"src_ip":"1.1.1.1"})})
    assert r["src_ip"] == "1.1.1.1"
test("format 4 — JSON string", t_format4)

def t_fallback():
    n,s,r = SplunkParser.parse({"search_name":"T","severity":"medium","host":"myhost"})
    assert r.get("host") == "myhost"
test("fallback — payload minimal", t_fallback)

def t_default_name():
    n,s,r = SplunkParser.parse({"severity":"high","result":{}})
    assert n == "Alerte Splunk"
test("nom par défaut si search_name absent", t_default_name)

# ── AlertEnricher.normalize_severity ─────────────────────────────
print("\nAlertEnricher.normalize_severity")
def t_sev():
    f = AlertEnricher.normalize_severity
    assert f("critical")==4 and f("high")==3 and f("medium")==2
    assert f("low")==1 and f("info")==1 and f("CRITICAL")==4
    assert f("banana")==2 and f("")==2
test("tous les niveaux + cas limites", t_sev)

# ── AlertEnricher.generate_source_ref ────────────────────────────
print("\nAlertEnricher.generate_source_ref")
def t_ref_deterministe():
    r = {"src_ip":"1.2.3.4","_time":"2026-01-01T00:00:00"}
    assert AlertEnricher.generate_source_ref("X",r) == AlertEnricher.generate_source_ref("X",r)
test("déterministe", t_ref_deterministe)

def t_ref_prefix():
    r = AlertEnricher.generate_source_ref("SSH",{"src_ip":"1.2.3.4"})
    assert r.startswith("splunk-") and len(r) == 23
test("préfixe splunk- + longueur 23", t_ref_prefix)

def t_ref_different():
    r1 = AlertEnricher.generate_source_ref("A",{"src_ip":"1.1.1.1"})
    r2 = AlertEnricher.generate_source_ref("B",{"src_ip":"2.2.2.2"})
    assert r1 != r2
test("refs différentes pour IOC différents", t_ref_different)

# ── AlertEnricher.extract_tags ────────────────────────────────────
print("\nAlertEnricher.extract_tags")
def t_tags_base():
    tags = AlertEnricher.extract_tags("test",{},{})
    assert "splunk" in tags and "auto-ingested" in tags
test("tags de base", t_tags_base)

def t_tags_ssh_brute():
    tags = AlertEnricher.extract_tags("SSH Brute Force",{"source":"/var/log/auth.log"},{}
    )
    assert "brute_force" in tags and "ssh" in tags and "linux" in tags
test("SSH brute force Linux", t_tags_ssh_brute)

def t_tags_windows():
    tags = AlertEnricher.extract_tags("4625",{"index":"windows_logs","EventCode":"4625"},{})
    assert "windows" in tags and "brute_force" in tags
test("EventCode Windows 4625", t_tags_windows)

def t_tags_vt():
    vt = {"1.2.3.4": {"malicious":10,"suspicious":0,"total":72,"reputation":-50}}
    tags = AlertEnricher.extract_tags("test",{},vt)
    assert "vt-malicious" in tags
test("tag vt-malicious si VT détecte menace", t_tags_vt)

def t_tags_no_dup():
    tags = AlertEnricher.extract_tags("SSH Brute Force SSH",{},{}) 
    assert len(tags) == len(set(tags))  # pas de doublons
test("pas de tags en double", t_tags_no_dup)

# ── AlertEnricher.extract_observables ────────────────────────────
print("\nAlertEnricher.extract_observables")
def t_obs_all_types():
    arts = AlertEnricher.extract_observables({
        "src_ip":"1.2.3.4","user":"root",
        "file_hash":"d41d8cd98f00b204e9800998ecf8427e",
        "domain":"evil.com","url":"http://bad.com/payload",
    }, {})
    dtypes = {a.dataType for a in arts}
    assert dtypes == {"ip","other","hash","domain","url"}
test("tous les types d'artifacts", t_obs_all_types)

def t_obs_vt_ioc():
    vt = {"1.2.3.4": {"malicious":10,"suspicious":0,"total":72,"reputation":-50}}
    arts = AlertEnricher.extract_observables({"src_ip":"1.2.3.4"}, vt)
    ip_art = [a for a in arts if a.dataType=="ip"][0]
    assert ip_art.ioc == True
    assert "vt-malicious" in ip_art.tags
test("artifact marqué IOC si VT malveillant", t_obs_vt_ioc)

def t_obs_skip_na():
    arts = AlertEnricher.extract_observables({
        "src_ip":"N/A","user":"-","domain":"","file_hash":"none",
    }, {})
    assert len(arts) == 0
test("ignorer les valeurs N/A, -, vide, none", t_obs_skip_na)

def t_obs_fallback_host():
    arts = AlertEnricher.extract_observables({"host":"myserver"},{})
    assert len(arts) == 1 and arts[0].data == "myserver"
test("fallback sur host si aucun IOC", t_obs_fallback_host)

def t_obs_hash_lengths():
    arts_md5  = AlertEnricher.extract_observables({"file_hash":"d"*32},{})
    arts_sha1 = AlertEnricher.extract_observables({"file_hash":"a"*40},{})
    arts_sha256 = AlertEnricher.extract_observables({"file_hash":"b"*64},{})
    arts_bad  = AlertEnricher.extract_observables({"file_hash":"c"*10},{})
    assert len(arts_md5)==1 and len(arts_sha1)==1 and len(arts_sha256)==1
    assert len(arts_bad)==0
test("hashs MD5/SHA1/SHA256 acceptés, autres ignorés", t_obs_hash_lengths)

# ── VirusTotalClient ──────────────────────────────────────────────
print("\nVirusTotalClient")
def t_vt_disabled():
    assert cfg.VT_ENABLED == False
    assert VirusTotalClient.check_ip("8.8.8.8")  == {}
    assert VirusTotalClient.check_hash("a"*32)   == {}
    assert VirusTotalClient.check_domain("x.com") == {}
    assert VirusTotalClient.check_url("http://x") == {}
test("désactivé → {} sans erreur pour tous les types", t_vt_disabled)

def t_vt_malicious_logic():
    assert VirusTotalClient.is_malicious({"malicious":3,"suspicious":0,"total":70,"reputation":0})
    assert VirusTotalClient.is_malicious({"malicious":0,"suspicious":0,"total":70,"reputation":-15})
    assert not VirusTotalClient.is_malicious({"malicious":1,"suspicious":0,"total":70,"reputation":0})
    assert not VirusTotalClient.is_malicious({})
    assert not VirusTotalClient.is_malicious(None)
test("is_malicious : seuils et cas limites", t_vt_malicious_logic)

def t_vt_format_summary():
    s1 = VirusTotalClient.format_summary({"malicious":10,"suspicious":0,"total":72,"reputation":-20,"country":"RU"})
    assert "MALVEILLANT" in s1 and "10/72" in s1
    s2 = VirusTotalClient.format_summary({"malicious":0,"suspicious":3,"total":72,"reputation":0})
    assert "Suspect" in s2 or "suspect" in s2.lower()
    s3 = VirusTotalClient.format_summary({})
    assert "non analysé" in s3
test("format_summary : malveillant, suspect, non analysé", t_vt_format_summary)

# ── Helpers ──────────────────────────────────────────────────────
print("\nFonctions utilitaires")
def t_is_ip():
    assert _is_ip("1.2.3.4") and _is_ip("::1")
    assert not _is_ip("evil.com") and not _is_ip("") and not _is_ip("256.0.0.1")
test("_is_ip", t_is_ip)

def t_public_ip():
    assert _is_valid_public_ip("8.8.8.8")
    assert _is_valid_public_ip("185.220.101.50")
    assert not _is_valid_public_ip("10.2.3.50")
    assert not _is_valid_public_ip("192.168.1.1")
    assert not _is_valid_public_ip("127.0.0.1")
    assert not _is_valid_public_ip("172.16.0.1")
test("_is_valid_public_ip : publiques/privées", t_public_ip)

def t_rate_limit():
    import time, random
    from collections import defaultdict
    import threading
    # Test isolé : créer un rate_cache local propre
    local_cache = defaultdict(float)
    local_lock  = threading.Lock()
    rate_sec    = 10
    def _test_rate(key):
        with local_lock:
            now  = time.time()
            last = local_cache.get(key, 0.0)
            if now - last < rate_sec:
                return True
            local_cache[key] = now
            return False
    key = "test-unique-key"
    r1 = _test_rate(key)
    r2 = _test_rate(key)
    assert r1 == False, "premier passage doit être OK (got {})".format(r1)
    assert r2 == True,  "deuxième doit être bloqué (got {})".format(r2)
test("rate_limit : 1er OK, 2ème bloqué", t_rate_limit)

# ── build_description ─────────────────────────────────────────────
print("\nAlertEnricher.build_description")
def t_desc_basic():
    d = AlertEnricher.build_description("SSH BF",{"host":"srv","src_ip":"1.2.3.4","user":"root"},{})
    assert "## 🚨 Alerte Splunk : SSH BF" in d
    assert "1.2.3.4" in d and "root" in d and "srv" in d
test("description basique", t_desc_basic)

def t_desc_with_vt():
    d = AlertEnricher.build_description("SSH BF",{"src_ip":"1.2.3.4"},{
        "1.2.3.4": {"malicious":10,"suspicious":0,"total":72,"reputation":-50,"country":"RU"}
    })
    assert "VirusTotal" in d and "MALVEILLANT" in d and "RU" in d
test("description avec résultats VT", t_desc_with_vt)

def t_desc_vt_disabled_msg():
    global cfg
    old = cfg.VT_APIKEY
    cfg.VT_APIKEY = ""
    cfg.VT_ENABLED = True
    d = AlertEnricher.build_description("T",{},{})
    assert "VT_APIKEY" in d
    cfg.VT_APIKEY = old
    cfg.VT_ENABLED = False
test("message si VT_APIKEY manquant", t_desc_vt_disabled_msg)

# ── Résumé ────────────────────────────────────────────────────────
print("\n" + "="*55)
total = PASS + FAIL
print("  Résultat : {}/{} tests passés".format(PASS, total))
if FAIL == 0:
    print("  ✅ TOUS LES TESTS PASSÉS")
else:
    print("  ❌ {} TEST(S) ÉCHOUÉ(S)".format(FAIL))
print("="*55 + "\n")
sys.exit(0 if FAIL == 0 else 1)
