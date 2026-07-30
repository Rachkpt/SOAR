#!/usr/bin/env python3
"""Faux serveur TheHive 5 (+ connecteur Cortex) pour test d'integration."""
import json, re, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {
    "alerts": {}, "cases": {}, "observables": {}, "comments": [],
    "jobs": {}, "patches": [], "alert_seq": 0, "case_seq": 0,
    "obs_seq": 0, "job_seq": 0,
}
LOCK = threading.Lock()

ANALYZERS = [
    {"id": "AbuseIPDB_1_0", "name": "AbuseIPDB", "version": "1.0",
     "dataTypeList": ["ip"], "cortexIds": ["local"]},
    {"id": "MaxMind_GeoIP_4_0", "name": "MaxMind_GeoIP", "version": "4.0",
     "dataTypeList": ["ip"], "cortexIds": ["local"]},
    {"id": "VirusTotal_GetReport_3_1", "name": "VirusTotal_GetReport",
     "version": "3.1", "dataTypeList": ["ip", "hash", "domain", "url"],
     "cortexIds": ["local"]},
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except ValueError:
            return {}

    # ── GET ──────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]
        with LOCK:
            if path == "/api/v1/user/current":
                return self._send(200, {"login": "analyst@lab", "_id": "u1"})

            m = re.match(r"^/api/v1/alert/([^/]+)/observable$", path)
            if m:
                return self._send(200, STATE["alerts"].get(m.group(1), {}).get(
                    "observables", []))

            m = re.match(r"^/api/v1/case/([^/]+)$", path)
            if m:
                return self._send(200, STATE["cases"].get(m.group(1), {}))

            if path == "/api/connector/cortex/analyzer":
                return self._send(200, ANALYZERS)

            m = re.match(r"^/api/connector/cortex/analyzer/type/([^/]+)$", path)
            if m:
                dt = m.group(1)
                return self._send(200, [a for a in ANALYZERS
                                        if dt in a["dataTypeList"]])

            m = re.match(r"^/api/connector/cortex/job/([^/]+)$", path)
            if m:
                job = STATE["jobs"].get(m.group(1))
                if not job:
                    return self._send(404, {})
                return self._send(200, {
                    "id": m.group(1), "status": "Success",
                    "report": {"summary": {"taxonomies": [{
                        "level": "malicious", "namespace": job["analyzer"],
                        "predicate": "Records", "value": "42"}]}}})

        return self._send(404, {"error": "not found", "path": path})

    # ── POST ─────────────────────────────────────────────────────
    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._body()
        with LOCK:
            if path == "/api/v1/alert":
                STATE["alert_seq"] += 1
                aid = "alert-{}".format(STATE["alert_seq"])
                record = dict(body)
                record["_id"] = aid
                record["status"] = "New"
                record["observables"] = [
                    dict(o, _id="obs-a{}".format(i))
                    for i, o in enumerate(body.get("observables") or [])]
                STATE["alerts"][aid] = record
                return self._send(201, record)

            if path == "/api/v1/query":
                return self._send(200, list(STATE["alerts"].values()))

            m = re.match(r"^/api/v1/alert/([^/]+)/case$", path)
            if m:
                alert = STATE["alerts"].get(m.group(1), {})
                STATE["case_seq"] += 1
                cid = "case-{}".format(STATE["case_seq"])
                case = {"_id": cid, "number": STATE["case_seq"],
                        "title": alert.get("title", ""), "tags": [],
                        "severity": alert.get("severity", 2), "status": "New"}
                STATE["cases"][cid] = case
                return self._send(201, case)

            m = re.match(r"^/api/v1/case/([^/]+)/observable$", path)
            if m:
                STATE["obs_seq"] += 1
                oid = "obs-{}".format(STATE["obs_seq"])
                STATE["observables"][oid] = dict(body, case=m.group(1), _id=oid)
                return self._send(201, [STATE["observables"][oid]])

            m = re.match(r"^/api/v1/case/([^/]+)/comment$", path)
            if m:
                STATE["comments"].append({"case": m.group(1),
                                          "message": body.get("message", "")})
                return self._send(201, {"_id": "c{}".format(len(STATE["comments"]))})

            if path == "/api/connector/cortex/job":
                STATE["job_seq"] += 1
                jid = "job-{}".format(STATE["job_seq"])
                STATE["jobs"][jid] = {"analyzer": body.get("analyzerId"),
                                      "artifact": body.get("artifactId")}
                return self._send(201, {"cortexJobId": jid})

            if path == "/api/v1/case":
                STATE["case_seq"] += 1
                cid = "case-{}".format(STATE["case_seq"])
                STATE["cases"][cid] = dict(body, _id=cid, number=STATE["case_seq"])
                return self._send(201, STATE["cases"][cid])

        return self._send(404, {"error": "not found", "path": path})

    # ── PATCH ────────────────────────────────────────────────────
    def do_PATCH(self):
        path = self.path.split("?")[0]
        body = self._body()
        with LOCK:
            STATE["patches"].append({"path": path, "body": body})
            m = re.match(r"^/api/v1/case/([^/]+)$", path)
            if m and m.group(1) in STATE["cases"]:
                STATE["cases"][m.group(1)].update(body)
            m = re.match(r"^/api/v1/alert/([^/]+)$", path)
            if m and m.group(1) in STATE["alerts"]:
                STATE["alerts"][m.group(1)].update(body)
        return self._send(200, {"ok": True})


class DumpHandler(Handler):
    """Ajoute /__state pour inspecter le serveur depuis le test."""

    def do_GET(self):
        if self.path == "/__state":
            with LOCK:
                return self._send(200, STATE)
        return Handler.do_GET(self)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9911
    server = ThreadingHTTPServer(("127.0.0.1", port), DumpHandler)
    print("stub TheHive sur http://127.0.0.1:{}".format(port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
