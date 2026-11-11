"""Centro de control del SIEM: página web para navegar, lanzar ataques y ver todo en vivo.

Corre en el contenedor `panel` (misma imagen que el atacante: trae nmap, hydra y sqlmap).
Abre http://localhost:8090
"""
import base64
import json
import os
import ssl
import subprocess
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ES = "https://es01:9200"
AUTH = "Basic " + base64.b64encode(f"elastic:{os.environ['ELASTIC_PASSWORD']}".encode()).decode()
CTX = ssl.create_default_context(cafile="/certs/ca/ca.crt")
AQUI = os.path.dirname(os.path.abspath(__file__))
ATAQUES = {"escaneo", "fuerza-bruta", "sqli", "rutas"}
ALERTAS = ".alerts-security.alerts-default"
TRABAJOS = {}


def es(ruta, cuerpo=None):
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(ES + ruta, data=datos, method="POST" if datos else "GET",
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
        return json.loads(r.read())


def intenta(fn, por_defecto):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - que el panel aguante aunque ES esté arrancando o un índice no exista
        return por_defecto


def resumen():
    salud = intenta(lambda: es("/_cluster/health"), {"status": "?", "number_of_nodes": 0})
    total = intenta(lambda: es("/logs-siem.*/_count")["count"], 0)
    errores = intenta(lambda: es("/logs-siem.errores-*/_count")["count"], 0)
    alertas_hoy = intenta(lambda: es(f"/{ALERTAS}/_count",
                                     {"query": {"range": {"@timestamp": {"gte": "now/d"}}}})["count"], 0)

    def sev():
        b = es(f"/{ALERTAS}/_search", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now/d"}}},
               "aggs": {"s": {"terms": {"field": "kibana.alert.severity", "size": 5}}}})
        d = {x["key"]: x["doc_count"] for x in b["aggregations"]["s"]["buckets"]}
        return {k: d.get(k, 0) for k in ("critical", "high", "medium", "low")}

    def serie():
        b = es("/logs-siem.*/_search", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-30m"}}},
               "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m",
                                                 "min_doc_count": 0, "extended_bounds": {"min": "now-30m", "max": "now"}}}}})
        return [x["doc_count"] for x in b["aggregations"]["t"]["buckets"]][-30:]

    def fuentes():
        b = es("/logs-siem.*/_search", {"size": 0,
               "aggs": {"f": {"terms": {"field": "data_stream.dataset", "size": 10}}}})
        return [{"nombre": x["key"].replace("siem.", ""), "n": x["doc_count"]} for x in b["aggregations"]["f"]["buckets"]]

    def top_ips():
        cuerpo = {
            "size": 0,
            "query": {"bool": {
                "must_not": [{"term": {"tags": "red_interna"}}],
                "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                # Solo tráfico sospechoso: así el "top" son atacantes reales, no las visitas normales.
                "minimum_should_match": 1,
                "should": [
                    {"bool": {"filter": [{"term": {"data_stream.dataset": "siem.auth"}},
                                         {"term": {"event.outcome": "failure"}}]}},
                    {"term": {"siem.sqli": True}},
                    {"term": {"siem.ruta_sensible": True}},
                    {"term": {"siem.herramienta_ataque": True}},
                    {"term": {"data_stream.dataset": "siem.red"}},
                    {"term": {"http.response.status_code": 404}},
                ],
            }},
            "aggs": {"ip": {
                "terms": {"field": "source.ip", "size": 6},
                "aggs": {"p": {"terms": {"field": "source.geo.country_name", "size": 1}}},
            }},
        }
        b = es("/logs-siem.*/_search", cuerpo)
        out = []
        for x in b["aggregations"]["ip"]["buckets"]:
            pais = x["p"]["buckets"][0]["key"] if x["p"]["buckets"] else "—"
            out.append({"ip": x["key"], "pais": pais, "n": x["doc_count"]})
        return out

    return {
        "cluster": salud.get("status"), "nodos": salud.get("number_of_nodes"),
        "eventos": total, "rechazados": errores,
        "parseo": round((total - errores) * 100 / total, 2) if total else 0,
        "alertas_hoy": alertas_hoy,
        "severidades": intenta(sev, {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        "serie": intenta(serie, []),
        "fuentes": intenta(fuentes, []),
        "top_ips": intenta(top_ips, []),
        "alertas": alertas("now-24h"),
    }


def alertas(desde):
    def q():
        r = es(f"/{ALERTAS}/_search", {"size": 15, "sort": [{"@timestamp": "desc"}],
               "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "source.ip", "user.name"],
               "query": {"range": {"@timestamp": {"gte": desde}}}})
        salida = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            g = lambda plano, *ruta: s.get(plano) or _anidado(s, ruta)  # noqa: E731
            salida.append({"hora": s["@timestamp"],
                           "regla": g("kibana.alert.rule.name", "kibana", "alert", "rule", "name"),
                           "severidad": g("kibana.alert.severity", "kibana", "alert", "severity"),
                           "ip": g("source.ip", "source", "ip"),
                           "usuario": g("user.name", "user", "name")})
        return salida
    return intenta(q, [])


def _anidado(d, ruta):
    for k in ruta:
        d = d.get(k, {}) if isinstance(d, dict) else {}
    return d or None


def lanzar(nombre):
    tid = uuid.uuid4().hex[:8]
    t = {"nombre": nombre, "inicio": datetime.now(timezone.utc).isoformat(), "salida": [], "terminado": False}
    TRABAJOS[tid] = t

    def correr():
        p = subprocess.Popen(["bash", f"/ataques/{nombre}.sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, env={**os.environ, "OBJETIVO": "victima"})
        for linea in p.stdout:
            if linea.startswith(("[ATTEMPT]", "[STATUS]")):
                continue
            t["salida"].append(linea.rstrip())
            t["salida"] = t["salida"][-200:]
        p.wait()
        t["terminado"] = True

    threading.Thread(target=correr, daemon=True).start()
    return tid


class Manejador(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def responder(self, codigo, cuerpo, tipo="application/json"):
        datos = cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo, ensure_ascii=False).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", tipo + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        try:
            if self.path in ("/", "/index.html"):
                with open(os.path.join(AQUI, "index.html"), "rb") as f:
                    return self.responder(200, f.read(), "text/html")
            if self.path == "/api/resumen":
                return self.responder(200, resumen())
            if self.path.startswith("/api/alertas"):
                desde = self.path.split("desde=", 1)[1] if "desde=" in self.path else "now-1h"
                return self.responder(200, alertas(urllib.request.unquote(desde)))
            if self.path.startswith("/api/trabajo/"):
                t = TRABAJOS.get(self.path.rsplit("/", 1)[1])
                return self.responder(200 if t else 404, t or {"error": "no existe"})
            self.responder(404, {"error": "no existe"})
        except Exception as e:  # noqa: BLE001
            self.responder(503, {"error": str(e)})

    def do_POST(self):
        if self.path.startswith("/api/ataque/"):
            nombre = self.path.rsplit("/", 1)[1]
            if nombre not in ATAQUES:
                return self.responder(400, {"error": "ataque desconocido"})
            return self.responder(200, {"id": lanzar(nombre)})
        self.responder(404, {"error": "no existe"})


if __name__ == "__main__":
    print("Centro de control en http://localhost:8090", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8090), Manejador).serve_forever()
