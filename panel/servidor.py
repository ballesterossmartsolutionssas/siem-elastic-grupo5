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
INVESTIGACIONES = "siem-investigaciones"  # R8.7 y R8.8: cada investigación guiada que se cierra en el panel
KIBANA = "http://kibana:5601"
TRABAJOS = {}
# Las reglas EQL de secuencia guardan una alerta "building block" por cada evento de la secuencia,
# además de la alerta real. Esas no se cuentan (Kibana tampoco las muestra por defecto).
SIN_BB = [{"exists": {"field": "kibana.alert.building_block_type"}}]


def q_alertas(*filtros):
    return {"bool": {"filter": list(filtros), "must_not": SIN_BB}}


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
    estado = intenta(lambda: es("/_cluster/health"), {"status": "?", "number_of_nodes": 0})
    total = intenta(lambda: es("/logs-siem.*/_count")["count"], 0)
    errores = intenta(lambda: es("/logs-siem.errores-*/_count")["count"], 0)
    alertas_hoy = intenta(lambda: es(f"/{ALERTAS}/_count",
                                     {"query": q_alertas({"range": {"@timestamp": {"gte": "now/d"}}})})["count"], 0)

    def sev():
        b = es(f"/{ALERTAS}/_search", {"size": 0, "query": q_alertas({"range": {"@timestamp": {"gte": "now/d"}}}),
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

    r = {
        "cluster": estado.get("status"), "nodos": estado.get("number_of_nodes"),
        "eventos": total, "rechazados": errores,
        "parseo": round((total - errores) * 100 / total, 2) if total else 0,
        "alertas_hoy": alertas_hoy,
        "severidades": intenta(sev, {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        "serie": intenta(serie, []),
        "fuentes": intenta(fuentes, []),
        "top_ips": intenta(top_ips, []),
        "alertas": agrupar_alertas("now-24h"),
    }
    r["salud"] = salud()
    r["investigaciones"] = investigaciones()
    r["requisitos"] = cumplimiento(r, r["salud"], r["investigaciones"])
    return r


def alertas(desde):
    def q():
        r = es(f"/{ALERTAS}/_search", {"size": 15, "sort": [{"@timestamp": "desc"}],
               "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "source.ip", "user.name"],
               "query": q_alertas({"range": {"@timestamp": {"gte": desde}}})})
        salida = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            salida.append({"hora": s["@timestamp"],
                           "regla": campo(s, "kibana.alert.rule.name", "kibana", "alert", "rule", "name"),
                           "severidad": campo(s, "kibana.alert.severity", "kibana", "alert", "severity"),
                           "ip": campo(s, "source.ip", "source", "ip"),
                           "usuario": campo(s, "user.name", "user", "name")})
        return salida
    return intenta(q, [])


def logs(desde):
    """Stream de eventos ya parseados, el más reciente primero (tail -f del SIEM)."""
    def q():
        r = es("/logs-siem.*/_search", {"size": 45, "sort": [{"@timestamp": "desc"}],
               "_source": ["@timestamp", "data_stream.dataset", "source.ip", "source.geo.country_name",
                           "event.action", "event.outcome", "http.response.status_code",
                           "url.original", "message", "user.name", "tags"],
               "query": {"range": {"@timestamp": {"gte": desde}}}})
        out = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            tags = campo(s, "tags") or []
            out.append({
                "hora": s["@timestamp"],
                "fuente": (campo(s, "data_stream.dataset", "data_stream", "dataset") or "").replace("siem.", ""),
                "ip": campo(s, "source.ip", "source", "ip"),
                "pais": campo(s, "source.geo.country_name", "source", "geo", "country_name"),
                "accion": campo(s, "event.action", "event", "action"),
                "outcome": campo(s, "event.outcome", "event", "outcome"),
                "codigo": campo(s, "http.response.status_code", "http", "response", "status_code"),
                "usuario": campo(s, "user.name", "user", "name"),
                "url": campo(s, "url.original", "url", "original"),
                "msg": (campo(s, "message") or ""),
                "interna": "red_interna" in tags if isinstance(tags, list) else False,
            })
        return out
    return intenta(q, [])


def investigar_ip(ip):
    """Qué hizo una IP en 24 h: eventos, país, acciones, usuarios, puertos y qué reglas disparó."""
    def q():
        base = {"bool": {"filter": [{"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": "now-24h"}}}]}}
        agg = es("/logs-siem.*/_search", {"size": 0, "query": base, "aggs": {
            "acciones": {"terms": {"field": "event.action", "size": 8}},
            "fuentes": {"terms": {"field": "data_stream.dataset", "size": 6}},
            "pais": {"terms": {"field": "source.geo.country_name", "size": 1}},
            "primero": {"min": {"field": "@timestamp"}},
            "ultimo": {"max": {"field": "@timestamp"}},
            "ssh": {"filter": {"term": {"event.action": "ssh_login"}}, "aggs": {
                "usuarios": {"terms": {"field": "user.name", "size": 6},
                             "aggs": {"r": {"terms": {"field": "event.outcome", "size": 2}}}}}},
            "puertos": {"cardinality": {"field": "destination.port"}},
            "sqli": {"filter": {"term": {"siem.sqli": True}}},
            "sensibles": {"filter": {"term": {"siem.ruta_sensible": True}}},
            "e404": {"filter": {"term": {"http.response.status_code": 404}}},
            "ua": {"filter": {"term": {"siem.herramienta_ataque": True}},
                   "aggs": {"t": {"terms": {"field": "user_agent.original", "size": 1}}}},
        }})
        a = agg["aggregations"]
        total = agg["hits"]["total"]["value"]
        reglas = es(f"/{ALERTAS}/_search", {"size": 0,
                    "query": q_alertas({"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": "now-24h"}}}),
                    "aggs": {"r": {"terms": {"field": "kibana.alert.rule.name", "size": 10},
                                   "aggs": {"s": {"terms": {"field": "kibana.alert.severity", "size": 1}}}}}})
        usuarios = []
        for u in a["ssh"]["usuarios"]["buckets"]:
            r = {x["key"]: x["doc_count"] for x in u["r"]["buckets"]}
            usuarios.append({"usuario": u["key"], "fallos": r.get("failure", 0), "exitos": r.get("success", 0)})
        exitos = sum(u["exitos"] for u in usuarios)
        fallos = sum(u["fallos"] for u in usuarios)
        sqli = a["sqli"]["doc_count"]
        # Playbook y severidad sugeridos con las tablas de clasificación de docs/playbooks
        if fallos or exitos:
            playbook = "fuerza-bruta-ssh"
            sugerida = "Crítica" if exitos and fallos >= 5 else ("Media" if fallos else "Baja")
        else:
            playbook = "inyeccion-sql"
            sugerida = "Alta" if sqli else "Media"
        ua = a["ua"]["t"]["buckets"]
        return {
            "ip": ip, "total": total,
            "pais": a["pais"]["buckets"][0]["key"] if a["pais"]["buckets"] else None,
            "primero": a["primero"].get("value_as_string"), "ultimo": a["ultimo"].get("value_as_string"),
            "acciones": [{"k": x["key"], "n": x["doc_count"]} for x in a["acciones"]["buckets"]],
            "fuentes": [{"k": x["key"].replace("siem.", ""), "n": x["doc_count"]} for x in a["fuentes"]["buckets"]],
            "reglas": [{"k": x["key"], "n": x["doc_count"],
                        "sev": x["s"]["buckets"][0]["key"] if x["s"]["buckets"] else None}
                       for x in reglas["aggregations"]["r"]["buckets"]],
            "usuarios": usuarios, "fallos": fallos, "exitos": exitos,
            "puertos": a["puertos"]["value"], "sqli": sqli,
            "sensibles": a["sensibles"]["doc_count"], "e404": a["e404"]["doc_count"],
            "herramienta": ua[0]["key"] if ua else None,
            "playbook": playbook, "sugerida": sugerida,
        }
    return intenta(q, {"ip": ip, "total": 0, "acciones": [], "fuentes": [], "reglas": [], "usuarios": []})


def agrupar_alertas(desde="now-24h"):
    """Alertas agrupadas por regla e IP: una fila por incidente, no una por evento."""
    def q():
        r = es(f"/{ALERTAS}/_search", {"size": 0, "query": q_alertas({"range": {"@timestamp": {"gte": desde}}}),
               "aggs": {"g": {"multi_terms": {"terms": [{"field": "kibana.alert.rule.name"},
                                                        {"field": "source.ip", "missing": "0.0.0.0"}],
                                              "size": 40, "order": {"ultima": "desc"}},
                              "aggs": {"ultima": {"max": {"field": "@timestamp"}},
                                       "sev": {"terms": {"field": "kibana.alert.severity", "size": 1}},
                                       "usuario": {"terms": {"field": "user.name", "size": 1}}}}}})
        orden = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        out = []
        for b in r["aggregations"]["g"]["buckets"]:
            regla, ip = b["key"]
            out.append({"regla": regla, "ip": None if ip == "0.0.0.0" else ip, "n": b["doc_count"],
                        "hora": b["ultima"]["value_as_string"],
                        "severidad": b["sev"]["buckets"][0]["key"] if b["sev"]["buckets"] else "low",
                        "usuario": b["usuario"]["buckets"][0]["key"] if b["usuario"]["buckets"] else None})
        # Las más graves arriba; dentro de cada severidad, la más reciente primero
        out.sort(key=lambda x: x["hora"], reverse=True)
        out.sort(key=lambda x: orden.get(x["severidad"], 9))
        return out[:14]
    return intenta(q, [])


def salud():
    """Salud general del sistema: nodos, ILM, retraso de la ingesta y volumen anómalo."""
    def nodos():
        r = es("/_nodes/stats/jvm,fs,os")
        out = []
        for n in r["nodes"].values():
            fs = n["fs"]["total"]
            out.append({"nombre": n["name"], "heap": n["jvm"]["mem"]["heap_used_percent"],
                        "disco": round(100 - fs["available_in_bytes"] * 100 / fs["total_in_bytes"], 1),
                        "cpu": n["os"]["cpu"]["percent"]})
        return sorted(out, key=lambda x: x["nombre"])

    def ilm():
        r = es("/logs-siem.*/_ilm/explain?filter_path=indices.*.phase,indices.*.policy")
        fases, politicas = {}, set()
        for i in r.get("indices", {}).values():
            fases[i.get("phase", "?")] = fases.get(i.get("phase", "?"), 0) + 1
            politicas.add(i.get("policy"))
        return {"fases": fases, "politicas": sorted(p for p in politicas if p)}

    def ingesta():
        r = es("/logs-siem.*/_search", {"size": 0, "query": {"range": {"@timestamp": {"lte": "now"}}},
               "aggs": {"u": {"max": {"field": "@timestamp"}}}})
        ultimo = r["aggregations"]["u"].get("value")
        return round(datetime.now(timezone.utc).timestamp() - ultimo / 1000, 1) if ultimo else None

    def anomalia():
        # Volumen de los últimos 5 min contra la línea base de las últimas 24 h (z-score)
        r = es("/logs-siem.*/_search", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
               "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m", "min_doc_count": 0,
                                                 "extended_bounds": {"min": "now-24h", "max": "now"}}}}})
        cubos = [b["doc_count"] for b in r["aggregations"]["t"]["buckets"]]
        if len(cubos) < 12:
            return None
        base, actual = cubos[:-2], max(cubos[-2], cubos[-1])  # los 5 min recientes contra el resto del día
        media = sum(base) / len(base)
        desv = (sum((x - media) ** 2 for x in base) / len(base)) ** 0.5 or 1
        z = (actual - media) / desv
        return {"actual": actual, "media": round(media, 1), "z": round(z, 1), "anomalo": z >= 3}

    return {"nodos": intenta(nodos, []), "ilm": intenta(ilm, {"fases": {}, "politicas": []}),
            "retraso_s": intenta(ingesta, None), "volumen": intenta(anomalia, None)}


def kibana(ruta):
    req = urllib.request.Request(KIBANA + ruta, headers={"Authorization": AUTH, "kbn-xsrf": "panel"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def investigaciones():
    def q():
        r = es(f"/{INVESTIGACIONES}/_search", {"size": 10, "sort": [{"@timestamp": "desc"}]})
        return [h["_source"] for h in r["hits"]["hits"]]
    return intenta(q, [])


def reglas_por_nombre(desde):
    b = es(f"/{ALERTAS}/_search", {"size": 0, "query": q_alertas({"range": {"@timestamp": {"gte": desde}}}),
           "aggs": {"r": {"terms": {"field": "kibana.alert.rule.name", "size": 50}}}})
    return {x["key"] for x in b["aggregations"]["r"]["buckets"]}


ESCENARIOS = {"SIEM - Fuerza bruta SSH", "SIEM - Escaneo de puertos", "SIEM - Inyección SQL", "SIEM - Acceso a rutas sensibles"}


def cumplimiento(r, sal, inv):
    """Estado en vivo de cada requisito del enunciado, con la medición que lo respalda."""
    reglas_total = intenta(lambda: kibana("/api/detection_engine/rules/_find?per_page=100")["total"], None)
    disparadas = len(intenta(lambda: reglas_por_nombre("now-7d"), set()))
    hoy = intenta(lambda: reglas_por_nombre("now-24h"), set())
    fuentes = [f for f in r["fuentes"] if f["nombre"] != "errores" and f["n"] > 0]
    analistas = {i.get("analista") for i in inv}
    mejor = min((i["duracion_s"] for i in inv), default=None)
    return [
        {"id": "R8.1", "nombre": "Clúster e ILM",
         "ok": r["cluster"] == "green" and r["nodos"] == 3 and "siem-30d" in sal["ilm"]["politicas"],
         "dato": f'{r["nodos"]} nodos {r["cluster"]} · ILM siem-30d'},
        {"id": "R8.2", "nombre": "Fuentes", "ok": len(fuentes) >= 3, "dato": f"{len(fuentes)} fuentes con datos"},
        {"id": "R8.3", "nombre": "Parseo", "ok": r["parseo"] > 95, "dato": f'{r["parseo"]} % (mín. 95 %)'},
        {"id": "R8.4", "nombre": "Reglas", "ok": bool(reglas_total) and reglas_total >= 5 and disparadas >= 5,
         "dato": f"{reglas_total or '?'} activas · {disparadas} dispararon"},
        {"id": "R8.5", "nombre": "Ataques", "ok": len(ESCENARIOS & hoy) >= 3,
         "dato": f"{len(ESCENARIOS & hoy)} de 4 escenarios en 24 h"},
        {"id": "R8.6", "nombre": "Ejecutivo", "ok": True, "dato": "se actualiza cada minuto"},
        {"id": "R8.7", "nombre": "Investigación", "ok": mejor is not None and mejor < 300,
         "dato": f"mejor tiempo {mejor // 60}:{mejor % 60:02d} (máx. 5:00)" if mejor is not None else "sin investigaciones aún"},
        {"id": "R8.8", "nombre": "Playbooks", "ok": len(analistas) >= 2,
         "dato": f"{len(inv)} cerradas por {len(analistas)} persona{'s' if len(analistas) != 1 else ''}"},
    ]


def guardar_investigacion(d):
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "analista": str(d.get("analista", "")).strip()[:60] or "sin nombre",
        "ip": str(d.get("ip", ""))[:45],
        "playbook": str(d.get("playbook", ""))[:80],
        "clasificacion": str(d.get("clasificacion", ""))[:20],
        "duracion_s": int(d.get("duracion_s", 0)),
        "pasos_hechos": int(d.get("pasos_hechos", 0)),
        "pasos_total": int(d.get("pasos_total", 0)),
        "contencion": [str(x)[:120] for x in d.get("contencion", [])][:10],
        "notas": str(d.get("notas", ""))[:2000],
    }
    doc["dentro_de_5_min"] = doc["duracion_s"] < 300
    es(f"/{INVESTIGACIONES}/_doc?refresh=true", doc)
    return doc


def campo(s, plano, *ruta):
    """Lee un campo de _source esté aplanado ("a.b.c") o anidado ({a:{b:{c}}})."""
    if plano in s and s[plano] not in (None, ""):
        return s[plano]
    d = s
    for k in ruta:
        d = d.get(k, {}) if isinstance(d, dict) else {}
    return d if d not in ({}, "") else None


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
            if self.path.startswith("/api/logs"):
                desde = self.path.split("desde=", 1)[1] if "desde=" in self.path else "now-30m"
                return self.responder(200, logs(urllib.request.unquote(desde)))
            if self.path.startswith("/api/ip/"):
                return self.responder(200, investigar_ip(urllib.request.unquote(self.path.rsplit("/", 1)[1])))
            if self.path.startswith("/api/trabajo/"):
                t = TRABAJOS.get(self.path.rsplit("/", 1)[1])
                return self.responder(200 if t else 404, t or {"error": "no existe"})
            self.responder(404, {"error": "no existe"})
        except Exception as e:  # noqa: BLE001
            self.responder(503, {"error": str(e)})

    def do_POST(self):
        if self.path == "/api/investigacion":
            largo = int(self.headers.get("Content-Length", 0))
            try:
                datos = json.loads(self.rfile.read(largo) or b"{}")
                return self.responder(200, guardar_investigacion(datos))
            except Exception as e:  # noqa: BLE001
                return self.responder(503, {"error": str(e)})
        if self.path.startswith("/api/ataque/"):
            nombre = self.path.rsplit("/", 1)[1]
            if nombre not in ATAQUES:
                return self.responder(400, {"error": "ataque desconocido"})
            return self.responder(200, {"id": lanzar(nombre)})
        self.responder(404, {"error": "no existe"})


if __name__ == "__main__":
    print("Centro de control en http://localhost:8090", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8090), Manejador).serve_forever()
