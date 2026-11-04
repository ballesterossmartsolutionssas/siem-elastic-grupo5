"""Configura Kibana una vez que arranca: data views, reglas de detección y dashboards.

Corre en el contenedor kibana-setup (python:3.12-slim), sin librerías externas.
Es idempotente: si la regla ya existe, la actualiza.
"""
import base64
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

KIBANA = os.environ.get("KIBANA_URL", "http://kibana:5601")
AUTH = base64.b64encode(f"elastic:{os.environ['ELASTIC_PASSWORD']}".encode()).decode()


def llamar(metodo, ruta, cuerpo=None, headers=None, crudo=False):
    h = {"Authorization": f"Basic {AUTH}", "kbn-xsrf": "true"}
    datos = None
    if cuerpo is not None:
        if crudo:
            datos = cuerpo
        else:
            datos = json.dumps(cuerpo).encode()
            h["Content-Type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(KIBANA + ruta, data=datos, method=metodo, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            texto = r.read().decode() or "{}"
            return r.status, json.loads(texto)
    except urllib.error.HTTPError as e:
        texto = e.read().decode()
        try:
            return e.code, json.loads(texto)
        except ValueError:
            return e.code, {"error": texto}


def esperar_kibana():
    print("== Esperando a que Kibana esté disponible")
    for _ in range(120):
        try:
            code, estado = llamar("GET", "/api/status")
            if code == 200 and estado.get("status", {}).get("overall", {}).get("level") == "available":
                return
        except Exception:  # noqa: BLE001 - Kibana todavía no responde
            pass
        time.sleep(5)
    sys.exit("Kibana no quedó disponible")


def data_views():
    print("== Data views")
    vistas = [
        ("logs-siem", "logs-siem.*", "SIEM - todos los logs"),
        ("logs-siem-errores", "logs-siem.errores-*", "SIEM - logs rechazados"),
        ("siem-alertas", ".alerts-security.alerts-default", "SIEM - alertas"),
    ]
    for vid, patron, nombre in vistas:
        code, resp = llamar("POST", "/api/data_views/data_view", {
            "data_view": {"id": vid, "title": patron, "name": nombre, "timeFieldName": "@timestamp"},
            "override": True,
        })
        print(f"   {code}  {nombre}")
        if code >= 300:
            print("  ", resp)


def reglas():
    print("== Reglas de detección")
    errores = 0
    for archivo in sorted(glob.glob("/app/reglas/*.json")):
        with open(archivo, encoding="utf-8") as f:
            regla = json.load(f)
        code, resp = llamar("POST", "/api/detection_engine/rules", regla)
        if code == 409:  # ya existe: actualizarla
            code, resp = llamar("PUT", "/api/detection_engine/rules", regla)
        ok = code < 300
        errores += 0 if ok else 1
        print(f"   {code}  {regla['name']}")
        if not ok:
            print("  ", json.dumps(resp, ensure_ascii=False)[:500])
    return errores


def dashboards():
    archivos = sorted(glob.glob("/app/dashboards/*.ndjson"))
    if not archivos:
        print("== Sin dashboards para importar (kibana/dashboards/ está vacío)")
        return
    print("== Dashboards")
    for archivo in archivos:
        frontera = uuid.uuid4().hex
        with open(archivo, "rb") as f:
            contenido = f.read()
        nombre = os.path.basename(archivo)
        cuerpo = (
            f"--{frontera}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{nombre}"\r\n'
            "Content-Type: application/ndjson\r\n\r\n"
        ).encode() + contenido + f"\r\n--{frontera}--\r\n".encode()
        code, resp = llamar(
            "POST", "/api/saved_objects/_import?overwrite=true", cuerpo,
            headers={"Content-Type": f"multipart/form-data; boundary={frontera}"}, crudo=True,
        )
        print(f"   {code}  {nombre}  -> {resp.get('successCount', '?')} objetos")
        if code >= 300 or resp.get("errors"):
            print("  ", json.dumps(resp, ensure_ascii=False)[:800])


if __name__ == "__main__":
    esperar_kibana()
    data_views()
    fallidas = reglas()
    dashboards()
    if fallidas:
        sys.exit(f"{fallidas} reglas fallaron")
    print("== Kibana configurado")
