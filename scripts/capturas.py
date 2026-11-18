"""Saca las capturas de evidencia (R8.x) con un navegador sin ventana.

Requisitos: el stack arriba y Playwright (pip install playwright && playwright install chromium).
Uso, desde la raíz del repo:

    python scripts/capturas.py               # todas
    python scripts/capturas.py --ip 192.168.16.10   # IP para el drill-down del operacional

Las guarda en docs/evidencias/R8.x-*.png. La contraseña de Kibana se lee del .env.
"""
import argparse
import base64
import json
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "docs" / "evidencias"
KIBANA = "http://localhost:5601"
PANEL = "http://localhost:8090"


def env():
    datos = {}
    for linea in (RAIZ / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in linea and not linea.lstrip().startswith("#"):
            k, v = linea.split("=", 1)
            datos[k.strip()] = v.strip()
    return datos


def ip_atacante(clave):
    """La IP con más alertas de hoy (la del contenedor atacante)."""
    cuerpo = json.dumps({"size": 0, "query": {"range": {"@timestamp": {"gte": "now/d"}}},
                         "aggs": {"ip": {"terms": {"field": "source.ip", "size": 1}}}}).encode()
    req = urllib.request.Request(f"{KIBANA}/api/console/proxy?path=.alerts-security.alerts-default/_search&method=GET",
                                 data=cuerpo, method="POST", headers={
                                     "Authorization": "Basic " + base64.b64encode(f"elastic:{clave}".encode()).decode(),
                                     "Content-Type": "application/json", "kbn-xsrf": "capturas"})
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=20) as r:
            cubetas = json.loads(r.read())["aggregations"]["ip"]["buckets"]
            return cubetas[0]["key"] if cubetas else None
    except Exception as e:  # noqa: BLE001
        print("  no pude averiguar la IP atacante:", e)
        return None


def es_por_kibana(clave, metodo, ruta, cuerpo=None):
    """Consulta Elasticsearch a través de la consola de Kibana (así no hace falta la CA)."""
    q = urllib.parse.urlencode({"path": ruta, "method": metodo})
    req = urllib.request.Request(f"{KIBANA}/api/console/proxy?{q}", method="POST",
                                 data=json.dumps(cuerpo).encode() if cuerpo is not None else b"",
                                 headers={"Authorization": "Basic " + base64.b64encode(f"elastic:{clave}".encode()).decode(),
                                          "Content-Type": "application/json", "kbn-xsrf": "capturas"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def pagina_ilm(clave):
    """Tabla con la respuesta real de _ilm/explain de la prueba acelerada: índice, fase y edad."""
    try:
        r = es_por_kibana(clave, "GET", "/.ds-logs-siem.ilmdemo-*/_ilm/explain?filter_path=indices.*.phase,indices.*.age,indices.*.policy,indices.*.index")
    except Exception as e:  # noqa: BLE001
        print("  no pude leer el ILM:", e)
        return None
    indices = sorted(r.get("indices", {}).values(), key=lambda x: x["index"])
    if not indices:
        return None
    colores = {"hot": "#ff8f82", "warm": "#e6c24f", "cold": "#6cc5ff", "delete": "#7a8696"}
    filas = "".join(
        f'<tr><td>{i["index"]}</td><td>{i.get("policy", "")}</td><td>{i.get("age", "")}</td>'
        f'<td style="color:{colores.get(i.get("phase"), "#fff")};font-weight:700">{i.get("phase", "").upper()}</td></tr>'
        for i in indices)
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
      body {{ margin: 0; background: #070a0e; color: #d6dee8; font: 19px/1.5 Consolas, monospace; padding: 34px 44px; }}
      .p {{ color: #00BFB3; }} h1 {{ font: 700 26px "Segoe UI", sans-serif; color: #fff; margin: 0 0 6px; }}
      .s {{ color: #7a8696; font-family: "Segoe UI", sans-serif; margin-bottom: 20px; }}
      table {{ border-collapse: collapse; width: 100%; }} td, th {{ text-align: left; padding: 7px 14px; border-bottom: 1px solid #1d2530; }}
      th {{ color: #7a8696; font-weight: 400; }}
    </style></head><body>
      <h1>R8.1 · ILM acelerado: los índices pasan de hot a warm y a cold</h1>
      <div class="s">Política siem-demo (la misma que siem-30d, pero en minutos): rollover cada 1 min, warm a los 2 min, cold a los 4 min y se borra a los 30 min.</div>
      <div class="p">GET .ds-logs-siem.ilmdemo-*/_ilm/explain</div><br>
      <table><tr><th>Índice</th><th>Política</th><th>Edad</th><th>Fase</th></tr>{filas}</table>
    </body></html>"""


def esperar_kibana(pagina, extra=6000):
    try:
        pagina.wait_for_load_state("networkidle", timeout=45000)
    except Exception:  # noqa: BLE001 - Kibana sigue haciendo polling; con lo cargado basta
        pass
    pagina.wait_for_timeout(extra)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", help="IP para filtrar el dashboard operacional")
    args = ap.parse_args()
    clave = env()["ELASTIC_PASSWORD"]
    ip = args.ip or ip_atacante(clave)
    SALIDA.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        nav = p.chromium.launch()
        ctx = nav.new_context(viewport={"width": 1600, "height": 900}, device_scale_factor=1, locale="es-CO",
                              timezone_id="America/Bogota")
        pag = ctx.new_page()

        def foto(nombre, pagina_completa=False):
            ruta = SALIDA / nombre
            pag.mouse.move(5, 890)  # sin tooltips ni celdas resaltadas
            pag.wait_for_timeout(500)
            pag.screenshot(path=str(ruta), full_page=pagina_completa)
            print("  ok", ruta.relative_to(RAIZ))

        # Centro de operaciones propio (sin login)
        pag.goto(PANEL)
        pag.wait_for_timeout(8000)
        foto("R8.0-centro-de-operaciones.png", pagina_completa=True)

        # Login en Kibana
        pag.goto(f"{KIBANA}/login")
        pag.fill('[data-test-subj="loginUsername"]', "elastic")
        pag.fill('[data-test-subj="loginPassword"]', clave)
        pag.click('[data-test-subj="loginSubmit"]')
        pag.wait_for_url("**/app/**", timeout=60000)
        esperar_kibana(pag, 3000)
        # El aviso de "Help us improve the Elastic Stack" tapa la parte de arriba: se cierra una vez
        try:
            pag.get_by_role("button", name="Dismiss").first.click(timeout=5000)
        except Exception:  # noqa: BLE001 - ya estaba cerrado
            pass

        pag.goto(f"{KIBANA}/app/dashboards#/view/siem-dashboard-ejecutivo?_g=(time:(from:now-7d,to:now))")
        esperar_kibana(pag, 12000)
        foto("R8.6-dashboard-ejecutivo.png", pagina_completa=True)

        filtro = ""
        if ip:
            q = urllib.parse.quote(f"(query:(language:kuery,query:'source.ip : \"{ip}\"'))", safe="(),:'")
            filtro = f"&_a={q}"
        pag.goto(f"{KIBANA}/app/dashboards#/view/siem-dashboard-operacional?_g=(time:(from:now-1h,to:now)){filtro}")
        esperar_kibana(pag, 12000)
        foto("R8.7-operacional-filtrado-por-ip.png", pagina_completa=True)

        def cerrar_avisos():
            for boton in pag.locator('[data-test-subj="euiDismissCalloutButton"]').all():
                try:
                    boton.click(timeout=2000)
                except Exception:  # noqa: BLE001
                    pass

        pag.set_viewport_size({"width": 1600, "height": 1250})
        pag.goto(f"{KIBANA}/app/security/rules")
        esperar_kibana(pag, 8000)
        cerrar_avisos()
        pag.wait_for_timeout(1500)
        foto("R8.4-reglas.png")
        pag.set_viewport_size({"width": 1600, "height": 900})

        pag.goto(f"{KIBANA}/app/security/alerts")
        esperar_kibana(pag, 12000)
        cerrar_avisos()
        foto("R8.5-alertas.png", pagina_completa=True)

        pag.goto(f"{KIBANA}/app/management/data/index_lifecycle_management/policies")
        esperar_kibana(pag, 5000)
        foto("R8.1-politicas-ilm.png")

        def discover(nombre, data_view, columnas, kql, desde="now-7d"):
            a = f"(columns:!({','.join(columnas)}),index:'{data_view}',query:(language:kuery,query:'{kql}'))"
            pag.goto("about:blank")  # si no, Discover conserva la vista de datos anterior
            pag.goto(f"{KIBANA}/app/discover#/?_g=(time:(from:{desde},to:now))&_a={urllib.parse.quote(a, safe='(),:!')}")
            esperar_kibana(pag, 9000)
            cerrar_avisos()
            foto(nombre)

        # R8.3: los malformados, cada uno con su motivo en error.message
        discover("R8.3-indice-errores.png", "logs-siem-errores", ["error.message", "labels.origen", "message"], "")
        # R8.2: la cuarta fuente, Kubernetes, con los metadatos que agrega Filebeat (scripts/kubernetes.sh)
        discover("R8.2-kubernetes.png", "logs-siem",
                 ["kubernetes.namespace", "kubernetes.pod.name", "kubernetes.node.name", "http.response.status_code", "url.original"],
                 'data_stream.dataset : "siem.k8s" and kubernetes.namespace : "tienda"', desde="now-30m")

        # R8.1: la prueba acelerada (scripts/demo-ilm.sh) con índices en warm y cold. Los borra a los 30 min.
        html_ilm = pagina_ilm(clave)
        if html_ilm:
            pag.set_content(html_ilm)
            pag.wait_for_timeout(800)
            foto("R8.1-ilm-warm-cold.png")
        else:
            print("  (sin índices de la prueba acelerada: corre antes bash scripts/demo-ilm.sh)")

        nav.close()
    print("Listo. IP usada en el operacional:", ip)


if __name__ == "__main__":
    main()
