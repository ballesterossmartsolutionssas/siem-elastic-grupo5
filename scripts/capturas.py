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

        nav.close()
    print("Listo. IP usada en el operacional:", ip)


if __name__ == "__main__":
    main()
