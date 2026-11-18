"""Graba la demo de la sustentación como un video sin audio, con subtítulos que explican cada parte.

El profesor pidió la demo grabada (no en vivo). Este script la hace siempre igual:
lanza el ataque real desde el panel, espera las alertas, hace la investigación guiada y
recorre Kibana, el ILM, el índice de errores y Kubernetes. Graba escena por escena con
Playwright y las une con ffmpeg; las esperas largas (la alerta crítica, el ILM) quedan
fuera del video.

Requisitos: el stack arriba, Kubernetes creado (bash scripts/kubernetes.sh crear),
Playwright con Chromium y ffmpeg.
Uso, desde la raíz del repo:

    python scripts/grabar-demo.py                     # deja diapositivas/demo-SIEM-Grupo5.mp4
    python scripts/grabar-demo.py --analista "Valentina"

Tarda unos 12 minutos (el ILM acelerado necesita ~6 min para llegar a cold).
"""
import argparse
import html
import json
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

from capturas import pagina_ilm  # misma tabla de _ilm/explain que la captura de evidencia

RAIZ = Path(__file__).resolve().parent.parent
KIBANA = "http://localhost:5601"
PANEL = "http://localhost:8090"
REPO = "https://github.com/ballesterossmartsolutionssas/siem-elastic-grupo5"
ANCHO, ALTO = 1920, 1080

ESTILO_SUB = """
#sub-demo { position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483647; pointer-events: none;
  background: rgba(8, 12, 20, .92); border-top: 3px solid #00BFB3; padding: 18px 48px 22px;
  font-family: "Segoe UI", system-ui, sans-serif; color: #fff; display: flex; gap: 26px; align-items: center; }
#sub-demo .chip { font: 700 22px Consolas, monospace; color: #0B1220; background: #00BFB3; border-radius: 10px;
  padding: 8px 16px; white-space: nowrap; }
#sub-demo .t { font-size: 30px; font-weight: 700; line-height: 1.2; }
#sub-demo .d { font-size: 23px; color: #c9d3e0; margin-top: 4px; line-height: 1.3; }
.resaltado-demo { outline: 4px solid #FEC514 !important; outline-offset: 4px; border-radius: 6px;
  transition: outline-color .3s; }
"""


def env():
    datos = {}
    for linea in (RAIZ / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in linea and not linea.lstrip().startswith("#"):
            k, v = linea.split("=", 1)
            datos[k.strip()] = v.strip()
    return datos


def api(ruta):
    with urllib.request.urlopen(PANEL + ruta, timeout=60) as r:
        return json.loads(r.read())


def esperar(condicion, maximo, cada=5, que=""):
    t0 = time.time()
    while time.time() - t0 < maximo:
        try:
            if condicion():
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(cada)
    print("  (no llegó a tiempo:", que, ")")
    return False


def subtitulo(pag, chip, titulo, texto=""):
    pag.evaluate("""([css, chip, titulo, texto]) => {
        if (!document.getElementById('estilo-sub-demo')) {
            const st = document.createElement('style'); st.id = 'estilo-sub-demo'; st.textContent = css;
            document.head.appendChild(st);
        }
        let s = document.getElementById('sub-demo');
        if (!s) { s = document.createElement('div'); s.id = 'sub-demo'; document.body.appendChild(s); }
        s.innerHTML = (chip ? `<span class="chip">${chip}</span>` : '') +
          `<div><div class="t">${titulo}</div>${texto ? `<div class="d">${texto}</div>` : ''}</div>`;
    }""", [ESTILO_SUB, chip, titulo, texto])


def resaltar(pag, selector, centrar=True):
    pag.evaluate("""([sel, centrar]) => {
        document.querySelectorAll('.resaltado-demo').forEach(e => e.classList.remove('resaltado-demo'));
        const e = document.querySelector(sel); if (!e) return;
        if (centrar) e.scrollIntoView({behavior: 'smooth', block: 'center'});
        e.classList.add('resaltado-demo');
    }""", [selector, centrar])


def tarjeta(titulo, subtitulo_txt, puntos=None, pie=""):
    """Una pantalla de título (portada, separadores y cierre) en HTML."""
    lista = "".join(f"<li>{html.escape(p)}</li>" for p in (puntos or []))
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
      body {{ margin: 0; height: 100vh; background: #0B1220; color: #fff; font-family: "Segoe UI", system-ui, sans-serif;
        display: flex; flex-direction: column; justify-content: center; padding: 0 140px; box-sizing: border-box; }}
      h1 {{ font: 700 76px Arial, sans-serif; margin: 0; }}
      h2 {{ font-weight: 400; font-size: 36px; color: #00BFB3; margin: 18px 0 40px; }}
      ul {{ font-size: 30px; color: #c9d3e0; line-height: 1.7; margin: 0; padding-left: 36px; }}
      li::marker {{ color: #00BFB3; }}
      .pie {{ position: absolute; bottom: 60px; left: 140px; font-size: 22px; color: #7a8696; }}
    </style></head><body><h1>{html.escape(titulo)}</h1><h2>{html.escape(subtitulo_txt)}</h2>
    <ul>{lista}</ul><div class="pie">{html.escape(pie)}</div></body></html>"""


def terminal(bloques):
    """Salida real de comandos, con pinta de terminal."""
    cuerpo = ""
    for cmd, salida in bloques:
        cuerpo += f'<div class="p">$ {html.escape(cmd)}</div><pre>{html.escape(salida)}</pre>'
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
      body {{ margin: 0; background: #070a0e; color: #8fe0a6; font: 21px/1.45 Consolas, "Cascadia Mono", monospace;
        padding: 40px 56px; }}
      .p {{ color: #00BFB3; margin-top: 14px; }} pre {{ margin: 6px 0 0; color: #d6dee8; white-space: pre; }}
    </style></head><body>{cuerpo}</body></html>"""


def correr(cmd):
    try:
        return subprocess.run(cmd, cwd=RAIZ, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:  # noqa: BLE001
        return f"(no se pudo correr: {e})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analista", default="Demo grabada", help="nombre que queda en la investigación guiada")
    ap.add_argument("--salida", default=str(RAIZ / "diapositivas" / "demo-SIEM-Grupo5.mp4"))
    args = ap.parse_args()
    clave = env()["ELASTIC_PASSWORD"]
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise SystemExit("Falta ffmpeg")
    trabajo = Path(tempfile.mkdtemp(prefix="demo-siem-"))
    escenas = []

    # El ILM acelerado arranca ya: cuando lleguemos a esa escena habrá índices en warm y cold
    print("== ILM acelerado en segundo plano")
    ilm = subprocess.Popen(["bash", "scripts/demo-ilm.sh"], cwd=RAIZ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t_ilm = time.time()

    with sync_playwright() as p:
        nav = p.chromium.launch()

        # Sesión de Kibana una sola vez (fuera del video)
        ctx0 = nav.new_context(viewport={"width": ANCHO, "height": ALTO})
        pg = ctx0.new_page()
        pg.goto(f"{KIBANA}/login")
        pg.fill('[data-test-subj="loginUsername"]', "elastic")
        pg.fill('[data-test-subj="loginPassword"]', clave)
        pg.click('[data-test-subj="loginSubmit"]')
        pg.wait_for_url("**/app/**", timeout=60000)
        sesion = ctx0.storage_state()
        ctx0.close()

        def escena(nombre, fn):
            print("== Escena:", nombre)
            carpeta = trabajo / f"{len(escenas):02d}"
            ctx = nav.new_context(viewport={"width": ANCHO, "height": ALTO}, storage_state=sesion,
                                  record_video_dir=str(carpeta), record_video_size={"width": ANCHO, "height": ALTO},
                                  locale="es-CO", timezone_id="America/Bogota")
            pag = ctx.new_page()
            try:
                fn(pag)
            finally:
                video = pag.video
                ctx.close()
                escenas.append(Path(video.path()))

        def kibana(pag, ruta, espera=9000):
            pag.goto(KIBANA + ruta)
            try:
                pag.wait_for_load_state("networkidle", timeout=40000)
            except Exception:  # noqa: BLE001
                pass
            pag.wait_for_timeout(espera)
            for b in pag.locator('[data-test-subj="euiDismissCalloutButton"]').all():
                try:
                    b.click(timeout=1500)
                except Exception:  # noqa: BLE001
                    pass

        # ---------------------------------------------------------------- 0. portada
        def portada(pag):
            pag.set_content(tarjeta("SIEM con Elastic Stack", "Demo grabada · Proyecto 8 · Grupo 5", [
                "El stack: Elasticsearch, Logstash, Kibana y Kubernetes",
                "Panel SOC: los 8 requisitos medidos en vivo",
                "Ataque real de fuerza bruta y sus alertas",
                "Investigación guiada con el playbook",
                "Dashboards, ILM, índice de errores y logs de Kubernetes",
            ], "Valentina Velastegui · Juan Camilo Ballesteros · Juan Miguel Carabali"))
            pag.wait_for_timeout(7000)
        escena("portada", portada)

        # ---------------------------------------------------------------- 1. el stack
        def stack(pag):
            ps = correr(["docker", "compose", "ps", "--format", "table {{.Service}}\t{{.Status}}"])
            pods = correr(["kubectl", "--context", "k3d-siem-k8s", "get", "pods", "-n", "tienda", "-o", "wide"])
            fb = correr(["kubectl", "--context", "k3d-siem-k8s", "get", "daemonset", "filebeat", "-n", "kube-system"])
            pag.set_content(terminal([("docker compose ps", ps), ("kubectl get pods -n tienda", pods),
                                      ("kubectl get daemonset filebeat -n kube-system", fb)]))
            subtitulo(pag, "R8.1 · R8.2", "Todo corre con Docker Compose, más un clúster de Kubernetes (k3s)",
                      "3 nodos de Elasticsearch con TLS, Logstash, Kibana y Filebeat. En Kubernetes: una app de ejemplo y Filebeat como DaemonSet.")
            pag.wait_for_timeout(10000)
        escena("stack", stack)

        # ---------------------------------------------------------------- 2. panel: cumplimiento y salud
        def panel(pag):
            pag.goto(PANEL)
            pag.wait_for_timeout(5000)
            subtitulo(pag, "Panel SOC", "El centro de operaciones del grupo: localhost:8090",
                      "Arriba, cada requisito del enunciado (R8.1 a R8.8) con su medición real. Se pone en verde solo.")
            resaltar(pag, "#req", centrar=False)
            pag.wait_for_timeout(8000)
            subtitulo(pag, "R8.2 · R8.3", "4 fuentes y más del 99 % de los eventos parseados sin error",
                      "auth.log, nginx y syslog de la víctima, y los logs de Kubernetes. Los malformados van a un índice aparte.")
            resaltar(pag, ".tira", centrar=False)
            pag.wait_for_timeout(6000)
            subtitulo(pag, "R8.1 · R8.6", "Salud general del sistema",
                      "Memoria y disco de cada nodo, fases de ILM, retraso de la ingesta y detección de anomalías de volumen.")
            resaltar(pag, ".g3")
            pag.wait_for_timeout(8000)
        escena("panel", panel)

        # ---------------------------------------------------------------- 3. ataque en vivo
        inicio_ataque = {}

        def ataque(pag):
            pag.goto(PANEL)
            pag.wait_for_timeout(4000)
            resaltar(pag, 'button[data-a="fuerza-bruta"]')
            subtitulo(pag, "R8.5", "Ataque real: fuerza bruta contra el SSH de la víctima",
                      "Con un clic, el panel lanza hydra con un diccionario de claves para root y admin.")
            pag.wait_for_timeout(4000)
            inicio_ataque["t"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            pag.click('button[data-a="fuerza-bruta"]')
            pag.wait_for_timeout(2500)
            resaltar(pag, "#consola")
            subtitulo(pag, "R8.5", "hydra está probando claves…",
                      "Cada intento queda en auth.log. Filebeat lo recoge, Logstash lo pasa a ECS y lo guarda en Elasticsearch.")
            # Hasta que aparezca el tiempo de la alerta junto al botón
            for _ in range(60):
                txt = pag.inner_text("#r-fuerza-bruta")
                if "alerta en" in txt:
                    break
                pag.wait_for_timeout(1500)
            resaltar(pag, "#r-fuerza-bruta")
            subtitulo(pag, "R8.5", f"Alerta generada: {pag.inner_text('#r-fuerza-bruta').replace('✔ ', '')}",
                      "El enunciado pide menos de 60 segundos. Se mide desde que arranca el ataque hasta la alerta.")
            pag.wait_for_timeout(7000)
            resaltar(pag, ".g3 .panel:last-child")
            subtitulo(pag, "Anomalías", "El volumen de eventos se salió de lo normal",
                      "El panel compara los últimos 5 minutos con la línea base del día (z-score). A partir de 3σ lo marca anómalo.")
            pag.wait_for_timeout(8000)
        escena("ataque", ataque)

        # Fuera del video: esperar la alerta crítica y la de IP nueva
        print("  esperando la alerta crítica…")
        def del_ataque():
            return {a["regla"] for a in api("/api/alertas?desde=" + urllib.parse.quote(inicio_ataque["t"]))}
        esperar(lambda: "SIEM - Acceso tras fuerza bruta" in del_ataque(), maximo=180, que="alerta crítica")
        time.sleep(35)  # un ciclo más de las reglas, por si la de IP nueva sale en el siguiente
        ip_nueva = "SIEM - Ingreso desde una IP nueva" in del_ataque()

        # Los subtítulos dicen lo que de verdad muestra la pantalla: los números salen de la ficha de la IP
        ip, ficha = None, {}
        try:
            ip = next(a["ip"] for a in api("/api/resumen")["alertas"] if a["severidad"] == "critical")
            ficha = api("/api/ip/" + urllib.parse.quote(ip))
        except Exception:  # noqa: BLE001
            pass
        fallos, exitos, puertos = ficha.get("fallos", 0), ficha.get("exitos", 0), ficha.get("puertos", 0)
        con_exito = [u["usuario"] for u in ficha.get("usuarios", []) if u["exitos"]]
        quien = " y ".join(con_exito) or "admin"

        # ---------------------------------------------------------------- 4. incidentes y ficha de la IP
        def incidentes(pag):
            pag.goto(PANEL)
            pag.wait_for_timeout(5000)
            resaltar(pag, "#alertas tr.critica")
            subtitulo(pag, "R8.4", "Alrededor de un minuto después: una alerta CRÍTICA",
                      "La regla EQL vio 5 fallos y luego un ingreso desde la misma IP: hydra adivinó la clave de admin.")
            pag.wait_for_timeout(8000)
            if ip_nueva:
                subtitulo(pag, "R8.4 · Anomalías", "Y la de «Ingreso desde una IP nueva»",
                          "Regla new terms: admin nunca había entrado desde esa IP en los últimos 7 días.")
            else:
                subtitulo(pag, "R8.4 · Anomalías", "«Ingreso desde una IP nueva» saltó solo la primera vez",
                          "La regla new terms aprende: admin ya había entrado desde esa IP, así que ese par dejó de ser una anomalía.")
            pag.wait_for_timeout(6000)
            pag.locator("#alertas tr.critica .ipc").first.click()
            pag.wait_for_timeout(3000)
            subtitulo(pag, "R8.7", "Clic en la IP: qué hizo el atacante",
                      f"En 24 h: {fallos} intentos fallidos y {exitos} ingreso{'s' if exitos != 1 else ''} exitoso{'s' if exitos != 1 else ''} "
                      f"como {quien}, más las reglas que disparó.")
            resaltar(pag, "#cExitos", centrar=False)
            pag.wait_for_timeout(8000)
        escena("incidentes", incidentes)

        # ---------------------------------------------------------------- 5. investigación guiada
        def guiada(pag):
            pag.goto(PANEL)
            pag.wait_for_timeout(5000)
            pag.locator("#alertas tr.critica .ipc").first.click()
            pag.wait_for_timeout(2500)
            pag.click("#mGuiada")
            pag.wait_for_timeout(1500)
            subtitulo(pag, "R8.7 · R8.8", "Investigación guiada: el playbook con cronómetro",
                      "El analista sigue los pasos del playbook. Arriba a la derecha corre el tiempo: el objetivo es menos de 5 minutos.")
            pag.locator("#iAnalista").fill("")
            pag.locator("#iAnalista").type(args.analista, delay=90)
            pag.wait_for_timeout(1500)
            pasos = pag.locator(".iPaso").all()
            textos = ["Paso 1: la alerta, con la IP y la hora", "Paso 2: el dashboard operacional filtrado por la IP",
                      f"Paso 3: ¿hubo ingreso exitoso? Sí: el atacante entró como {quien}",
                      (f"Paso 4: la misma IP también tocó {puertos} puertos (escaneo)" if puertos
                       else "Paso 4: ¿más alertas de la misma IP? Fuerza bruta y la crítica de correlación")]
            for i, c in enumerate(pasos):
                c.scroll_into_view_if_needed()
                subtitulo(pag, "R8.7 · R8.8", "1 · Detección y triage", textos[i] if i < len(textos) else "")
                pag.wait_for_timeout(2200)
                c.check()
                pag.wait_for_timeout(1200)
            subtitulo(pag, "R8.8", "2 · Contención", "Bloquear la IP, cerrar las sesiones de admin y bloquear la cuenta.")
            for c in pag.locator(".iCont").all():
                c.scroll_into_view_if_needed()
                pag.wait_for_timeout(900)
                c.check()
            pag.locator("#iNotas").scroll_into_view_if_needed()
            pag.locator("#iNotas").type("Clave de diccionario en admin. Pasar SSH a solo llaves y activar fail2ban.", delay=25)
            pag.wait_for_timeout(1000)
            pag.click("#iFin")
            pag.wait_for_timeout(2500)
            pag.locator("#iRes").scroll_into_view_if_needed()
            subtitulo(pag, "R8.7", "Incidente cerrado y registrado",
                      "Queda en el índice siem-investigaciones quién lo investigó y en cuánto tiempo.")
            pag.wait_for_timeout(6000)
            pag.click("#iCerrar")
            pag.wait_for_timeout(4500)
            resaltar(pag, "#invs")
            subtitulo(pag, "R8.7 · R8.8", "Las investigaciones registradas",
                      "Cada integrante repite el playbook que no escribió: así se cumple el criterio de R8.8.")
            pag.wait_for_timeout(7000)
        escena("investigacion", guiada)

        # ---------------------------------------------------------------- 6. Kibana: alertas
        def alertas(pag):
            kibana(pag, "/app/security/alerts", 10000)
            subtitulo(pag, "R8.4 · R8.5", "Las mismas alertas en Kibana Security",
                      "8 reglas: fuerza bruta, escaneo, 404, horario, rutas sensibles, SQLi, correlación EQL y anomalía new terms.")
            pag.wait_for_timeout(9000)
            pag.mouse.wheel(0, 700)
            pag.wait_for_timeout(5000)
        escena("alertas", alertas)


        # ---------------------------------------------------------------- 7. operacional
        def operacional(pag):
            filtro = ""
            if ip:
                filtro = "&_a=" + urllib.parse.quote(f"(query:(language:kuery,query:'source.ip : \"{ip}\"'))", safe="(),:'")
            kibana(pag, f"/app/dashboards#/view/siem-dashboard-operacional?_g=(time:(from:now-1h,to:now)){filtro}", 11000)
            subtitulo(pag, "R8.7", "Dashboard operacional filtrado por la IP atacante",
                      f"Logs en tiempo real, alertas activas y top de usuarios en SSH: {quien} aparece con ingresos exitosos.")
            pag.wait_for_timeout(10000)
            pag.mouse.wheel(0, 800)
            subtitulo(pag, "R8.7", "Drill-down hasta cada evento",
                      "Abajo, cada línea del auth.log ya parseada: usuario, IP, acción y resultado.")
            pag.wait_for_timeout(7000)
        escena("operacional", operacional)

        # ---------------------------------------------------------------- 8. ejecutivo
        def ejecutivo(pag):
            kibana(pag, "/app/dashboards#/view/siem-dashboard-ejecutivo?_g=(time:(from:now-7d,to:now))", 12000)
            subtitulo(pag, "R8.6", "Dashboard ejecutivo, para gente no técnica",
                      "Alertas de hoy y graves, top amenazas y el mapa de las IPs sospechosas. Se actualiza solo cada minuto.")
            pag.wait_for_timeout(10000)
            pag.mouse.wheel(0, 700)
            subtitulo(pag, "R8.6", "Tendencia de la semana y salud del sistema",
                      "Ataques por día y tipo, y cuántos eventos llegan de cada fuente.")
            pag.wait_for_timeout(8000)
        escena("ejecutivo", ejecutivo)

        # ---------------------------------------------------------------- 9. errores
        def errores(pag):
            a = "(columns:!(error.message,labels.origen,message),index:'logs-siem-errores',query:(language:kuery,query:''))"
            kibana(pag, "/app/discover#/?_g=(time:(from:now-7d,to:now))&_a=" + urllib.parse.quote(a, safe="(),:!"), 9000)
            subtitulo(pag, "R8.3", "Los logs malformados no se pierden",
                      "Van al índice logs-siem.errores con el motivo en error.message. Son menos del 1 %.")
            pag.wait_for_timeout(9000)
        escena("errores", errores)

        # ---------------------------------------------------------------- 10. kubernetes
        def kubernetes(pag):
            a = ("(columns:!(kubernetes.namespace,kubernetes.pod.name,kubernetes.node.name,http.response.status_code,url.original),"
                 "index:'logs-siem',query:(language:kuery,query:'data_stream.dataset : \"siem.k8s\" and kubernetes.namespace : \"tienda\"'))")
            kibana(pag, "/app/discover#/?_g=(time:(from:now-15m,to:now))&_a=" + urllib.parse.quote(a, safe="(),:!"), 9000)
            subtitulo(pag, "R8.2", "Cuarta fuente: logs de Kubernetes",
                      "Filebeat como DaemonSet agrega namespace, pod y nodo. Logstash parsea el nginx de los pods como cualquier otra fuente.")
            pag.wait_for_timeout(10000)
        escena("kubernetes", kubernetes)

        # Fuera del video: que el ILM acelerado tenga índices en cold
        print("  esperando a que el ILM acelerado llegue a cold…")
        esperar(lambda: api("/api/resumen")["salud"]["ilm"]["fases"].get("cold", 0) > 0 and time.time() - t_ilm > 300,
                maximo=600, cada=10, que="ILM en cold")

        # ---------------------------------------------------------------- 11. ILM
        def ilm_escena(pag):
            pag.set_content(pagina_ilm(clave) or tarjeta("ILM", "Sin índices de la prueba acelerada", []))
            pag.wait_for_timeout(1000)
            subtitulo(pag, "R8.1", "ILM: prueba acelerada pasando a warm y cold",
                      "La política siem-30d mueve los datos a warm el día 7, a cold el día 15 y los borra el día 30. Aquí, lo mismo en minutos.")
            pag.wait_for_timeout(10000)
            pag.goto(PANEL)
            pag.wait_for_timeout(4500)
            resaltar(pag, "#fases")
            subtitulo(pag, "R8.1", "El panel ve los índices en cada fase",
                      "HOT recibe datos, WARM es solo lectura y COLD es el archivo barato. En la nube, ahí está el ahorro.")
            pag.wait_for_timeout(7000)
        escena("ilm", ilm_escena)

        # ---------------------------------------------------------------- 12. playbook en el repo
        def repo(pag):
            pag.goto(f"{REPO}/blob/main/docs/playbooks/fuerza-bruta-ssh.md")
            pag.wait_for_timeout(5000)
            subtitulo(pag, "R8.8", "Los playbooks están en el repositorio",
                      "Investigación, contención, erradicación, recuperación y lecciones aprendidas, con la línea de tiempo real.")
            pag.wait_for_timeout(6000)
            pag.mouse.wheel(0, 900)
            pag.wait_for_timeout(5000)
        escena("repo", repo)

        # ---------------------------------------------------------------- 13. cierre
        def cierre(pag):
            r = api("/api/resumen")
            ok = sum(1 for q in r["requisitos"] if q["ok"])
            pag.set_content(tarjeta("Resultado", f"{ok} de 8 requisitos en verde en el panel", [
                f"Clúster {r['cluster']} con {r['nodos']} nodos · {r['parseo']} % de parseo",
                "Fuerza bruta detectada en segundos, crítica cuando el atacante entra",
                "Anomalías: regla new terms y volumen por z-score",
                "Investigación guiada registrada, en menos de 5 minutos",
                "Todo es código: github.com/ballesterossmartsolutionssas/siem-elastic-grupo5",
            ], "SIEM con Elastic Stack · Grupo 5 · Computación en la Nube 2026-2S"))
            pag.wait_for_timeout(8000)
        escena("cierre", cierre)

        nav.close()

    ilm.wait(timeout=600)

    # ---------------------------------------------------------------- unir las escenas
    print("== Uniendo", len(escenas), "escenas con ffmpeg")
    lista = trabajo / "lista.txt"
    # Una sola codificación, a los 25 fps nativos de Playwright (pasar a 30 duplicaba cuadros y el
    # movimiento saltaba), saltando el primer instante de cada escena (un cuadro en blanco al cargar).
    lista.write_text("".join(f"file '{Path(v).as_posix()}'\ninpoint 0.4\n" for v in escenas), encoding="utf-8")
    salida = Path(args.salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(lista),
                    "-vf", "fps=25,format=yuv420p", "-c:v", "libx264", "-preset", "slow", "-crf", "25",
                    "-tune", "stillimage", "-g", "50", "-an", "-movflags", "+faststart", str(salida)], check=True)
    print("Listo:", salida, f"({salida.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
