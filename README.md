# SIEM con Elastic Stack: Grupo 5

Proyecto 8 de Computación en la Nube (541201, 2026-2S): plataforma de análisis de logs y seguridad con Elastic Stack.

**Integrantes:** Valentina Velastegui · Juan Camilo Ballesteros · Juan Miguel Carabali

Un SIEM sencillo y reproducible con un solo comando. Un servidor **víctima** genera logs reales (SSH, web y puertos). Un contenedor **atacante** lo ataca con nmap, hydra y sqlmap. Elastic Stack centraliza y normaliza los logs, detecta los ataques y los muestra en dashboards.

## Demo en video

Recorrido de 5 minutos, sin audio y con subtítulos que explican cada parte: el stack, el panel con R8.1-R8.8, un ataque real con sus alertas, la investigación guiada, los dashboards, el índice de errores, Kubernetes y el ILM. Archivo: [diapositivas/demo-SIEM-Grupo5.mp4](diapositivas/demo-SIEM-Grupo5.mp4).

## Arquitectura

```text
 ┌────────────┐  ataques   ┌──────────────────────────────┐
 │ atacante   │──────────▶ │ victima                      │
 │ nmap hydra │            │ sshd ─▶ auth.log             │
 │ sqlmap     │            │ nginx ─▶ access.log          │
 └────────────┘            │ portguard/cron ─▶ syslog     │
 ┌────────────┐  normal    │ (volumen victima-logs)       │
 │ trafico    │──────────▶ └──────────────┬───────────────┘
 └────────────┘                           │
 generadores/historico.py ─▶ datos/historico/
                                          ▼
                                   ┌─────────────┐
                                   │  Filebeat   │  fields.origen = auth | nginx | syslog
                                   └──────┬──────┘
                                          ▼ :5044
                                   ┌─────────────┐  grok · date · mutate · geoip · cidr
                                   │  Logstash   │  malformados ─▶ logs-siem.errores
                                   └──────┬──────┘
                                          ▼ data streams logs-siem.{auth,nginx,syslog,red,errores}-default
                   ┌──────────────────────────────────────────┐
                   │ Elasticsearch: es01 · es02 · es03 (TLS)  │  ILM siem-30d (hot→warm→cold→delete)
                   └─────────────────────┬────────────────────┘
                                         ▼
                   ┌──────────────────────────────────────────┐
                   │ Kibana: Security (8 reglas) · Dashboards │
                   └──────────────────────────────────────────┘
```

## Requisitos

- Docker Desktop (Windows o Mac) o Docker Engine (Linux), con Compose v2.
- 16 GB de RAM o más (el stack usa unos 8 GB) y 20 GB libres en disco.
- Python 3.10 o más, para el generador histórico (y Playwright para las capturas y el video).
- Para la cuarta fuente: [k3d](https://k3d.io) y `kubectl` (Docker Desktop ya trae kubectl). k3s pide alrededor de 1 GB más de RAM.
- Para grabar la demo: `ffmpeg`.

## Paso a paso

### 1. Ajuste del kernel (una vez por PC)

Elasticsearch necesita `vm.max_map_count` ≥ 262144.

En Windows con Docker Desktop (WSL2), en PowerShell:

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

En Linux:

```bash
sudo sysctl -w vm.max_map_count=262144
```

> En Windows el valor se pierde al reiniciar Docker Desktop: si Elasticsearch no arranca, repítelo.

### 2. Variables

```bash
cp .env.example .env
```

Cambia las contraseñas de `.env` (solo letras y números).

### 3. Levantar todo

```bash
docker compose up -d --build
```

La primera vez tarda entre 5 y 10 minutos (descarga las imágenes). Orden de arranque:
`setup` (certificados) → `es01`, `es02` y `es03` → `setup` (ILM, templates y usuarios) → `kibana` y `logstash` → `kibana-setup` (data views y reglas) → `filebeat`, `victima` y `trafico`.

Para ver si terminó:

```bash
docker compose ps
docker compose logs -f setup kibana-setup
```

### 4. Centro de operaciones (la pantalla principal)

**<http://localhost:8090>** — un panel web propio desde donde se maneja todo sin tocar la terminal:

- **cumplimiento en vivo**: una franja con R8.1 a R8.8 que se pone en verde sola con las mediciones reales (clúster, fuentes, parseo, reglas que dispararon, escenarios atacados, investigaciones);
- estado de la plataforma (clúster, eventos, tasa de parseo, alertas y severidades de hoy), eventos por minuto y por fuente;
- **salud del sistema**: heap, disco y CPU de cada nodo, índices por fase de ILM y segundos desde el último evento;
- **detección de anomalías de volumen**: compara los últimos 5 minutos con la línea base de 24 h (z-score) y marca «VOLUMEN ANÓMALO» a partir de 3 desviaciones;
- flujo de logs en vivo;
- **botones para lanzar los 4 ataques**, con la consola del ataque y el tiempo hasta la alerta;
- **incidentes** agrupados por regla e IP (los críticos arriba) y top de IPs atacantes;
- clic en una IP: qué hizo, cuántos fallos y **si logró entrar**, puertos tocados, herramienta y reglas que disparó;
- **investigación guiada (R8.7 y R8.8)**: desde la IP se abre el playbook que corresponde, con cronómetro, la evidencia ya cargada, enlaces al dashboard operacional filtrado, la clasificación sugerida y los pasos de contención. Al cerrar el incidente se guarda en el índice `siem-investigaciones` quién lo investigó y en cuánto tiempo;
- enlaces a todos los tableros de Kibana.

Es la forma recomendada de mostrar el proyecto. Kibana queda un clic más adentro para el detalle.

### 4b. Entrar a Kibana

<http://localhost:5601>: usuario `elastic` y la contraseña `ELASTIC_PASSWORD` del `.env`.

- **Discover**, data view `SIEM - todos los logs`: los eventos en vivo.
- **Security → Rules**: las 8 reglas cargadas.
- **Security → Alerts**: las alertas.

### 5. Verificar (R8.1, R8.2 y R8.3)

```bash
bash scripts/verificar.sh
```

Muestra la salud del clúster (debe estar en verde), los nodos, los data streams con su política ILM y la tasa de parseo (debe superar el 95 %).

### 6. Historia de una semana (para los dashboards)

```bash
python generadores/historico.py --dias 7
```

### 7. Ataques (R8.4 y R8.5)

Cada comando lanza el ataque real y mide cuántos segundos tarda en aparecer la alerta:

```bash
bash scripts/atacar-y-medir.sh escaneo      "SIEM - Escaneo de puertos"
bash scripts/atacar-y-medir.sh fuerza-bruta "SIEM - Fuerza bruta SSH"
bash scripts/atacar-y-medir.sh sqli         "SIEM - Inyección SQL"
bash scripts/atacar-y-medir.sh rutas        "SIEM - Acceso a rutas sensibles"
```

Para lanzar un ataque sin medir: `docker compose run --rm atacante <escenario>` (escenarios: `escaneo`, `fuerza-bruta`, `sqli`, `rutas` o `todo`). Las alertas salen en Security → Alerts. Las reglas corren cada 30 s.

### 7b. Dashboards (R8.6 y R8.7)

En Kibana → Dashboards:

- **SIEM - Ejecutivo** (últimos 7 días): alertas de hoy, top amenazas, mapa de IPs, tendencia semanal y salud del sistema.
- **SIEM - Operacional** (última hora, se actualiza cada 10 s): alertas activas, top de IPs y usuarios, y logs en vivo. Pasa el mouse sobre una IP de *Top IPs* y dale a **Filter for**: todo el tablero se filtra por esa IP (drill-down).

Los dashboards son código: [`kibana/construir_dashboards.py`](kibana/construir_dashboards.py). Para cambiarlos:

```bash
python kibana/construir_dashboards.py
docker compose run --rm --no-deps kibana-setup
```

> Si después de reimportarlos un panel se ve viejo, dale a **Reset** arriba a la derecha del tablero. Kibana guarda en el navegador los cambios sin guardar.

### 8. Prueba acelerada de ILM (R8.1)

```bash
bash scripts/demo-ilm.sh
```

Tarda unos 8 minutos. Muestra cómo los índices de `logs-siem.ilmdemo` pasan de hot a warm y a cold. La política `siem-demo` los borra a los 30 minutos.

### 8a. Cuarta fuente: logs de Kubernetes (R8.2)

```bash
bash scripts/kubernetes.sh crear     # k3s con k3d, app de ejemplo y Filebeat como DaemonSet
bash scripts/kubernetes.sh estado    # pods y eventos de k8s que ya llegaron al SIEM
```

Crea un clúster k3s dentro de la red de Docker del SIEM. Despliega una app de ejemplo en el namespace `tienda` (nginx y un generador de tráfico) y un Filebeat como DaemonSet que manda los logs de los pods, con sus metadatos, al mismo Logstash. Llegan a `logs-siem.k8s-default`. Detalles en [docs/kubernetes.md](docs/kubernetes.md).

### 8b. Demo de la sustentación (video)

La demo se presenta grabada, sin audio y con subtítulos que explican cada parte. El video lo hace un script, siempre igual:

1. lanza el ataque real desde el panel y espera las alertas;
2. hace la investigación guiada;
3. recorre Kibana, el índice de errores, Kubernetes y el ILM acelerado;
4. une las escenas con ffmpeg.

```bash
python scripts/grabar-demo.py      # deja diapositivas/demo-SIEM-Grupo5.mp4 (~12 min)
```

Para recorrer lo mismo a mano, en la terminal y con pausas: `bash scripts/demo.sh`.

### 8c. Capturas de evidencia

Con el stack arriba y Playwright instalado (`pip install playwright` y `playwright install chromium`):

```bash
python scripts/capturas.py
```

Guarda en `docs/evidencias/`:

- el panel;
- los dos dashboards (el operacional, filtrado por la IP atacante);
- las reglas y las alertas;
- el índice de errores;
- los logs de Kubernetes;
- las políticas ILM y la prueba acelerada en warm y cold.

Antes hay que correr `bash scripts/demo-ilm.sh`.

### 9. Apagar

```bash
docker compose down        # conserva los datos
docker compose down -v     # borra todo (datos, certificados, logs)
```

## Cómo se cumple cada requisito

Resultados de la corrida final, con capturas: [docs/evidencias/resultados-2026-11-18.md](docs/evidencias/resultados-2026-11-18.md). La primera prueba completa (con la demo acelerada de ILM) está en [resultados-2026-11-04.md](docs/evidencias/resultados-2026-11-04.md).

| ID | Qué se hizo | Dónde | Resultado |
| --- | --- | --- | --- |
| R8.1 | 3 nodos con TLS; ILM `siem-30d` (borra a los 30 días) y `siem-demo` acelerada | `docker-compose.yml`, `setup/ilm/`, `scripts/demo-ilm.sh` | Clúster green; índices en warm y cold en 8 min |
| R8.2 | auth.log, syslog y nginx reales en la víctima, logs de **Kubernetes** (k3s, Filebeat DaemonSet) y puertos señuelo; ECS por `ecs@mappings` | `victima/`, `filebeat/`, `kubernetes/`, `setup/templates/` | Las 4 fuentes del enunciado visibles en Kibana |
| R8.3 | grok, date, mutate, geoip, cidr y urldecode; los malformados van a `logs-siem.errores` con `error.message` | `logstash/pipeline/` | 99,16 % parseado |
| R8.4 | 5 reglas pedidas, más inyección SQL, una de correlación EQL (fuerza bruta seguida de ingreso = cuenta comprometida) y una de anomalía *new terms* (usuario que entra desde una IP nunca vista en 7 días) | `reglas/` | Las 8 disparan |
| R8.5 | Ataques reales: nmap, hydra, sqlmap y curl | `atacante/`, `scripts/atacar-y-medir.sh` | Alertas en 13 a 28 s (la correlación, en 52 s) |
| R8.6 | Dashboard ejecutivo con mapa, tendencia y salud; se actualiza solo cada minuto | `kibana/construir_dashboards.py` | Evaluación con personas no técnicas: [evaluacion-dashboard-ejecutivo.md](docs/evidencias/evaluacion-dashboard-ejecutivo.md) |
| R8.7 | Dashboard operacional con drill-down por IP, más la investigación guiada con cronómetro del panel | `kibana/construir_dashboards.py`, `panel/` | Cada investigación queda medida en `siem-investigaciones` (objetivo < 5 min) |
| R8.8 | 2 playbooks: fuerza bruta SSH e inyección SQL, también como flujo guiado en el panel | `docs/playbooks/`, `panel/` | Probados con ataques reales; la investigación guiada registra quién los siguió |

## Decisiones de diseño

- **Correlación y anomalías sin licencia de pago:** el *machine learning* de Elastic pide licencia Platinum. Para la parte de anomalías se usaron las herramientas de la licencia Basic: una regla *new terms* (combinación usuario + IP nunca vista), una secuencia EQL (fallos seguidos de éxito) y, en el panel, un z-score del volumen de eventos contra la línea base de 24 h.

- **Data streams `logs-siem.<dataset>-default`** en vez de índices con fecha y alias: el rollover y el ILM los maneja Elasticsearch solo, y los componentes `ecs@mappings` y `logs@mappings` dejan los campos ECS bien tipados (por ejemplo, `source.ip` como `ip` y `source.geo.location` como `geo_point`).
- **Víctima real en vez de solo logs inventados:** los ataques de la demo son de verdad (hydra contra sshd y nmap contra los puertos), y los logs salen de los servicios reales.
- **X-Forwarded-For:** las IPs de Docker son privadas, así que la víctima se comporta como si estuviera detrás de un balanceador. Los ataques web mandan una IP pública en esa cabecera y GeoIP la ubica en el mapa. Los ataques SSH sí quedan con la IP privada real, marcada `red_interna`.
- **Puertos señuelo (portguard):** en un contenedor no hay logs del kernel ni del firewall. Por eso el escaneo se detecta con un servicio que escucha en puertos que no se usan. nmap se corre con `-sT`.
- **Logstash con un usuario propio** (`logstash_internal`), que solo puede escribir en `logs-siem.*`.

## Estructura

```text
├── docker-compose.yml       stack completo
├── .env.example             variables (copiar a .env)
├── setup/                   certificados, ILM, templates y configuración de Kibana
├── logstash/pipeline/       10-entrada · 20-auth · 30-nginx · 40-syslog · 50-k8s · 80-enriquecer · 90-salida
├── filebeat/                recolección
├── kubernetes/              app de ejemplo y Filebeat como DaemonSet (cuarta fuente)
├── panel/                   centro de operaciones web (:8090)
├── reglas/                  reglas de detección (JSON de la API de Kibana)
├── kibana/                  kibana.yml, construir_dashboards.py y el ndjson que genera
├── victima/                 servidor atacado (sshd, nginx, rsyslog y portguard)
├── atacante/                nmap, hydra y sqlmap, más el tráfico normal
├── generadores/             histórico de N días
├── scripts/                 verificar, atacar y medir, ILM, Kubernetes, capturas y grabar la demo
├── docs/                    playbooks, evidencias, plan de trabajo
└── diapositivas/            presentación (PPTX y PDF), video de la demo y guion de la sustentación
```

## Uso responsable

Las herramientas de ataque solo apuntan al contenedor `victima`, dentro de la red de Docker del laboratorio. No se deben usar contra sistemas de terceros.
