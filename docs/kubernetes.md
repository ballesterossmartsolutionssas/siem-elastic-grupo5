# Cuarta fuente: logs de Kubernetes (R8.2)

El enunciado nombra cuatro fuentes: syslog, nginx, **Kubernetes** y auth.log. Las tres primeras vienen de la víctima. Kubernetes corre en un clúster **k3s** creado con **k3d** dentro de la misma red de Docker del SIEM.

```text
 k3d-siem-k8s-server-0 (k3s)                                  red siem_siem
 ┌──────────────────────────────────────────────┐
 │ namespace tienda                             │
 │   web (nginx ×2) ◀── clientes (wget en bucle)│
 │                                              │
 │ namespace kube-system                        │
 │   Filebeat (DaemonSet)                       │
 │     lee /var/log/containers/*.log            │──▶ Logstash :5044 ──▶ logs-siem.k8s-default
 │     + add_kubernetes_metadata                │    (50-k8s.conf)
 └──────────────────────────────────────────────┘
```

## Cómo se levanta

Requisitos: el stack arriba, [k3d](https://k3d.io) y `kubectl` (Docker Desktop ya trae kubectl).

```bash
bash scripts/kubernetes.sh crear    # clúster, app de ejemplo y Filebeat (~1 min la primera vez)
bash scripts/kubernetes.sh estado   # pods y cuántos eventos de k8s hay en el SIEM
bash scripts/kubernetes.sh borrar   # elimina el clúster
```

## Qué llega al SIEM

Cada evento trae los metadatos de Kubernetes que agrega Filebeat:

- `kubernetes.namespace`, `kubernetes.pod.name`, `kubernetes.container.name` y `kubernetes.node.name`;
- `kubernetes.labels.*`, por ejemplo `app: web`.

Logstash (`logstash/pipeline/50-k8s.conf`) hace dos cosas:

- Parsea el formato *combined* del nginx del pod. Saca `source.ip`, `url.original`, `http.response.status_code` y `user_agent.original`, y calcula `event.outcome`.
- Marca `siem.ruta_sensible` y `siem.herramienta_ataque` con las mismas reglas que el nginx de la víctima.

Los logs que no son HTTP (por ejemplo, los de CoreDNS) quedan como `event.action: log_contenedor`.

Cada 20 vueltas, el generador de tráfico busca rutas sensibles con el user agent de gobuster. Así se ven 404 desde dentro del clúster.

En Kibana (Discover, data view `SIEM - todos los logs`):

```text
data_stream.dataset : "siem.k8s" and kubernetes.namespace : "tienda"
```

## Decisiones

- **k3d y no minikube:** k3d corre k3s como un contenedor más. Se conecta a la red `siem_siem`, así que Filebeat llega a Logstash sin publicar puertos. Además, pesa menos de 1 GB de RAM.
- **`hostAliases` con la IP de Logstash:** el script la lee con `docker inspect` y la pone en el DaemonSet. Así no depende del DNS de Docker dentro de los pods.
- **`--api-port 127.0.0.1:6550`:** en Windows, k3d deja el kubeconfig apuntando a `host.docker.internal` y desde el PC no responde.
- Solo entran los namespaces `tienda` y `kube-system`. Los logs del propio Filebeat se descartan para no hacer bucle.
