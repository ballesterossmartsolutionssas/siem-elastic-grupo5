# Dashboards

`siem-dashboards.ndjson` lo genera [`../construir_dashboards.py`](../construir_dashboards.py). No se edita a mano.

- **SIEM - Ejecutivo (R8.6):** alertas de hoy, alertas graves, IPs atacantes, eventos analizados, top amenazas del día, mapa de IPs sospechosas, ataques por día y tipo, salud por fuente y logs rechazados.
- **SIEM - Operacional (R8.7):** alertas activas, top IPs (con drill-down), top usuarios SSH, eventos por minuto, acciones y logs en tiempo real.

El contenedor `kibana-setup` importa todos los `.ndjson` de esta carpeta al arrancar el stack. Para reimportar sin reiniciar:

```bash
python kibana/construir_dashboards.py
docker compose run --rm --no-deps kibana-setup
```

Si alguien arma un panel nuevo a mano en Kibana, `bash scripts/exportar-dashboards.sh` lo exporta. Ojo: ese script sobrescribe este ndjson, así que lo mejor es pasar el panel nuevo a `construir_dashboards.py`.
