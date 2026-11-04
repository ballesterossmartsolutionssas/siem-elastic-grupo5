# Resultados de la primera prueba completa: 4 nov 2026

Stack levantado desde cero con `docker compose up -d --build` en un PC con Windows 11 y Docker Desktop (12 GB asignados a WSL2), con Elastic 8.19.23.

## R8.1: clúster e ILM

- `setup` creó los certificados, los usuarios, las 2 políticas ILM y los 2 templates sin errores. Clúster **green**, 3 nodos y 0 shards sin asignar.
- `scripts/demo-ilm.sh` (política `siem-demo`). A los 8 minutos:

| Índice | Edad | Fase |
| --- | --- | --- |
| `…ilmdemo-default-…-000001` | 7,2 min | **cold** |
| `…-000002` | 6,0 min | **cold** |
| `…-000003` | 4,9 min | **cold** |
| `…-000004` | 3,7 min | **warm** |
| `…-000005` | 2,5 min | **warm** |
| `…-000006` | 1,4 min | hot |
| `…-000007` / `000008` | segundos | hot (rollover) |

## R8.2 y R8.3: ingesta y parseo

`scripts/verificar.sh`, después de la semana de histórico con 1 % de líneas corruptas:

| Data stream | Documentos |
| --- | --- |
| `logs-siem.nginx-default` | 6.610 |
| `logs-siem.auth-default` | 649 |
| `logs-siem.syslog-default` | 419 |
| `logs-siem.red-default` | 67 |
| `logs-siem.errores-default` | 72 |

- **Tasa de parseo: 99,08 %** (7.817 eventos, 72 rechazados; el requisito es más del 95 %).
- Motivos de rechazo: 63 «La línea no tiene el formato siem de nginx» y 9 «El encabezado syslog no cuadra con el patrón esperado».
- GeoIP: por ejemplo, `181.49.112.7` quedó ubicada en La Estrella (Antioquia) y `185.220.101.34` en Alemania. `source.ip` quedó mapeada como `ip` y `source.geo.location` como `geo_point`.

## R8.4 y R8.5: detección (`scripts/atacar-y-medir.sh`)

El tiempo se cuenta desde que arranca el contenedor atacante hasta la primera alerta en `.alerts-security.alerts-default`.

| Escenario | Herramienta | Alerta | Tiempo |
| --- | --- | --- | --- |
| Escaneo de puertos | `nmap -sT` | SIEM - Escaneo de puertos | **10 s** |
| Fuerza bruta SSH | `hydra` (root y admin) | SIEM - Fuerza bruta SSH | **43 s** |
| Inyección SQL | `curl` + `sqlmap` | SIEM - Inyección SQL | **32 s** |
| Rutas sensibles + 404 | `curl` (UA gobuster) | SIEM - Acceso a rutas sensibles | **25 s** |
| (efecto de la fuerza bruta) | hydra adivinó la clave de `admin` | SIEM - Login fuera de horario | 52 s |
| Ráfaga de 404 | 40 peticiones | SIEM - Ráfaga de 404 | 19 s |

Las 6 reglas dispararon y todos los escenarios alertaron en menos de 60 s.

## R8.6 y R8.7: dashboards

- **SIEM - Ejecutivo:** alertas de hoy, alertas graves, IPs atacantes, eventos analizados, top amenazas, mapa (Alemania, Países Bajos, China, Brasil y otros), tendencia diaria por tipo de ataque, salud por fuente y rechazados.
- **SIEM - Operacional:** con *Filter for* sobre `192.168.16.10` en *Top IPs*, el tablero muestra la historia completa en una pantalla: escaneo, 48 fallos SSH (root y admin), **1 ingreso exitoso de admin** y la alerta de login fuera de horario. Menos de 1 minuto de investigación.

## Capturas pendientes

Hay que tomarlas en la corrida final, con nombres `R8.x-que-muestra.png`:

- `R8.1-cluster-green.png` y `R8.1-ilm-warm-cold.png`
- `R8.3-tasa-parseo.png` y `R8.3-indice-errores.png`
- `R8.5-alerta-<escenario>.png` (con la hora del ataque y la de la alerta)
- `R8.6-ejecutivo.png` y `R8.7-operacional-filtrado.png`
