# Resultados de la corrida final: 18 nov 2026

Stack levantado con `docker compose up -d` en Windows 11 y Docker Desktop, con Elastic 8.19. Las capturas de esta carpeta salen de esta corrida y se sacan solas con `python scripts/capturas.py`.

## R8.1: clúster e ILM

- Clúster **green**: 3 nodos, 104 shards activos y 0 sin asignar.
- Los 5 data streams `logs-siem.*` tienen la política `siem-30d`: hot → warm a los 7 días → cold a los 15 → se borran a los 30.
- La prueba acelerada (`siem-demo`, 8 minutos) está en [resultados-2026-11-04.md](resultados-2026-11-04.md).
- Captura: [R8.1-politicas-ilm.png](R8.1-politicas-ilm.png).

## R8.2 y R8.3: ingesta y parseo

| Fuente | Documentos |
| --- | --- |
| nginx | 14.093 |
| auth | 2.009 |
| syslog | 929 |
| red (puertos señuelo) | 208 |
| errores (rechazados) | 146 |

- **Tasa de parseo: 99,16 %** (17.385 eventos y 146 rechazados; el requisito pide más del 95 %).
- Motivos de rechazo: 125 «La línea no tiene el formato siem de nginx» y 21 «El encabezado syslog no cuadra con el patrón esperado».

## R8.4 y R8.5: detección

Se cuenta desde que arranca el contenedor atacante hasta la primera alerta en `.alerts-security.alerts-default` (`scripts/atacar-y-medir.sh`).

| Escenario | Herramienta | Alerta | Tiempo |
| --- | --- | --- | --- |
| Escaneo de puertos | `nmap -sT` | SIEM - Escaneo de puertos | **13 s** |
| Fuerza bruta SSH | `hydra` (root y admin) | SIEM - Fuerza bruta SSH | **28 s** |
| Inyección SQL | `curl` + `sqlmap` | SIEM - Inyección SQL | **17 s** |
| Rutas sensibles + 404 | `curl` (UA gobuster) | SIEM - Acceso a rutas sensibles | **27 s** |
| (efecto de la fuerza bruta) | hydra adivinó la clave de `admin` | **SIEM - Acceso tras fuerza bruta** (crítica, nueva) | **52 s** |
| (efecto de la fuerza bruta) | ingreso de `admin` a la 1:07 a. m. | SIEM - Login fuera de horario | 59 s |
| (efecto de las rutas) | 40 páginas inexistentes | SIEM - Ráfaga de 404 | 27 s |

**Las 7 reglas dispararon y todos los escenarios alertaron en menos de 60 s.** La mejora frente al 4 nov: los 4 ataques bajaron de 10-43 s a 13-28 s, y ahora hay una alerta crítica cuando la fuerza bruta funciona.

Capturas: [R8.4-reglas.png](R8.4-reglas.png) y [R8.5-alertas.png](R8.5-alertas.png).

### La regla nueva: correlación con EQL

`reglas/07-acceso-tras-fuerza-bruta.json` busca una **secuencia** por IP de origen: 5 ingresos SSH fallidos y después uno exitoso, en menos de 3 minutos.

```text
sequence by source.ip with maxspan=3m
  [authentication where event.action == "ssh_login" and event.outcome == "failure"] with runs=5
  [authentication where event.action == "ssh_login" and event.outcome == "success"]
```

| Hora (UTC) | Evento |
| --- | --- |
| 06:06:59 | Arranca hydra desde `192.168.80.11` |
| 06:07:03 | Primer intento fallido |
| 06:07:28 | Alerta **Fuerza bruta SSH** (alta) |
| 06:07:39 | `Accepted password for admin`: hydra adivinó la clave |
| 06:07:52 | Alerta **Acceso tras fuerza bruta** (crítica): 12 s después del ingreso |
| 06:07:58 | Alerta **Login fuera de horario** para `admin` |

Kibana guarda además una alerta interna (*building block*) por cada evento de la secuencia. El panel y los dashboards las excluyen para no contar 7 alertas donde hay una.

## R8.6 y R8.7: dashboards

- **SIEM - Ejecutivo** (7 días): 22 alertas hoy, 10 graves, 12 IPs atacantes, el mapa (Países Bajos, Alemania, Lituania, China, Brasil y Estados Unidos) y la tendencia del 11 al 18 nov. Captura: [R8.6-dashboard-ejecutivo.png](R8.6-dashboard-ejecutivo.png).
- **SIEM - Operacional** filtrado por `192.168.80.11`: en una pantalla salen las 3 alertas de esa IP, 48 fallos, 19 puertos tocados, y en *Top usuarios en SSH* `admin` con **1 éxito**. Captura: [R8.7-operacional-filtrado-por-ip.png](R8.7-operacional-filtrado-por-ip.png).
- **Centro de operaciones** (`http://localhost:8090`): [R8.0-centro-de-operaciones.png](R8.0-centro-de-operaciones.png).

## Agregado en la mañana del 18 nov: panel y anomalías

Fuerza bruta lanzada con el botón del panel a las 15:34:14 UTC:

| Hora (UTC) | Alerta |
| --- | --- |
| 15:34:26 | SIEM - Fuerza bruta SSH (alta): **12 s** |
| 15:35:26 | SIEM - Acceso tras fuerza bruta (crítica) |
| 15:35:26 | **SIEM - Ingreso desde una IP nueva** (regla 08, *new terms*): `admin` entró desde una IP que no se había visto en 7 días |

- El panel marcó **VOLUMEN ANÓMALO** con z = +6,0 σ: 241 eventos en 5 minutos contra un promedio de 10,4.
- La franja de cumplimiento del panel mostró R8.1 a R8.6 en verde. R8.7 y R8.8 se cumplen cuando se cierran investigaciones guiadas con el panel, y deben hacerlas integrantes que no escribieron los playbooks.
- Captura: [R8.0-centro-de-operaciones.png](R8.0-centro-de-operaciones.png).
