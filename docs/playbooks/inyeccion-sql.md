# Playbook: inyección SQL y reconocimiento web

| Dato | Valor |
| --- | --- |
| Alertas | `SIEM - Inyección SQL` (alta), `SIEM - Acceso a rutas sensibles` y `SIEM - Ráfaga de 404` (medias) |
| Reglas | `reglas/06-inyeccion-sql.json`, `reglas/05-rutas-sensibles.json`, `reglas/03-rafaga-404.json` |
| Fuente | `logs-siem.nginx-*` (access.log de la víctima) |
| MITRE ATT&CK | T1595 Active Scanning → T1190 Exploit Public-Facing Application |
| Cómo simularlo | `bash scripts/atacar-y-medir.sh sqli "SIEM - Inyección SQL"` y `bash scripts/atacar-y-medir.sh rutas "SIEM - Acceso a rutas sensibles"` |
| Tiempo objetivo | Investigación completa en menos de 5 minutos |

**Quién lo ejecuta:** el analista de turno. Para contener necesita acceso al WAF o al balanceador, y para erradicar, al equipo que mantiene la aplicación.

## 1. Detección y triage (≈ 2 min)

1. **Security → Alerts.** Abrir la alerta y anotar `source.ip`, el país (`source.geo.country_name`) y la URL (`url.original`).
2. **`SIEM - Operacional`.** *Filter for* sobre la IP en *Top IPs*.
3. En *Logs en tiempo real*, revisar las peticiones de esa IP en orden:
   - el **user agent** (`user_agent.original`): `sqlmap`, `gobuster` o `nikto` indican una herramienta automática;
   - qué **rutas** probó: `/.env` o `/.git` buscan credenciales; `/admin` o `/wp-login.php` buscan paneles.
4. **La pregunta clave: ¿la inyección funcionó?**
   - En Discover: `source.ip : "<IP>" and siem.sqli : true`. Agregar las columnas `http.response.status_code` y `http.response.body.bytes`.
   - Si una petición con inyección responde **200 con un tamaño mucho mayor** que las normales, probablemente devolvió datos. Eso es una **brecha**.
   - Errores 500 seguidos sugieren que la entrada llega a la base de datos sin sanitizar: **vulnerable**, aunque todavía no se haya explotado.
5. Clasificar:

| Situación | Severidad |
| --- | --- |
| Solo 404 y rutas sensibles (reconocimiento) | Media |
| SQLi con respuestas normales | Alta |
| SQLi con respuestas grandes o errores 500 | **Crítica** |

## 2. Contención

1. Bloquear la IP en el WAF o el balanceador. Si la IP viene de Tor o de un proveedor de nube, bloquear el rango o activar el *rate limiting*.
2. Si hay indicios de explotación, quitar del aire el endpoint afectado (por ejemplo, `location /buscar { return 503; }` en nginx) mientras se corrige.
3. Marcar las alertas como **Acknowledged** y abrir el caso.

## 3. Erradicación

1. Corregir el código del endpoint: **consultas parametrizadas** (nunca concatenar la entrada del usuario en el SQL) y validar el tipo (`id` numérico).
2. Si hubo brecha:
   - rotar las credenciales de la base de datos;
   - revisar qué tablas se consultaron (log de la base de datos);
   - evaluar si hay que notificar (en Colombia, la Ley 1581 obliga a reportar los incidentes con datos personales).
3. Quitar del servidor lo que no debe estar publicado: `.env`, `.git` y respaldos.

## 4. Recuperación

1. Volver a publicar el endpoint corregido y repetir el ataque (`atacante sqli`) para confirmar que ya no funciona.
2. Activar las reglas de inyección SQL de un WAF (por ejemplo, ModSecurity con OWASP CRS) como segunda capa.

## 5. Lecciones aprendidas (prueba del 4 nov 2026)

| Hora (UTC) | Evento |
| --- | --- |
| 05:38:07 | Empieza el ataque desde `185.220.101.34` (Alemania, nodo de salida de Tor), con curl y sqlmap |
| 05:38:39 | Alerta **Inyección SQL**: 32 s después; 7 peticiones marcadas, todas respondieron 200 con el tamaño normal (la víctima no tiene base de datos) |
| 05:38:41 | Empieza el reconocimiento desde `45.95.147.236` (Países Bajos) con user agent `gobuster` |
| 05:39:00 | Alerta **Ráfaga de 404** (40 peticiones a páginas inexistentes) |
| 05:39:06 | Alerta **Rutas sensibles**: 25 s después (`/.env`, `/.git/config`, `/admin`, `/phpmyadmin/`…) |

**Qué funcionó:** GeoIP ubicó las dos IPs en el mapa del dashboard ejecutivo, y el user agent delató la herramienta en los dos casos.

**Qué mejorar:**
- sqlmap probó con `--technique=BU` y casi todas sus peticiones no cuadraron con nuestras expresiones (solo se marcaron las de curl y algunas de sqlmap). Conviene agregar a la detección los patrones de *boolean-based blind* (`AND 1=1`, `AND 1=2`) y una regla por user agent de herramienta (`siem.herramienta_ataque : true`).
- La detección por expresiones regulares en la URL no ve las inyecciones que van en el cuerpo de un POST. Para eso hace falta un WAF o logs de la aplicación.
