# Guion de la sustentación y del video

**Miércoles 18 nov 2026.** Máximo 20 minutos. La nota es 70 % presentación y demo y 30 % guía y repo.
Diapositivas: [SIEM-Grupo5.pptx](SIEM-Grupo5.pptx) (también en [PDF](SIEM-Grupo5.pdf)). Cada diapositiva tiene en las notas quién habla y qué decir.

## Reparto (propuesto, ajústenlo entre ustedes)

| Min | Diapositivas | Quién | Tema |
| --- | --- | --- | --- |
| 0-3 | 1-3 | Valentina | Presentación, problema y los 8 requisitos |
| 3-6 | 4, 6 y 7 | Miguel | Arquitectura, clúster e ILM, ingesta y parseo |
| 6-14 | 5 y demo | Camilo | **Demo en vivo** (abajo, paso a paso) |
| 14-16 | 8-10 | Camilo | Reglas, tiempos y la correlación EQL |
| 16-18 | 12-13 | Valentina | Dashboards y playbooks |
| 18-19 | 14 | Miguel | Lecciones aprendidas |
| 19-20 | 15 | Todos | Preguntas |

La diapositiva 11 (panel SOC) se salta si ya se mostró en la demo. La 6, la 7 y la 9 a la 12 sirven de respaldo si la demo falla.

## Antes de entrar (10 minutos antes)

1. Si el PC se reinició, en PowerShell: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
2. `docker compose up -d` y esperar unos 2 minutos.
3. `bash scripts/verificar.sh`: el clúster debe estar en green y el parseo por encima del 95 %.
4. Abrir en el navegador, cada uno en su pestaña:
   - <http://localhost:8090> (panel SOC);
   - <http://localhost:5601> con la sesión ya iniciada (usuario `elastic`; la clave está en el `.env`);
   - Kibana → Security → Alerts;
   - el playbook en GitHub: `docs/playbooks/fuerza-bruta-ssh.md`.
5. Cerrar WhatsApp, notificaciones y pestañas personales. Zoom del navegador al 110-125 % para que se lea en el proyector.
6. Tener el video de respaldo a mano por si Docker no arranca.

## Demo paso a paso (≈ 8 minutos, Camilo)

| # | Qué se hace | Qué se dice |
| --- | --- | --- |
| 1 | Panel SOC (`:8090`): señalar clúster VERDE, eventos analizados, el 99 % de parseo y el flujo de logs en vivo | «Esto es lo que vería un analista en el turno: el estado del SIEM y los logs llegando en vivo.» |
| 2 | En «Simular ataques», clic en **EJECUTAR** en *Fuerza bruta SSH* | «Vamos a lanzar hydra de verdad contra el SSH de la víctima, con un diccionario para root y admin.» |
| 3 | Mientras corre (~40 s): mostrar la consola del ataque en el panel y el flujo de logs con los `ssh_login failure` | «Cada intento fallido queda en auth.log, Filebeat lo recoge y Logstash lo convierte en un evento ECS.» |
| 4 | Cuando sale el tiempo junto al botón, ir a Kibana → **Security → Alerts** y refrescar | «Alerta de fuerza bruta en unos 30 segundos. Y miren esta otra, en rojo: crítica, *Acceso tras fuerza bruta*. hydra adivinó la clave de admin.» |
| 5 | Abrir la alerta crítica y mostrar el `source.ip` | «Esta regla es una secuencia en EQL: 5 fallos y después un éxito desde la misma IP. Nos dice que no solo intentaron: entraron.» |
| 6 | Dashboards → **SIEM - Operacional**. En *Top IPs*, pasar el mouse por la IP y darle a **Filter for** | «El analista filtra por la IP y en una sola pantalla ve todo.» |
| 7 | Señalar *Top usuarios en SSH*: `admin` con 1 en **Exitosos**. Señalar los puertos tocados (si antes se lanzó el escaneo) | «Aquí está la prueba: un ingreso exitoso de admin. Esto se investigó en menos de un minuto.» |
| 8 | Dashboards → **SIEM - Ejecutivo** (últimos 7 días): mapa y tendencia | «Para gerencia: cuántos ataques hubo, de qué países y si van subiendo.» |
| 9 | Pestaña de GitHub con el playbook: secciones 1 (triage) y 2 (contención) | «Y esto es lo que hace el analista después: bloquear la IP, cerrar sesiones y bloquear la cuenta.» |

Si sobra tiempo: lanzar *Inyección SQL* desde el panel. Viene de una IP de Alemania, sale en el mapa y alerta en unos 20 s.

### Plan B

- **La alerta no sale en 60 s:** las reglas corren cada 30 s, así que basta con refrescar. Si el clúster está lento, mostrar la diapositiva 9 (tiempos medidos) y la captura `docs/evidencias/R8.5-alertas.png`.
- **Docker no arranca:** pasar al video de respaldo y usar las diapositivas 9 a 12, que tienen capturas reales de la corrida del 18 nov.

## Preguntas probables

- **¿Por qué data streams y no índices con fecha?** El rollover y el ILM los maneja Elasticsearch solo, y con `ecs@mappings` los campos quedan bien tipados (`source.ip` como ip y la ubicación como geo_point).
- **¿Cómo se lleva esto a la nube?** Elastic Cloud o 3 VMs con el mismo compose, y Filebeat en cada servidor real. El ILM con warm y cold es justo donde se ahorra, porque los datos viejos van a discos más baratos.
- **¿Qué pasa con los falsos positivos?** Las excepciones: el operador entra de noche a propósito, así que la regla de horario lo excluye. La correlación también baja el ruido: 50 fallos y 1 éxito quedan en una sola alerta crítica.
- **¿Por qué una víctima real y no solo logs inventados?** Para que los ataques sean de verdad: hydra contra sshd y nmap contra los puertos. El histórico de 7 días solo sirve para llenar los tableros.
- **¿Cómo detectan el escaneo si un contenedor no tiene firewall?** Con puertos señuelo (portguard): cualquier conexión a un puerto que no se usa queda registrada.
- **¿Qué no detecta?** Inyecciones en el cuerpo de un POST, porque solo miramos la URL; para eso hace falta un WAF. Tampoco la técnica *boolean-based blind* de sqlmap. Está en el playbook, en «Qué mejorar».

## Video de respaldo (6-8 minutos)

Grabarlo con OBS o con la grabadora de Windows (`Win + Alt + R`), en pantalla completa y a 1080p. Es el mismo recorrido de la demo, con voz:

1. **(0:00-0:40) Presentación.** Diapositivas 1 y 4: quiénes somos y la arquitectura en una frase cada uno.
2. **(0:40-1:30) El stack arriba.** En la terminal, `docker compose ps` y `bash scripts/verificar.sh`: green, 3 nodos, 99 %.
3. **(1:30-2:30) Panel SOC.** Recorrer las tarjetas, la gráfica y el flujo de logs.
4. **(2:30-4:00) Ataque en vivo.** Fuerza bruta desde el panel. Dejar correr el cronómetro hasta que aparezca el tiempo de la alerta.
5. **(4:00-5:00) Alertas.** Security → Alerts. Abrir la crítica *Acceso tras fuerza bruta*.
6. **(5:00-6:00) Investigación.** Operacional → Filter for la IP → `admin` con 1 éxito.
7. **(6:00-6:45) Ejecutivo.** Mapa y tendencia de la semana.
8. **(6:45-7:30) Playbook y cierre.** El playbook en GitHub y el enlace al repo.

Para un ataque más fluido en el video, lanzar antes el *Escaneo de puertos*: así el operacional muestra también los 19 puertos tocados por la misma IP.
