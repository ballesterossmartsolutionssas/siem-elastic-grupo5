# Guion de la sustentación y del video

**Miércoles 18 nov 2026.** Máximo 20 minutos. La nota es 70 % presentación y demo y 30 % guía y repo.
Diapositivas: [SIEM-Grupo5.pptx](SIEM-Grupo5.pptx) (también en [PDF](SIEM-Grupo5.pdf)). Cada diapositiva tiene en las notas quién habla y qué decir.

## Cómo cubrimos la rúbrica

| Criterio de la rúbrica | Dónde se ve |
| --- | --- |
| Buena introducción | Diapositivas 1 y 2: el problema |
| Descripción de las tecnologías | Diapositiva 3 |
| Descripción de la solución | Diapositivas 4, 5, 7 y 8 |
| Pruebas realizadas | Demo en vivo y diapositivas 9 a 11 (tiempos medidos) |
| Se cumplen los objetivos | Franja R8.1-R8.8 del panel, en vivo |
| Conclusiones | Diapositivas 16 (lecciones) y 17 (conclusiones) |
| Ayudas audiovisuales | Panel SOC, Kibana y diapositivas con capturas reales |
| Tiempo | El reparto de abajo suma 20 minutos |
| Guía paso a paso | README del repo (pasos 1 a 9) |

## Reparto (propuesto, ajústenlo entre ustedes)

| Min | Diapositivas | Quién | Tema |
| --- | --- | --- | --- |
| 0-2 | 1, 2 y 4 | Valentina | Presentación, problema y los 8 requisitos |
| 2-5 | 3, 5, 7 y 8 | Miguel | Tecnologías, arquitectura, clúster e ILM, ingesta y parseo |
| 5-13 | 6 y demo | Camilo, más Valentina o Miguel en la investigación | **Demo en vivo** (abajo, paso a paso) |
| 13-15 | 9 a 11 | Camilo | Reglas, tiempos y correlación EQL |
| 15-17 | 13 a 15 | Valentina | Investigación guiada, dashboards y playbooks |
| 17-18 | 16 | Miguel | Lecciones aprendidas |
| 18-19 | 17 | Camilo | Conclusiones |
| 19-20 | 18 | Todos | Preguntas |

La diapositiva 12 (panel SOC) se salta si ya se mostró en la demo. Las 7 a 15 sirven de respaldo si la demo falla.

## Antes de entrar (10 minutos antes)

1. Si el PC se reinició, en PowerShell: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
2. `docker compose up -d` y esperar unos 2 minutos. Si se tocaron reglas o dashboards: `docker compose run --rm --no-deps kibana-setup`.
3. Abrir <http://localhost:8090>: la franja de arriba debe tener R8.1 a R8.6 en verde.
4. **R8.7 y R8.8 (importante):** el criterio dice que el playbook lo debe seguir *un integrante que no participó en su creación*. Antes de entrar, Valentina y Miguel hacen cada uno **una investigación guiada** en el panel (ver abajo). Así las dos casillas quedan en verde y la tabla «Investigaciones guiadas registradas» muestra los nombres y los tiempos.
5. Abrir en el navegador, cada uno en su pestaña:
   - el panel (`:8090`);
   - Kibana (`:5601`) con la sesión iniciada (usuario `elastic`; la clave está en el `.env`);
   - Kibana → Security → Alerts;
   - el dashboard ejecutivo.
6. Cerrar WhatsApp, las notificaciones y las pestañas personales. Zoom del navegador al 110-125 %.
7. Tener el video de respaldo a mano.

### Cómo se hace una investigación guiada

1. En el panel, en **Incidentes · 24 h**, clic en la IP de una alerta (la crítica en rojo es la mejor).
2. Clic en **«Iniciar investigación guiada (playbook)»**. Arranca el cronómetro.
3. Escribir el nombre, seguir los 4 pasos del triage (los enlaces abren Kibana ya filtrado), confirmar la clasificación y marcar la contención.
4. **«Cerrar incidente y registrar el tiempo»**. Tiene que quedar por debajo de 5:00.

## Demo paso a paso (≈ 8 minutos)

| # | Qué se hace | Qué se dice |
| --- | --- | --- |
| 1 | Panel (`:8090`): la franja **R8.1 a R8.8** en verde, el clúster, el 99 % de parseo, la salud de los nodos y la **detección de anomalías** | «Arriba se ve cada requisito del enunciado con su medición real. Ahora el volumen está normal; fíjense en este número cuando ataquemos.» |
| 2 | En «Simular ataques», **EJECUTAR** en *Fuerza bruta SSH* | «Lanzamos hydra de verdad contra el SSH de la víctima, con un diccionario para root y admin.» |
| 3 | Mientras corre (~35 s): la consola del ataque, el flujo de logs con los `ssh_login failure` y el **z-score**, que se pone rojo: **VOLUMEN ANÓMALO** | «Cada intento queda en auth.log. Filebeat lo recoge, Logstash lo convierte a ECS y el panel detecta que el volumen se salió de lo normal.» |
| 4 | Junto al botón sale «✔ alerta en ~12 s». En **Incidentes**, esperar unos 30-60 s a que salgan la crítica *Acceso tras fuerza bruta* y la de *Ingreso desde una IP nueva* | «Alerta de fuerza bruta en 12 segundos. Y esta en rojo es crítica: la regla EQL vio 5 fallos y luego un ingreso. hydra adivinó la clave de admin. La de IP nueva es la detección de anomalías: admin nunca había entrado desde ahí.» |
| 5 | Clic en la IP: fallos, **1 ingreso exitoso** en rojo, puertos y reglas | «Esto es lo primero que ve el analista.» |
| 6 | **Valentina o Miguel** pasa al computador: **Iniciar investigación guiada**, sigue los pasos (abre el operacional filtrado) y cierra el incidente | «El enunciado pide que el playbook lo siga alguien que no lo escribió, y en menos de 5 minutos. Miren el cronómetro.» |
| 7 | El resultado: «Incidente cerrado por … en 2:xx ✓». La tabla de investigaciones y la casilla R8.7 en verde | «Queda registrado quién lo hizo y en cuánto tiempo.» |
| 8 | Kibana → **SIEM - Ejecutivo** (últimos 7 días): mapa y tendencia | «Para gerencia: cuántos ataques hubo, de qué países y si van subiendo.» |

Si sobra tiempo: lanzar *Inyección SQL* desde el panel. Viene de una IP de Alemania, sale en el mapa y alerta en unos 20 s.

### Plan B

- **La alerta no sale:** las reglas corren cada 30 s; basta con esperar o refrescar. Si el clúster está lento, mostrar las diapositivas 10 y 11 (tiempos medidos).
- **Docker no arranca:** pasar al video de respaldo y usar las diapositivas 9 a 15, que tienen capturas reales.

## Preguntas probables

- **¿Y los logs de Kubernetes?** El enunciado pide mínimo 3 fuentes y tenemos 4: auth, nginx, syslog y los puertos señuelo. Kubernetes quedó documentado como extra en `docs/kubernetes.md`: Filebeat como DaemonSet con el input `container`, apuntando al mismo Logstash. El pipeline no cambia porque todo llega en ECS.
- **¿Dónde está el *machine learning*?** El ML de Elastic pide licencia Platinum. Con la licencia Basic hicimos la detección de anomalías de otras formas: la regla *new terms* (usuario + IP nunca vista en 7 días), la secuencia EQL y el z-score del volumen en el panel.
- **¿Por qué data streams y no índices con fecha?** El rollover y el ILM los maneja Elasticsearch solo, y con `ecs@mappings` los campos quedan bien tipados.
- **¿Cómo se lleva esto a la nube?** Elastic Cloud, o 3 VMs con el mismo compose y Filebeat en cada servidor real. El ILM con warm y cold es donde se ahorra, porque los datos viejos pasan a discos más baratos.
- **¿Qué pasa con los falsos positivos?** Las excepciones: el operador entra de noche a propósito y la regla de horario lo excluye. La correlación también baja el ruido: 50 fallos y 1 éxito quedan en una sola alerta crítica.
- **¿Qué no detecta?** Inyecciones en el cuerpo de un POST, porque solo miramos la URL (hace falta un WAF), y la técnica *boolean-based blind* de sqlmap. Está en el playbook, en «Qué mejorar».

## Video de respaldo (6-8 minutos)

Grabarlo con OBS o con la grabadora de Windows (`Win + Alt + R`), en pantalla completa y a 1080p:

1. **(0:00-0:40) Presentación.** Diapositivas 1 y 5: quiénes somos y la arquitectura.
2. **(0:40-1:30) El panel.** La franja R8.1-R8.8, la salud de los nodos y las anomalías.
3. **(1:30-3:00) Ataque en vivo.** Fuerza bruta desde el panel, hasta que salga el tiempo de la alerta y el z-score en rojo.
4. **(3:00-4:00) Alertas.** La crítica y la de IP nueva en *Incidentes*, y luego en Kibana → Security → Alerts.
5. **(4:00-6:00) Investigación guiada.** Clic en la IP → iniciar → seguir los pasos → cerrar. Que se vea el tiempo final.
6. **(6:00-6:45) Ejecutivo.** Mapa y tendencia de la semana.
7. **(6:45-7:30) Cierre.** El repo en GitHub y las conclusiones.
