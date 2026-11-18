# Guion de la sustentación

> **Versión vigente: [guion-sustentacion.pdf](guion-sustentacion.pdf).** El profesor pidió 15 minutos de diapositivas y la demo en video al final. El reparto quedó así: Valentina hace las diapositivas 1-4, 13 y 14; Miguel, la 6, 7, 8 y 15; Camilo, la 5, 9-12, 16, 17 y el video. Lo que sigue es la versión anterior, como referencia.

**Miércoles 18 nov 2026.** Máximo 20 minutos. La nota es 70 % presentación y demo y 30 % guía y repo.

- Diapositivas: [SIEM-Grupo5.pptx](SIEM-Grupo5.pptx), también en [PDF](SIEM-Grupo5.pdf). Las notas de cada diapositiva dicen quién habla y qué decir.
- **Demo: [demo-SIEM-Grupo5.mp4](demo-SIEM-Grupo5.mp4).** El profesor pidió la demo **grabada y sin audio**, para que no falle en clase. El video trae subtítulos que explican cada parte. Lo graba `python scripts/grabar-demo.py`: si algo cambia, se vuelve a grabar en unos 12 minutos.

## Cómo cubrimos la rúbrica

| Criterio de la rúbrica | Dónde se ve |
| --- | --- |
| Buena introducción | Diapositivas 1 y 2: el problema |
| Descripción de las tecnologías | Diapositiva 3 |
| Descripción de la solución | Diapositivas 4, 5, 7 y 8 |
| Pruebas realizadas | El video y las diapositivas 9 a 11, con tiempos medidos |
| Se cumplen los objetivos | Franja R8.1-R8.8 del panel, en el video |
| Conclusiones | Diapositivas 16 (lecciones) y 17 (conclusiones) |
| Ayudas audiovisuales | Video con subtítulos, panel SOC, Kibana y capturas reales |
| Tiempo | El reparto de abajo suma 20 minutos |
| Guía paso a paso | README del repo (pasos 1 a 9) |

## Reparto (propuesto, ajústenlo entre ustedes)

| Min | Diapositivas | Quién | Tema |
| --- | --- | --- | --- |
| 0-2 | 1, 2 y 4 | Valentina | Presentación, problema y los 8 requisitos |
| 2-5 | 3, 5, 7 y 8 | Miguel | Tecnologías, arquitectura, clúster e ILM, ingesta y parseo |
| 5-11 | 6 y el **video** | Camilo | La demo grabada, pausando para explicar cada parte (abajo) |
| 11-13 | 9 a 11 | Camilo | Reglas, tiempos y correlación EQL |
| 13-16 | 13 a 15 | Valentina | Investigación guiada, dashboards y playbooks |
| 16-17 | 16 | Miguel | Lecciones aprendidas |
| 17-18 | 17 | Camilo | Conclusiones |
| 18-20 | 18 | Todos | Preguntas |

La diapositiva 12 (panel SOC) se puede saltar: ya sale en el video.

## Antes de la clase

1. **R8.8 (importante).** El criterio dice que el playbook lo debe seguir *un integrante que no participó en su creación*. Valentina y Miguel hacen cada uno **una investigación guiada** en el panel (ver abajo). Así las casillas R8.7 y R8.8 quedan en verde y la tabla de investigaciones muestra sus nombres y sus tiempos. La investigación del video («Demo grabada») no cuenta para R8.8.
2. Si quieren que el video muestre R8.8 en verde, después de esas dos investigaciones se vuelve a grabar con `python scripts/grabar-demo.py`.
3. **R8.6:** cada uno le muestra el dashboard ejecutivo a una persona no técnica y llena [evaluacion-dashboard-ejecutivo.md](../docs/evidencias/evaluacion-dashboard-ejecutivo.md). Son 5 preguntas, 2 minutos.
4. Probar que el video se reproduce en el computador del salón. Llevarlo también en una USB.

### Cómo se hace una investigación guiada

1. Levantar el stack (`docker compose up -d`) y abrir <http://localhost:8090>.
2. En **Incidentes · 24 h**, clic en la IP de una alerta. La crítica, en rojo, es la mejor.
3. Clic en **«Iniciar investigación guiada (playbook)»**. Arranca el cronómetro.
4. Escribir el nombre y seguir los 4 pasos del triage (los enlaces abren Kibana ya filtrado). Confirmar la clasificación y marcar la contención.
5. **«Cerrar incidente y registrar el tiempo»**. Tiene que quedar por debajo de 5:00.

Si no hay alertas recientes, primero se lanza un ataque con el botón **EJECUTAR** de *Fuerza bruta SSH*.

## El video, parte por parte

El video no tiene audio. Quien presenta puede pausarlo al final de cada parte y agregar lo de la columna derecha.

| Parte | Qué se ve | Qué se puede agregar |
| --- | --- | --- |
| Portada | Qué se va a ver | — |
| El stack | `docker compose ps` con los 11 contenedores, los pods de Kubernetes y el DaemonSet de Filebeat | «Todo se levanta con un comando; Kubernetes es la cuarta fuente del enunciado.» |
| Panel SOC | La franja R8.1-R8.8, la tasa de parseo, la salud de los nodos, el ILM y las anomalías | «Cada casilla se calcula con datos reales, no está escrita a mano.» |
| Ataque real | El botón lanza hydra; la consola; «alerta en ~12 s»; el z-score en rojo | «El enunciado pide menos de 60 s.» |
| Incidentes | La alerta crítica (EQL) y la de IP nueva (*new terms*); la ficha de la IP con 1 ingreso exitoso | «La regla de correlación dice que el atacante entró, no solo que lo intentó.» |
| Investigación guiada | El playbook con cronómetro, paso a paso, y el registro | «Así se mide R8.7 (menos de 5 minutos) y se prueba R8.8.» |
| Kibana Security | Las alertas en Kibana | «8 reglas, todas con su técnica de MITRE.» |
| Operacional | Dashboard filtrado por la IP atacante, con drill-down | «Toda la historia del atacante en una pantalla.» |
| Ejecutivo | Alertas, mapa, tendencia y salud | «Para alguien que no es técnico.» |
| Errores | Índice de rechazados con su motivo | «Menos del 1 %, y no se pierden.» |
| Kubernetes | Logs de los pods con namespace, pod y nodo | «Mismo pipeline, mismo ECS.» |
| ILM | Índices en HOT, WARM y COLD | «En la nube, warm y cold son el ahorro.» |
| Playbook | El playbook en GitHub | «Investigación, contención, erradicación y lecciones.» |
| Cierre | Resumen de resultados | — |

### Plan B

- **El video no abre en el computador del salón:** está también en GitHub (`diapositivas/demo-SIEM-Grupo5.mp4`) y en la USB. Si nada funciona, las diapositivas 9 a 15 tienen capturas reales de cada parte.

## Preguntas probables

- **¿Cómo se ven los logs de Kubernetes?** Un clúster k3s, creado con k3d, corre dentro de la misma red de Docker. Un Filebeat como DaemonSet lee `/var/log/containers` y les agrega namespace, pod y nodo. Todo va al mismo Logstash (`50-k8s.conf`) y llega a `logs-siem.k8s-default`. Ver `docs/kubernetes.md`.
- **¿Dónde está el *machine learning*?** El ML de Elastic pide licencia Platinum. Con la licencia Basic hicimos la detección de anomalías de otras formas: la regla *new terms* (usuario + IP nunca vista en 7 días), la secuencia EQL y el z-score del volumen en el panel.
- **¿Por qué la demo es un video?** Lo pidió el profesor. Además lo graba un script, así que es reproducible: el ataque, las alertas y los tiempos son reales en cada grabación.
- **¿Por qué data streams y no índices con fecha?** El rollover y el ILM los maneja Elasticsearch solo, y con `ecs@mappings` los campos quedan bien tipados.
- **¿Cómo se lleva esto a la nube?** Elastic Cloud, o 3 VMs con el mismo compose y Filebeat en cada servidor real o en cada clúster de Kubernetes. El ILM con warm y cold es donde se ahorra, porque los datos viejos pasan a discos más baratos.
- **¿Qué pasa con los falsos positivos?** Las excepciones: el operador entra de noche a propósito y la regla de horario lo excluye. La correlación también baja el ruido: 50 fallos y 1 éxito quedan en una sola alerta crítica.
- **¿Qué no detecta?** Inyecciones en el cuerpo de un POST, porque solo miramos la URL (hace falta un WAF), y la técnica *boolean-based blind* de sqlmap. Está en el playbook, en «Qué mejorar».
