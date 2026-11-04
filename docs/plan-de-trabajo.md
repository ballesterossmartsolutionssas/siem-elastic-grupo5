# Plan de trabajo

**Entrega:** miércoles 18 nov 2026, 18:30: repo y diapositivas, más la sustentación (máx. 20 min).
**Nota:** 70 % presentación y demo · 30 % guía paso a paso y repo.

## Reparto propuesto (a confirmar en el grupo)

| Frente | Requisitos | Responsable |
| --- | --- | --- |
| Stack e ingesta: compose, ILM, Filebeat, Logstash y tasa de parseo | R8.1, R8.2, R8.3 | Camilo |
| Detección: reglas, ataques, tiempos de alerta y evidencias | R8.4, R8.5 | _(por definir)_ |
| Dashboards, playbooks y diapositivas | R8.6, R8.7, R8.8 | _(por definir)_ |

## Calendario

| Fecha | Meta |
| --- | --- |
| 5-6 nov | Stack arriba en el PC de cada uno; `scripts/verificar.sh` en verde |
| 7-9 nov | Logstash al 95 % o más; los 4 ataques generan alerta; capturas de tiempos |
| 10-12 nov | Dashboards ejecutivo y operacional exportados al repo |
| 13-15 nov | Playbooks con capturas; prueba cruzada (cada uno sigue el playbook del otro) |
| 16-17 nov | Diapositivas, README final y ensayo cronometrado de la demo |
| 18 nov | Entrega antes de las 18:30 |

## Riesgos

- **RAM:** si un PC no aguanta, bajar `ES_HEAP` a `512m` en `.env`, o hacer la demo desde el PC que sí aguante.
- **Demo en vivo:** tener el stack arriba desde antes de presentar (tarda unos 5 min en arrancar) y un video de respaldo.
- **vm.max_map_count** en Windows se pierde al reiniciar Docker Desktop (ver README, paso 1).
