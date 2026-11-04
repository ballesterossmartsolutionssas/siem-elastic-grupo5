#!/usr/bin/env bash
# Tráfico legítimo en bucle: visitas a la tienda desde IPs colombianas y, de vez en cuando,
# un ingreso SSH correcto del operador. Es la "línea base" contra la que se ven los ataques.
set -u
BASE="http://${OBJETIVO}"
IPS=(190.85.32.10 181.49.112.7 186.30.44.21 190.27.205.9 179.19.80.33 191.95.140.6 200.21.66.150)
RUTAS=(/ /buscar?q=zapatos /buscar?q=camisa /producto?id=7 /producto?id=12 /login /static/logo.png)

sleep 20
while true; do
  ip=${IPS[$RANDOM % ${#IPS[@]}]}
  ruta=${RUTAS[$RANDOM % ${#RUTAS[@]}]}
  curl -s -o /dev/null -H "X-Forwarded-For: ${ip}" \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36" "${BASE}${ruta}" || true

  if [ $((RANDOM % 30)) -eq 0 ]; then
    sshpass -p "${OPERADOR_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR "operador@${OBJETIVO}" uptime > /dev/null 2>&1 || true
  fi
  sleep $((RANDOM % 4 + 1))
done
