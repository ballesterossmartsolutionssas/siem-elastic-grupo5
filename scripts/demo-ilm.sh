#!/usr/bin/env bash
# Prueba acelerada de ILM (R8.1): la política siem-demo hace en minutos lo que siem-30d hace en días.
#   hot (rollover cada 1 min) -> warm a los 2 min -> cold a los 4 min -> delete a los 30 min
# Deja corriendo ~8 minutos y muestra en qué fase está cada índice.
source "$(dirname "$0")/_comun.sh"

echo "== ILM revisa cada 10 s (por defecto cada 10 min)"
es PUT /_cluster/settings '{"persistent":{"indices.lifecycle.poll_interval":"10s"}}'; echo

for i in $(seq 1 48); do
  es POST /logs-siem.ilmdemo-default/_doc \
    "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"message\":\"evento de prueba ILM $i\"}" > /dev/null
  if [ $((i % 6)) -eq 0 ]; then
    echo; echo "== Minuto $((i / 6)): fase de cada índice"
    es GET "/.ds-logs-siem.ilmdemo-*/_ilm/explain?filter_path=indices.*.phase,indices.*.action,indices.*.age" \
      | sed 's/},/},\n/g'
  fi
  sleep 10
done

echo; echo "== Volviendo poll_interval a su valor por defecto"
es PUT /_cluster/settings '{"persistent":{"indices.lifecycle.poll_interval":null}}'; echo
