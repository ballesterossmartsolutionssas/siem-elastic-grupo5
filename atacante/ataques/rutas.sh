#!/usr/bin/env bash
# Rutas sensibles y ráfaga de 404 (enumeración de directorios).
set -u
IP_PUBLICA="${IP_PUBLICA:-45.95.147.236}"
BASE="http://${OBJETIVO}"
H="X-Forwarded-For: ${IP_PUBLICA}"
echo "== [$(date -u +%T)] Rutas sensibles y ráfaga de 404 contra ${BASE} (XFF ${IP_PUBLICA})"

for ruta in /.env /.git/config /admin /wp-admin/ /wp-login.php /phpmyadmin/ /config.php /server-status /backup.zip; do
  curl -s -o /dev/null -w "%{http_code}  ${ruta}\n" -H "$H" -A "gobuster/3.6" "${BASE}${ruta}"
done

for i in $(seq 1 40); do
  curl -s -o /dev/null -H "$H" -A "gobuster/3.6" "${BASE}/pagina-que-no-existe-${i}"
done
echo "   40 peticiones 404 enviadas"
echo "== [$(date -u +%T)] Fin. Alertas: 'SIEM - Rutas sensibles' y 'SIEM - Ráfaga de 404'"
