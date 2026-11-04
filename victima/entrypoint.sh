#!/usr/bin/env bash
set -euo pipefail

: "${ADMIN_PASSWORD:?Falta VICTIMA_ADMIN_PASSWORD en .env}"
: "${OPERADOR_PASSWORD:?Falta VICTIMA_OPERADOR_PASSWORD en .env}"
echo "admin:${ADMIN_PASSWORD}"       | chpasswd
echo "operador:${OPERADOR_PASSWORD}" | chpasswd

mkdir -p /var/log/nginx /run/sshd
touch /var/log/auth.log /var/log/syslog /var/log/nginx/access.log
chmod 644 /var/log/auth.log /var/log/syslog /var/log/nginx/access.log

rm -f /run/rsyslogd.pid
rsyslogd
until [ -S /dev/log ]; do sleep 0.2; done
ssh-keygen -A > /dev/null
/usr/sbin/sshd
nginx
python3 /usr/local/bin/portguard.py &

logger -t arranque "Servidor victima iniciado"

# Actividad de fondo para que syslog no quede vacío
while true; do
  logger -t cron "(root) CMD (/usr/local/bin/respaldo.sh)"
  sleep 60
done
