# Servidor víctima del laboratorio: sshd + nginx + puertos señuelo, con logs reales.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsyslog nginx python3 sudo procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default \
 && useradd -m -s /bin/bash admin \
 && useradd -m -s /bin/bash operador \
 && usermod -aG sudo admin \
 && mkdir -p /run/sshd /var/www/siem

COPY rsyslog.conf     /etc/rsyslog.conf
COPY sshd-siem.conf   /etc/ssh/sshd_config.d/siem.conf
COPY nginx-siem.conf  /etc/nginx/conf.d/siem.conf
COPY www/             /var/www/siem/
COPY portguard.py     /usr/local/bin/portguard.py
COPY entrypoint.sh    /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
