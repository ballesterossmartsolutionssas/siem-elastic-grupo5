# Máquina atacante del laboratorio (y también el "tráfico normal").
# Solo apunta al contenedor victima, dentro de la red de Docker.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap hydra sqlmap curl sshpass openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY ataques/ /ataques/
COPY claves.txt /ataques/claves.txt
RUN chmod +x /ataques/*.sh

ENV OBJETIVO=victima
ENTRYPOINT ["/ataques/correr.sh"]
CMD ["ayuda"]
