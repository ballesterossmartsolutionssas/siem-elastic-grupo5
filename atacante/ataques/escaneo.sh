#!/usr/bin/env bash
# Escenario 2: escaneo de puertos con nmap.
# -sT (connect) completa el handshake, así portguard ve cada conexión.
# Un -sS (SYN) no la completa y solo se vería con logs de firewall.
set -u
echo "== [$(date -u +%T)] Escaneo nmap contra ${OBJETIVO}"
nmap -sT -Pn -T4 -p 1-1024,1433,1521,3306,3389,5432,5900,6379,8081,8443,9000,11211,27017 "${OBJETIVO}"
echo "== [$(date -u +%T)] Fin. En Kibana: Security -> Alerts -> 'SIEM - Escaneo de puertos'"
