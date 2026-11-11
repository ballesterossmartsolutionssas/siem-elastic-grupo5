#!/usr/bin/env bash
# Demo para la sustentación, paso a paso: cada Enter pasa al siguiente punto.
# Antes: docker compose up -d   (y esperar ~2 min a que kibana-setup termine)
# Uso:   bash scripts/demo.sh
source "$(dirname "$0")/_comun.sh"

paso() { echo; echo "================================================================"; echo "  $1"; echo "================================================================"; }
pausa() { read -r -p "  [Enter para seguir] " _; }
abrir() { cmd.exe /c start "" "$1" 2>/dev/null || xdg-open "$1" 2>/dev/null || open "$1" 2>/dev/null || echo "  Abrir: $1"; }

paso "1. Arquitectura: los contenedores del stack"
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
pausa

paso "2. R8.1-R8.3: clúster green, data streams con ILM y tasa de parseo"
bash scripts/verificar.sh
pausa

paso "3. R8.6: dashboard ejecutivo (Kibana, usuario elastic)"
abrir "http://localhost:5601/app/dashboards#/view/siem-dashboard-ejecutivo"
pausa

paso "4. R8.5 en vivo: fuerza bruta SSH con hydra y tiempo hasta la alerta"
bash scripts/atacar-y-medir.sh fuerza-bruta "SIEM - Fuerza bruta SSH"
pausa

paso "5. R8.7: dashboard operacional -> Top IPs -> 'Filter for' sobre la IP atacante"
abrir "http://localhost:5601/app/dashboards#/view/siem-dashboard-operacional"
pausa

paso "6. R8.4: las 6 reglas de detección"
abrir "http://localhost:5601/app/security/rules"
pausa

paso "7. R8.1: ILM - política de 30 días y fase actual de cada índice"
es GET "/_ilm/policy/siem-30d?filter_path=*.policy.phases.*.min_age&pretty"
es GET "/logs-siem.*/_ilm/explain?filter_path=indices.*.phase,indices.*.policy&pretty"
echo "  (La prueba acelerada hot -> warm -> cold dura 8 min: bash scripts/demo-ilm.sh)"
pausa

paso "8. R8.8: playbook de respuesta en el repo"
abrir "https://github.com/ballesterossmartsolutionssas/siem-elastic-grupo5/blob/main/docs/playbooks/fuerza-bruta-ssh.md"
echo; echo "  Fin de la demo."
