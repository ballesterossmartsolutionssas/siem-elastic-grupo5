#!/usr/bin/env bash
# R8.5: corre un escenario de ataque y mide cuánto tarda en aparecer la alerta en Kibana.
# Uso: bash scripts/atacar-y-medir.sh <escenario> "<nombre de la regla>"
#   bash scripts/atacar-y-medir.sh fuerza-bruta "SIEM - Fuerza bruta SSH"
#   bash scripts/atacar-y-medir.sh escaneo      "SIEM - Escaneo de puertos"
#   bash scripts/atacar-y-medir.sh sqli         "SIEM - Inyección SQL"
#   bash scripts/atacar-y-medir.sh rutas        "SIEM - Acceso a rutas sensibles"
source "$(dirname "$0")/_comun.sh"
escenario=$1; regla=$2

inicio=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
inicio_s=$(date -u +%s)
echo "== $(date +%T) Inicio del ataque '$escenario'"
docker compose run --rm atacante "$escenario"

echo "== Esperando la alerta '$regla' (máximo 3 min)"
consulta=$(printf '{"size":1,"sort":[{"@timestamp":"asc"}],"_source":["@timestamp","kibana.alert.rule.name","kibana.alert.severity"],"query":{"bool":{"filter":[{"term":{"kibana.alert.rule.name":"%s"}},{"range":{"@timestamp":{"gte":"%s"}}}]}}}' "$regla" "$inicio")
for _ in $(seq 1 36); do
  r=$(es POST "/.alerts-security.alerts-default/_search?filter_path=hits.hits._source" "$consulta")
  if echo "$r" | grep -q '@timestamp'; then
    ts=$(echo "$r" | sed -E 's/.*"@timestamp":"([^"]+)".*/\1/')
    alerta_s=$(date -u -d "$ts" +%s)
    echo "== ALERTA: '$regla' a las $ts  ->  $((alerta_s - inicio_s)) s desde el inicio del ataque"
    exit 0
  fi
  sleep 5
done
echo "== No llegó la alerta en 3 minutos"; exit 1
