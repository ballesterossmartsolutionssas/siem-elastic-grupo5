#!/usr/bin/env bash
# Exporta todos los dashboards (con sus visualizaciones y data views) a kibana/dashboards/.
source "$(dirname "$0")/_comun.sh"
destino=kibana/dashboards/siem-dashboards.ndjson
kb POST /api/saved_objects/_export '{"type":["dashboard"],"includeReferencesDeep":true,"excludeExportDetails":true}' > "$destino"
echo "Exportados $(wc -l < "$destino") objetos a $destino"
