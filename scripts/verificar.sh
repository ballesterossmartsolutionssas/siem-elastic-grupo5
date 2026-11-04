#!/usr/bin/env bash
# Evidencias rápidas para R8.1, R8.2 y R8.3: salud, nodos, data streams, ILM y tasa de parseo.
source "$(dirname "$0")/_comun.sh"

echo "== Salud del clúster (R8.1: debe ser green)"
es GET "/_cluster/health?filter_path=cluster_name,status,number_of_nodes,active_shards,unassigned_shards&pretty"

echo; echo "== Nodos"
es GET "/_cat/nodes?v&h=name,node.role,master,heap.percent,ram.percent"

echo; echo "== Data streams del SIEM y su política ILM"
es GET "/_cat/indices/logs-siem.*?v&h=index,health,docs.count,store.size&s=index&expand_wildcards=all"
es GET "/_data_stream/logs-siem.*?filter_path=data_streams.name,data_streams.ilm_policy,data_streams.status&pretty"

echo; echo "== Tasa de parseo (R8.3: > 95 %)"
total=$(es GET "/logs-siem.*/_count" | sed -E 's/.*"count":([0-9]+).*/\1/')
errores=$(es GET "/logs-siem.errores-*/_count" 2>/dev/null | sed -E 's/.*"count":([0-9]+).*/\1/;t;s/.*/0/')
if [ "${total:-0}" -gt 0 ]; then
  awk -v t="$total" -v e="$errores" 'BEGIN { printf "   %d eventos, %d rechazados -> %.2f %% parseados bien\n", t, e, (t-e)*100/t }'
else
  echo "   Todavía no hay eventos"
fi

echo; echo "== Motivos de rechazo"
es GET "/logs-siem.errores-*/_search?size=0&filter_path=aggregations" \
  '{"aggs":{"motivos":{"terms":{"field":"error.message.keyword","missing":"(sin motivo)"}}}}' || true
echo
