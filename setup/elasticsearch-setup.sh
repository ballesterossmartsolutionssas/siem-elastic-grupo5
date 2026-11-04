#!/usr/bin/env bash
# =============================================================================
# 1) Certificados (CA + uno por nodo).  2) Espera el clúster.
# 3) Contraseña de kibana_system, rol y usuario de Logstash, ILM y templates.
# Es idempotente: se puede correr varias veces.
# =============================================================================
set -euo pipefail

: "${ELASTIC_PASSWORD:?Falta ELASTIC_PASSWORD en .env}"
: "${KIBANA_PASSWORD:?Falta KIBANA_PASSWORD en .env}"
: "${LOGSTASH_PASSWORD:?Falta LOGSTASH_PASSWORD en .env}"

cd /usr/share/elasticsearch
CERTS=config/certs
CA="$CERTS/ca/ca.crt"
ES="https://es01:9200"

# ---- 1. Certificados --------------------------------------------------------
if [ ! -f "$CERTS/ca.zip" ]; then
  echo "== Creando la CA"
  bin/elasticsearch-certutil ca --silent --pem -out "$CERTS/ca.zip"
  unzip -o -q "$CERTS/ca.zip" -d "$CERTS"
fi
if [ ! -f "$CERTS/certs.zip" ]; then
  echo "== Creando los certificados de los nodos"
  bin/elasticsearch-certutil cert --silent --pem \
    -out "$CERTS/certs.zip" --in /setup/instances.yml \
    --ca-cert "$CERTS/ca/ca.crt" --ca-key "$CERTS/ca/ca.key"
  unzip -o -q "$CERTS/certs.zip" -d "$CERTS"
fi
chown -R root:root "$CERTS"
find "$CERTS" -type d -exec chmod 755 {} \;
find "$CERTS" -type f -name '*.key' -exec chmod 640 {} \;
find "$CERTS" -type f -name '*.crt' -exec chmod 644 {} \;

# ---- 2. Esperar el clúster --------------------------------------------------
echo "== Esperando a Elasticsearch"
until curl -s --cacert "$CA" "$ES" | grep -q "missing authentication credentials"; do sleep 5; done
until curl -s --cacert "$CA" -u "elastic:$ELASTIC_PASSWORD" \
  "$ES/_cluster/health?wait_for_nodes=3&wait_for_status=yellow&timeout=30s" | grep -q '"number_of_nodes":3'; do
  echo "   ...todavía no están los 3 nodos"; sleep 5
done

# api METODO RUTA [ARCHIVO|-]  (con "-" lee el cuerpo de stdin)
api() {
  local metodo=$1 ruta=$2 cuerpo=${3:-}
  local args=(-sS -o /tmp/resp -w '%{http_code}' --cacert "$CA" -u "elastic:$ELASTIC_PASSWORD"
              -X "$metodo" "$ES$ruta" -H 'Content-Type: application/json')
  if [ "$cuerpo" = "-" ]; then args+=(--data-binary @-); elif [ -n "$cuerpo" ]; then args+=(--data-binary "@$cuerpo"); fi
  local code; code=$(curl "${args[@]}")
  if [ "$code" -ge 300 ]; then
    echo "   ERROR $code en $metodo $ruta:"; cat /tmp/resp; echo; exit 1
  fi
  echo "   OK $code  $metodo $ruta"
}

# ---- 3. Seguridad -----------------------------------------------------------
echo "== Usuarios y roles"
printf '{"password":"%s"}' "$KIBANA_PASSWORD" | api POST /_security/user/kibana_system/_password -
api PUT /_security/role/siem_logstash - <<'JSON'
{
  "cluster": ["monitor"],
  "indices": [
    { "names": ["logs-siem.*"], "privileges": ["auto_configure", "create_doc", "view_index_metadata"] }
  ]
}
JSON
printf '{"password":"%s","roles":["siem_logstash"],"full_name":"Logstash del SIEM"}' "$LOGSTASH_PASSWORD" \
  | api PUT /_security/user/logstash_internal -

# ---- 4. ILM y templates -----------------------------------------------------
echo "== Políticas ILM"
api PUT /_ilm/policy/siem-30d   /setup/ilm/siem-30d.json
api PUT /_ilm/policy/siem-demo  /setup/ilm/siem-demo.json

echo "== Index templates (data streams logs-siem.*)"
api PUT /_index_template/logs-siem         /setup/templates/logs-siem.json
api PUT /_index_template/logs-siem-ilmdemo /setup/templates/logs-siem-ilmdemo.json

echo "== Listo. Salud del clúster:"
curl -s --cacert "$CA" -u "elastic:$ELASTIC_PASSWORD" "$ES/_cluster/health?pretty"
