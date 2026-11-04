# Funciones compartidas por los scripts. Se usan con: source scripts/_comun.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f .env ] || { echo "Falta .env (cp .env.example .env)"; exit 1; }
set -a; . ./.env; set +a

# es METODO RUTA [cuerpo JSON]  -> llama a Elasticsearch desde dentro de es01 (ahí está la CA)
es() {
  local metodo=$1 ruta=$2 cuerpo=${3:-}
  if [ -n "$cuerpo" ]; then
    docker compose exec -T es01 curl -s --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
      -X "$metodo" "https://localhost:9200${ruta}" -H 'Content-Type: application/json' -d "$cuerpo"
  else
    docker compose exec -T es01 curl -s --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
      -X "$metodo" "https://localhost:9200${ruta}"
  fi
}

# kb METODO RUTA [cuerpo JSON]  -> llama a Kibana desde el PC
kb() {
  local metodo=$1 ruta=$2 cuerpo=${3:-}
  curl -s -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -X "$metodo" "http://localhost:5601${ruta}" ${cuerpo:+-d "$cuerpo"}
}
