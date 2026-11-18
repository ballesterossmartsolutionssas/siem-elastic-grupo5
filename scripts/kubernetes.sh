#!/usr/bin/env bash
# Cuarta fuente (R8.2): logs de Kubernetes.
# Crea un clúster k3s con k3d dentro de la red de Docker del SIEM, despliega una app de ejemplo
# (namespace tienda) y Filebeat como DaemonSet apuntando al mismo Logstash.
#
# Requisitos: el stack arriba (docker compose up -d), k3d y kubectl.
# Uso:  bash scripts/kubernetes.sh crear | estado | borrar
source "$(dirname "$0")/_comun.sh"

CLUSTER=siem-k8s
RED=$(docker network ls --format '{{.Name}}' | grep -E '_siem$' | head -1)
CTX="k3d-${CLUSTER}"

crear() {
  [ -n "$RED" ] || { echo "No encuentro la red del SIEM: levanta primero docker compose up -d"; exit 1; }
  if ! k3d cluster list 2>/dev/null | grep -q "^${CLUSTER} "; then
    echo "== Creando el clúster ${CLUSTER} (k3s de 1 nodo) en la red ${RED}"
    # --api-port en 127.0.0.1: en Windows el kubeconfig queda apuntando a host.docker.internal, que no responde
    k3d cluster create "$CLUSTER" --network "$RED" --servers 1 --agents 0 --no-lb --api-port 127.0.0.1:6550 \
      --k3s-arg "--disable=traefik@server:0" --k3s-arg "--disable=metrics-server@server:0" --wait
  fi
  # Las imágenes (nginx y filebeat) las descarga k3s la primera vez: «k3d image import» falla con
  # el almacén de imágenes de containerd de Docker Desktop.

  LOGSTASH_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${RED}\").IPAddress}}" "$(docker compose ps -q logstash)")
  echo "== Logstash está en ${LOGSTASH_IP}"
  kubectl --context "$CTX" apply -f kubernetes/tienda.yaml
  sed "s/LOGSTASH_IP/${LOGSTASH_IP}/" kubernetes/filebeat-k8s.yaml | kubectl --context "$CTX" apply -f -
  kubectl --context "$CTX" -n kube-system rollout restart daemonset/filebeat > /dev/null
  kubectl --context "$CTX" -n tienda rollout status deploy/web --timeout=120s
  kubectl --context "$CTX" -n kube-system rollout status daemonset/filebeat --timeout=120s
  estado
}

estado() {
  echo "== Pods"
  kubectl --context "$CTX" get pods -A -o wide | grep -E "NAMESPACE|tienda|filebeat"
  echo; echo "== Eventos de Kubernetes en el SIEM (logs-siem.k8s-default)"
  es POST "/logs-siem.k8s-*/_search?filter_path=hits.total,aggregations" \
    '{"size":0,"track_total_hits":true,"aggs":{"pods":{"terms":{"field":"kubernetes.pod.name","size":10}},"codigos":{"terms":{"field":"http.response.status_code"}}}}'
  echo
}

borrar() {
  k3d cluster delete "$CLUSTER"
}

case "${1:-}" in
  crear) crear ;;
  estado) estado ;;
  borrar) borrar ;;
  *) echo "Uso: bash scripts/kubernetes.sh crear | estado | borrar"; exit 1 ;;
esac
