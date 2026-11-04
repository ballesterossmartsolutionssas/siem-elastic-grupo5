#!/usr/bin/env bash
# Uso: docker compose run --rm atacante <escenario>
set -euo pipefail
cd /ataques

case "${1:-ayuda}" in
  fuerza-bruta) ./fuerza-bruta.sh ;;
  escaneo)      ./escaneo.sh ;;
  sqli)         ./sqli.sh ;;
  rutas)        ./rutas.sh ;;
  todo)         ./escaneo.sh; ./fuerza-bruta.sh; ./sqli.sh; ./rutas.sh ;;
  normal)       ./normal.sh ;;
  *)
    cat <<'TXT'
Escenarios:
  fuerza-bruta  hydra contra SSH (usuarios admin y root con claves.txt)   -> R8.4 / R8.5
  escaneo       nmap -sT contra la víctima (incluye los puertos señuelo)  -> R8.4 / R8.5
  sqli          sqlmap y curl con inyecciones SQL desde IPs "públicas"    -> R8.5
  rutas         rutas sensibles (/.env, /admin...) y ráfaga de 404        -> R8.4
  todo          los cuatro seguidos
  normal        tráfico legítimo en bucle (lo usa el servicio trafico)
TXT
    ;;
esac
