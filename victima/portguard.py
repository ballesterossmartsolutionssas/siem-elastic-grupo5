"""Puertos señuelo: escucha en puertos que el servidor no usa y registra cada conexión en syslog.

Un escaneo (nmap -sT) toca muchos puertos en segundos; la regla de escaneo de puertos
cuenta cuántos puertos distintos tocó cada IP en un minuto.
"""
import asyncio
import logging
import logging.handlers
import os

PUERTOS = [int(p) for p in os.environ.get(
    "PUERTOS_SENUELO",
    "21,23,25,110,135,139,445,1433,1521,3306,3389,5432,5900,6379,8081,8443,9000,11211,27017",
).split(",")]

log = logging.getLogger("portguard")
log.setLevel(logging.INFO)
manejador = logging.handlers.SysLogHandler(
    address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_LOCAL0
)
manejador.append_nul = False
manejador.setFormatter(logging.Formatter("portguard: %(message)s"))
log.addHandler(manejador)


def atender(puerto):
    async def _atender(reader, writer):
        ip, puerto_origen = writer.get_extra_info("peername")[:2]
        log.info("conexion src=%s spt=%s dpt=%s proto=tcp", ip, puerto_origen, puerto)
        writer.close()
    return _atender


async def main():
    servidores = [await asyncio.start_server(atender(p), "0.0.0.0", p) for p in PUERTOS]
    log.info("escuchando en %d puertos senuelo", len(servidores))
    await asyncio.gather(*(s.serve_forever() for s in servidores))


if __name__ == "__main__":
    asyncio.run(main())
