"""Genera N días de logs pasados (auth, syslog y nginx) en datos/historico/.

Sirve para que los dashboards tengan "tendencia por semana" y mapa de IPs desde el primer día.
Los ataques de verdad se hacen con el contenedor atacante; esto es solo el fondo histórico.

Uso (desde la raíz del repo, con Python 3.10+ y sin librerías extra):
    python generadores/historico.py --dias 7
    python generadores/historico.py --dias 7 --malformados 0.02
"""
import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SALIDA = Path(__file__).resolve().parent.parent / "datos" / "historico"
UTC = timezone.utc

# IPs públicas de ejemplo (para el mapa). Legítimas: Colombia. Atacantes: varios países.
IPS_NORMALES = ["190.85.32.10", "181.49.112.7", "186.30.44.21", "190.27.205.9", "179.19.80.33", "200.21.66.150"]
IPS_ATACANTES = ["185.220.101.34", "45.95.147.236", "61.177.172.140", "218.92.0.112", "103.145.13.20",
                 "177.54.144.71", "5.188.206.18", "141.98.11.27", "92.118.39.82", "36.110.228.254"]
USUARIOS_DICCIONARIO = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "guest"]
RUTAS_NORMALES = ["/", "/buscar?q=zapatos", "/buscar?q=camisa", "/producto?id=7", "/producto?id=12", "/login"]
RUTAS_SENSIBLES = ["/.env", "/.git/config", "/admin", "/wp-login.php", "/phpmyadmin/", "/config.php"]
SQLI = ["/buscar?q=1%27%20OR%20%271%27=%271", "/producto?id=1%20UNION%20SELECT%20user,pass%20FROM%20users--",
        "/producto?id=1%20AND%20SLEEP(5)"]
UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36"


def ts_syslog(t):
    return t.isoformat(timespec="microseconds")


def ts_nginx(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def nginx(t, ip, ruta, codigo, ua=UA_NORMAL):
    return (f'172.18.0.1 - - [{ts_nginx(t)}] "GET {ruta} HTTP/1.1" {codigo} {random.randint(80, 4000)} '
            f'"-" "{ua}" "{ip}" {random.uniform(0.001, 0.2):.3f}')


def generar(dias, tasa_malformados):
    auth, syslog, web = [], [], []
    ahora = datetime.now(UTC).replace(microsecond=0)
    inicio = ahora - timedelta(days=dias)

    t = inicio
    while t < ahora:
        # Tráfico normal (más de día que de noche, hora de Colombia = UTC-5)
        hora_col = (t - timedelta(hours=5)).hour
        if 7 <= hora_col < 22 or random.random() < 0.2:
            web.append((t, nginx(t, random.choice(IPS_NORMALES), random.choice(RUTAS_NORMALES), 200)))
        if random.random() < 0.02:
            ip = random.choice(IPS_NORMALES)
            auth.append((t, f"{ts_syslog(t)} victima sshd[{random.randint(300, 9999)}]: Accepted password for operador from {ip} port {random.randint(40000, 65000)} ssh2"))
        if random.random() < 0.05:
            syslog.append((t, f"{ts_syslog(t)} victima cron[{random.randint(300, 9999)}]: (root) CMD (/usr/local/bin/respaldo.sh)"))
        t += timedelta(seconds=random.randint(20, 120))

    # Ataques: unas cuantas ráfagas por día
    for d in range(dias):
        dia = inicio + timedelta(days=d)
        for _ in range(random.randint(2, 6)):
            t0 = dia + timedelta(seconds=random.randint(0, 86399))
            ip = random.choice(IPS_ATACANTES)
            tipo = random.choice(["ssh", "ssh", "sqli", "rutas", "escaneo"])
            if tipo == "ssh":
                for i in range(random.randint(10, 60)):
                    ti = t0 + timedelta(seconds=i)
                    u = random.choice(USUARIOS_DICCIONARIO)
                    auth.append((ti, f"{ts_syslog(ti)} victima sshd[{random.randint(300, 9999)}]: Failed password for invalid user {u} from {ip} port {random.randint(40000, 65000)} ssh2"))
            elif tipo == "sqli":
                for i, ruta in enumerate(SQLI * 3):
                    ti = t0 + timedelta(seconds=i * 2)
                    web.append((ti, nginx(ti, ip, ruta, 200, "sqlmap/1.7.2#stable (https://sqlmap.org)")))
            elif tipo == "rutas":
                for i in range(30):
                    ti = t0 + timedelta(seconds=i)
                    ruta = random.choice(RUTAS_SENSIBLES) if i % 3 == 0 else f"/pagina-{random.randint(1, 999)}"
                    web.append((ti, nginx(ti, ip, ruta, 404, "gobuster/3.6")))
            else:
                for i, puerto in enumerate(random.sample([21, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8081, 8443], 12)):
                    ti = t0 + timedelta(milliseconds=i * 150)
                    syslog.append((ti, f"{ts_syslog(ti)} victima portguard: conexion src={ip} spt={random.randint(40000, 65000)} dpt={puerto} proto=tcp"))

    # Líneas malformadas para probar el índice de errores (R8.3)
    for lista in (auth, syslog, web):
        for _ in range(int(len(lista) * tasa_malformados)):
            ti = inicio + timedelta(seconds=random.randint(0, dias * 86400))
            lista.append((ti, random.choice(["#### linea corrupta ####", "Nov 99 25:61:00 ???", "\x00\x01 basura binaria"])))

    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, lista in (("auth.log", auth), ("syslog", syslog), ("access.log", web)):
        lista.sort(key=lambda x: x[0])
        with open(SALIDA / nombre, "a", encoding="utf-8", newline="\n") as f:
            f.writelines(linea + "\n" for _, linea in lista)
        print(f"{nombre:<11} {len(lista):>7} líneas -> {SALIDA / nombre}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dias", type=int, default=7)
    p.add_argument("--malformados", type=float, default=0.01, help="fracción de líneas corruptas (0.01 = 1 %%)")
    a = p.parse_args()
    generar(a.dias, a.malformados)
