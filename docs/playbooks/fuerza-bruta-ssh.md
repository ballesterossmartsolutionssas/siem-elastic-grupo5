# Playbook: fuerza bruta SSH

| Dato | Valor |
| --- | --- |
| Alertas | `SIEM - Fuerza bruta SSH` (alta) y, si el atacante entra, `SIEM - Acceso tras fuerza bruta` (crítica) y `SIEM - Login fuera de horario` |
| Reglas | `reglas/01-fuerza-bruta-ssh.json`, `reglas/07-acceso-tras-fuerza-bruta.json` y `reglas/04-login-fuera-de-horario.json` |
| Fuente | `logs-siem.auth-*` (auth.log de la víctima) |
| MITRE ATT&CK | T1110 Brute Force → T1078 Valid Accounts |
| Cómo simularlo | `bash scripts/atacar-y-medir.sh fuerza-bruta "SIEM - Fuerza bruta SSH"` |
| Tiempo objetivo | Investigación completa en menos de 5 minutos con el dashboard operacional |

**Quién lo ejecuta:** el analista de turno. Necesita acceso a Kibana (Security y Dashboards) y, para contener, a la consola del servidor o al firewall.

## 1. Detección y triage (≈ 2 min)

1. **Kibana → Security → Alerts.** Abrir la alerta `SIEM - Fuerza bruta SSH` y anotar la IP de origen (`source.ip`) y la hora.
2. **Dashboards → `SIEM - Operacional`.** En la tabla *Top IPs*, pasar el mouse sobre la IP y darle a **Filter for** (la lupa con +). Todo el tablero queda filtrado por esa IP.
3. Mirar *Top usuarios en SSH*:
   - Columna **Fallidos**: qué cuentas probó y cuántas veces.
   - Columna **Exitosos**: **si hay algún número, el atacante entró.** La alerta crítica `SIEM - Acceso tras fuerza bruta` ya lo dice sola.
4. Mirar *Alertas activas*: ¿la misma IP tiene más alertas? (escaneo antes, login fuera de horario después).
5. Clasificar:

| Situación | Severidad | Siguiente paso |
| --- | --- | --- |
| Solo fallos | Media | Contención (bloquear IP) |
| Algún éxito | **Crítica: cuenta comprometida** | Contención + erradicación completas |
| IP interna conocida (monitoreo, un usuario que olvidó la clave) | Baja | Confirmar con el dueño y cerrar como falso positivo |

Consulta de apoyo en Discover (data view `SIEM - todos los logs`):

```text
source.ip : "<IP>" and event.dataset : "siem.auth"
```

## 2. Contención (≈ 2 min)

1. Bloquear la IP. En un servidor con UFW: `sudo ufw deny from <IP>`. En la nube: regla de denegación en el security group o en el NSG.
2. Si hubo éxito:
   - Cerrar las sesiones del usuario: `sudo pkill -KILL -u <usuario>`.
   - Bloquear la cuenta: `sudo passwd -l <usuario>`.
3. En Kibana, marcar la alerta como **Acknowledged** y anotar en el caso lo que se hizo.

## 3. Erradicación

1. Cambiar la clave de la cuenta comprometida.
2. Revisar si dejó persistencia:
   - `~/.ssh/authorized_keys` de la cuenta;
   - `crontab -l -u <usuario>`;
   - usuarios nuevos en `/etc/passwd`;
   - pertenencia a `sudo`.
3. Revisar qué hizo con la sesión: en Discover, `user.name : "<usuario>" and event.dataset : ("siem.auth" or "siem.syslog")` después de la hora del éxito.

## 4. Recuperación

1. Endurecer SSH: `PasswordAuthentication no` (solo llaves), `PermitRootLogin no`, `MaxAuthTries 3`.
2. Instalar fail2ban o bloquear automáticamente las IPs que disparen la regla.
3. Desbloquear la cuenta con la clave nueva y confirmar con el dueño que puede entrar.

## 5. Lecciones aprendidas (prueba del 4 nov 2026)

**Qué pasó.** hydra (`192.168.16.10`, IP interna del laboratorio) probó 25 claves para `root` y 25 para `admin`:

| Hora (UTC) | Evento |
| --- | --- |
| 05:36:57 | Alerta **Escaneo de puertos** de la misma IP: el reconocimiento llega primero |
| 05:37:16 | Primer intento fallido de SSH |
| 05:37:46 | **Ingreso exitoso como `admin`** con la clave `sunshine2024`, que estaba en el diccionario |
| 05:37:48 | Último intento |
| 05:37:54 | Alerta **Fuerza bruta SSH**: 43 s después de lanzar el ataque |
| 05:38:03 | Alerta **Login fuera de horario** para `admin` (00:37 hora de Colombia) |

**Qué funcionó:**
- Las dos reglas se complementan. La fuerza bruta avisa del intento, y la de horario delata el ingreso exitoso.
- Con el filtro por IP en el dashboard operacional, la historia completa (escaneo, fuerza bruta e ingreso) sale en una sola pantalla.

**Qué mejorar:**
- La regla de fuerza bruta alerta, pero no dice si hubo éxito. Hace falta una regla de correlación (EQL *sequence*): N fallos y luego un éxito de la misma IP, con severidad crítica. **Hecho el 18 nov** (`reglas/07-acceso-tras-fuerza-bruta.json`).
- El ingreso de `operador` que genera el tráfico normal también dispara «fuera de horario» de noche. Se arregla con una lista de excepciones para cuentas de servicio. **Hecho el 18 nov** (`not user.name : ("operador")` en la regla 04).
- Una clave de diccionario en una cuenta con `sudo` es el problema de fondo: SSH solo con llaves.

## 6. Segunda ejecución del playbook (18 nov 2026)

Se siguió el playbook paso a paso sobre el ataque de la corrida final ([resultados-2026-11-18.md](../evidencias/resultados-2026-11-18.md)):

| Paso | Qué se vio | Tiempo |
| --- | --- | --- |
| 1. Security → Alerts | `Acceso tras fuerza bruta` (crítica) y `Fuerza bruta SSH` (alta), las dos desde `192.168.80.11` | < 1 min |
| 2. Operacional, *Filter for* la IP | 79 eventos: 48 fallos, 19 puertos tocados y 3 alertas | < 1 min |
| 3. Top usuarios en SSH | `root`: 25 fallos y 0 éxitos. `admin`: 23 fallos y **1 éxito** | inmediato |
| 4. Clasificación | **Crítica: cuenta `admin` comprometida** (además, el ingreso fue a la 1:07 a. m.) | — |
| 5. Contención (simulada) | `ufw deny from 192.168.80.11`, `pkill -KILL -u admin` y `passwd -l admin` | ≈ 2 min |

Tiempo total del triage: unos 3 minutos, dentro del objetivo de 5. La alerta crítica nueva ahorra el paso de mirar la tabla de usuarios para saber si entró.
