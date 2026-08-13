# `service/` — `vpnmgr-svc`

Servicio Windows en SYSTEM. El **único** proceso que toca red, rutas, DNS y
procesos de VPN.

## Qué irá aquí

- `main.py` — ciclo de vida del servicio.
- `pipe.py` — servidor del named pipe, con ACL restringida a un grupo de AD.
  Lo único que tiene que hacer con lo que lee es dárselo a
  `core.protocol.MessageStream.feed()` y pasar cada mensaje por
  `Request.decode()`. Lo que salga de ahí ya se puede tratar como válido. Un
  `ProtocolError` cierra la conexión y se convierte en una respuesta de error
  genérica; **el mensaje recibido no se registra**.
- `watchdog.py` — antes de conectar un perfil `FULL`: guardar estado de red,
  armar temporizador (90 s por defecto) y conectar. Si la UI no confirma dentro
  de la ventana, deshacer y restaurar rutas y DNS. Lo que desarma el temporizador
  es `Command.CONFIRM`.

El protocolo vive en **`core/protocol.py`**, no aquí: lo necesitan los dos
procesos, y si viviera en esta capa la interfaz tendría que importar de la capa
privilegiada. Además así se testea en CI sobre Linux, que es donde interesa
probar a fondo el punto por el que entra todo lo de fuera.

## Regla de seguridad innegociable

El servicio **solo acepta `connect(profile_id)` y `disconnect(profile_id)` sobre
ids del catálogo firmado**. Nunca acepta rutas, rutas de binario, argumentos ni
comandos que vengan por el pipe.

Si un cambio hace que un dato llegado por el pipe termine en una línea de
comandos o en una operación de red, es una escalada de privilegios local en cada
puesto de la empresa. Se rechaza y se dice por qué.

## Por qué existe el watchdog

El equipo destino es un PC de oficina al que se llega por RDP. Conectar una VPN
de túnel completo corta la propia sesión RDP. Sin la reversión automática, un
fallo deja el equipo inalcanzable hasta ir físicamente hasta él.
