# `ui/` — `vpnmgr-ui`

Proceso en sesión de usuario. PySide6 con icono de bandeja. **Sin privilegios**:
no toca red, no lanza clientes VPN, no lee el catálogo del disco. Todo pasa por
el pipe.

## Qué irá aquí

- `tray.py`, `windows/` — bandeja y ventanas.
- `client.py` — cliente del named pipe.

## Reglas de interfaz

- **La UI se construye a partir de las capacidades declaradas por el conector.**
  Sin `Capability.CONNECT`, el botón dice «Abrir cliente», no «Conectar».
- Un perfil con `breaks_local_connectivity` exige confirmación explícita antes
  de conectar (HU-03): el usuario está probablemente dentro de una sesión RDP que
  se va a cortar.
- La UI **confirma** al servicio que la conexión ha ido bien; ese acuse es lo que
  desarma el watchdog. Si la UI muere, el watchdog revierte, que es justo lo que
  se quiere.
- El estado que muestra viene del servicio (adaptador + ruta + IP testigo), no
  del icono del cliente oficial.

Los usuarios no son administradores. Nada de esta capa debe pedir elevación.
