# `connectors/` — un módulo por cliente VPN oficial

Cada conector gobierna el cliente **ya instalado** en el equipo. No implementa
túneles ni parsea protocolos propietarios.

## Qué irá aquí

- `base.py` — interfaz común y `LauncherConnector`, el conector mínimo que solo
  sabe abrir el cliente oficial.
- Un módulo por proveedor: `wireguard.py`, `openvpn.py`, `ivanti.py`,
  `globalprotect.py`, `forticlient.py`, `forcepoint.py`, `azure.py`,
  `iap_desktop.py`.

## Regla de entrada

**Todo conector nuevo empieza siendo `LauncherConnector` y solo declara
`Capability.CONNECT` cuando se ha comprobado en un puesto real**, con la versión
del cliente anotada en `docs/CONECTORES.md`. La interfaz se construye a partir de
las capacidades declaradas: si un conector no declara `CONNECT`, el botón dice
«Abrir cliente». Prometer automatización que no existe es peor que no tenerla.

Ninguna versión de la tabla de `CLAUDE.md` está verificada todavía.

## Restricciones

- `subprocess` siempre con lista de argumentos. Nunca `shell=True`.
- Rutas de binario y argumentos salen **solo** del catálogo firmado, jamás de un
  dato recibido por el pipe.
