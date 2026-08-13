# `connectors/` — un módulo por cliente VPN oficial

Cada conector gobierna el cliente **ya instalado** en el equipo. No implementa
túneles ni parsea protocolos propietarios.

## Qué hay

- `base.py` — `Connector` (interfaz), `LauncherConnector` (el conector mínimo),
  `ProcessLauncher` (el puerto que arranca procesos) y `ConnectorRegistry`.

## Qué falta

- La implementación real de `ProcessLauncher` para Windows. Está bloqueada por la
  pregunta abierta de más abajo.
- Un módulo por proveedor: `wireguard.py`, `openvpn.py`, `ivanti.py`,
  `globalprotect.py`, `forticlient.py`, `forcepoint.py`, `azure.py`,
  `iap_desktop.py`. Hoy todos serían `LauncherConnector` con distinto nombre.

## Cómo está montado `base.py`

**El conector no arranca procesos: se los pide a un puerto.** `ProcessLauncher`
se inyecta en el constructor. Dos motivos: `base.py` sigue siendo lógica pura y
se testea en CI sobre Linux, y la creación de procesos queda concentrada en un
único sitio, que es el que hay que auditar.

**Las comprobaciones viven en la clase base.** `launch`, `connect`, `disconnect`
y `status` verifican —en este orden— que la operación esté declarada, que el
perfil sea de este conector y que el perfil valide; solo entonces delegan en el
`_launch`/`_connect`/… del proveedor. Un conector nuevo no puede saltarse el
filtro por descuido: para ejecutar algo tiene que pasar por ahí.

**`validate_declaration()` comprueba que un conector puede cumplir lo que
declara.** Si declara `CONNECT` y no ha implementado `_connect`, el registro lo
rechaza y el servicio no arranca. La regla de abajo deja de depender de la buena
memoria de quien programa.

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
  dato recibido por el pipe. Ninguna función de `base.py` acepta un `str` suelto
  que pueda acabar en una línea de comandos: se pasa un `Profile` entero.

## Pregunta abierta: quién arranca el cliente

Sin resolver, y condiciona la implementación de `ProcessLauncher`.

Los clientes VPN son aplicaciones **de interfaz gráfica**, y tienen que aparecer
en la sesión del usuario. `vpnmgr-svc` corre en SYSTEM, en la sesión 0: un
`subprocess.Popen` desde ahí crea el proceso en una sesión aislada, sin
escritorio. El usuario no ve nada y el cliente no puede pedirle credenciales
ni MFA.

Las dos salidas razonables:

1. **El servicio lanza en la sesión del usuario**, con `WTSQueryUserToken` +
   `CreateProcessAsUser`. Mantiene la arquitectura como está —el servicio es el
   único que ejecuta binarios de VPN— a cambio de código Win32 delicado y de
   pywin32 como dependencia.
2. **La UI lanza el cliente y el servicio se queda con la red.** El proceso GUI
   nace donde tiene que nacer y desaparece el problema de sesiones. A cambio, la
   UI necesita leer el catálogo firmado para saber qué ruta ejecutar. Es lectura,
   y la ACL solo restringe la escritura, así que no rompe la regla del catálogo;
   pero sí saca la ejecución de binarios del proceso privilegiado, y eso hay que
   decidirlo a propósito, no por inercia.

`base.py` vale igual con cualquiera de las dos: lo que cambia es quién
implementa `ProcessLauncher` y en qué proceso vive.

## Limitación conocida: el pid

`Connector.launch()` devuelve un `Result`, y `Result` no tiene dónde llevar el
pid que sí devuelve `LaunchOutcome`. Hoy no bloquea nada porque ningún conector
declara `DISCONNECT`, pero `DisconnectStrategy.TERMINATE` necesitará ese pid.
Cuando llegue el momento habrá que añadir el campo a `Result` o dejar que el
servicio actualice la `Session`, y eso es un cambio en `core/`.
