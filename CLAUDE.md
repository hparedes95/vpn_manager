# VPN Manager — contexto del proyecto

Orquestador local de conexiones VPN para Windows. Lee este fichero entero antes de proponer cambios.

## Qué es y qué NO es

Gobierna los **clientes VPN oficiales ya instalados** en el equipo. No implementa túneles, no reimplementa protocolos, no sustituye clientes por conexiones nativas.

**Prohibido, sin excepciones:**
- Implementar o parsear protocolos propietarios (SSL-VPN de Fortinet, GlobalProtect, etc.)
- Proponer sustituir un cliente oficial por una conexión RAS nativa u otra alternativa. Decisión cerrada del usuario
- Guardar credenciales. La v1 no gestiona secretos: cada cliente oficial sigue usando su propio almacén
- Escribir credenciales, tokens o cookies en el log

## Contexto de despliegue

- Corre en el PC de oficina, que es el destino de sesiones RDP. **Conectar una VPN de túnel completo corta la propia sesión RDP.**
- Lo usará toda la plantilla que necesite varias VPN de clientes. Los usuarios **no son administradores**.
- Distribución por Intune como app Win32 firmada.

## Clientes VPN en uso

| Cliente | Tipo | Automatización esperada |
|---|---|---|
| WireGuard | Túnel propio | Total — `wireguard.exe /installtunnelservice` |
| OpenVPN | Túnel propio | Total — `openvpn-gui.exe --command connect` |
| Ivanti Secure Access | Corporativo | Alta, por verificar — `pulselauncher.exe` |
| GlobalProtect | Corporativo | Media, según versión |
| FortiClient VPN | Corporativo | Media o nula (nula con SSO) |
| Forcepoint VPN | Corporativo | Sin verificar. Asumir solo lanzado |
| Azure VPN Client | App MSIX de Store | Solo lanzado, vía `shell:AppsFolder\<PFN>!App` |
| IAP Desktop | **No es VPN** | Túnel TCP por app sobre GCP IAP. Nunca entra en el árbitro de túnel |

**Ninguna versión de esta tabla está verificada contra los equipos reales.** No des por hecho que una CLI existe: todo conector nuevo empieza siendo `LauncherConnector` y solo declara `CONNECT` cuando se ha comprobado en un puesto.

## Arquitectura

Dos procesos:

- **`vpnmgr-svc`** — servicio Windows en SYSTEM. Único que toca red, rutas, DNS y procesos de VPN.
- **`vpnmgr-ui`** — proceso en sesión de usuario. PySide6 con icono de bandeja. Sin privilegios.

Comunicación por **named pipe** con ACL restringida a un grupo de AD.

### Regla de seguridad innegociable

El servicio **solo acepta `connect(profile_id)` y `disconnect(profile_id)` sobre ids del catálogo firmado**. Nunca acepta rutas, rutas de binario, argumentos ni comandos que vengan por el pipe. Si un cambio hace que un dato del cliente llegue a una línea de comandos o a una operación de red, es una escalada de privilegios local en cada puesto de la empresa: recházalo y dilo explícitamente.

Nada de `shell=True`. `subprocess` siempre con lista de argumentos.

### Catálogo de perfiles

JSON firmado en `%ProgramData%\VpnManager\profiles.json`, ACL de escritura solo para Administradores y SYSTEM. El servicio verifica la firma en cada carga; si no valida, no arranca ningún perfil y lo registra. Lo local por usuario es solo preferencias de interfaz.

### Watchdog de reversión

Antes de conectar un perfil `FULL`, el servicio guarda el estado de red, arma un temporizador (90 s por defecto) y conecta. Si la UI no confirma dentro de la ventana, deshace la conexión y restaura rutas y DNS. Sin esto, un fallo deja el equipo inalcanzable hasta ir físicamente.

### Estado real, no aparente

Un perfil está `CONNECTED` solo si pasan las tres comprobaciones: adaptador activo, ruta hacia la red destino, y respuesta de la IP testigo interna. El icono del cliente oficial no es fuente de verdad.

### Árbitro de túnel

Un solo perfil `FULL` activo a la vez; conectar otro desconecta el anterior primero. Los `SPLIT` conviven. Los `APP` (IAP Desktop) quedan siempre fuera del árbitro.

## Stack y convenciones

- Python 3.12, PySide6, SQLite, `keyring` (solo si algún día hay secretos), pytest, PyInstaller `onedir`
- **Las operaciones de red van en `.ps1` versionados** en `src/vpnmanager/net/ps/`, con entrada y salida en JSON (`ConvertTo-Json`). No reimplementes `Get-NetRoute` parseando texto en Python
- Identificadores en inglés, docstrings y comentarios en español
- `from __future__ import annotations` y tipado en todo el código nuevo
- El núcleo (`core/`) no importa nada de Windows: debe poder testearse en CI en Linux
- Sin dependencias nuevas sin justificar mantenimiento y CVEs

## Estructura

```
src/vpnmanager/
├── core/         # modelos, arbitro, estado, log. Logica pura, testeable
├── connectors/   # base.py + uno por proveedor
├── net/          # rutas, DNS, adaptadores + ps/*.ps1
├── security/     # firma del catalogo, saneado de logs
├── service/      # vpnmgr-svc: servicio y servidor del pipe
└── ui/           # vpnmgr-ui: PySide6
```

## Cómo trabajar en este repo

- Una funcionalidad por rama y por sesión. No pidas ni aceptes "implementa la app entera"
- Antes de implementar, explica el enfoque y espera confirmación. El razonamiento antes que el código
- Cada cambio en `core/` viene con sus tests, incluidos casos límite y de error
- No cierres una tarea sin decir qué casos no quedan cubiertos
- Cuando algo dependa de una versión concreta de un cliente VPN, documéntalo en `docs/CONECTORES.md`

## Estado actual

Fase 4 (entorno). Existe `core/models.py`. Pendiente: `connectors/base.py`, árbitro, protocolo del pipe, CI.

## Bloqueos abiertos fuera del código

Contratos con clientes, aval de dirección, certificado de firma de código, grupo de AD para la ACL. Ninguno impide programar; todos impiden desplegar.
