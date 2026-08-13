# Conectores y versiones de cliente

Aquí se anota, por cliente, **qué se ha comprobado y en qué versión**. Es el
registro que decide qué capacidades declara cada conector.

## Regla

Un conector solo declara `Capability.CONNECT` o `DISCONNECT` cuando la orden
correspondiente se ha ejecutado con éxito en un puesto real, y la versión del
cliente queda anotada en la tabla de abajo. Hasta entonces es un
`LauncherConnector`: solo `LAUNCH`.

Motivo: la UI se construye a partir de las capacidades declaradas. Si un conector
promete `CONNECT` y el cliente no obedece, el usuario ve un botón «Conectar» que
no conecta y un estado que no avanza.

## Estado de verificación

Ninguna fila está verificada todavía. La columna «Automatización esperada» viene
de la documentación de cada fabricante, **no** de una prueba.

| Cliente | Tipo | Automatización esperada | Verificado en | Capacidades declaradas |
|---|---|---|---|---|
| WireGuard | Túnel propio | `wireguard.exe /installtunnelservice` | — | — |
| OpenVPN | Túnel propio | `openvpn-gui.exe --command connect` | — | — |
| Ivanti Secure Access | Corporativo | `pulselauncher.exe` | — | — |
| GlobalProtect | Corporativo | Media, según versión | — | — |
| FortiClient VPN | Corporativo | Media o nula (nula con SSO) | — | — |
| Forcepoint VPN | Corporativo | Sin verificar, asumir solo lanzado | — | — |
| Azure VPN Client | MSIX de Store | Solo lanzado, `shell:AppsFolder\<PFN>!App` | — | — |
| IAP Desktop | No es VPN | Túnel TCP por app sobre GCP IAP | — | — |

## Cómo se rellena una fila

1. Versión exacta del cliente (la que reporta el propio cliente, no la del
   instalador).
2. Orden probada, literal, con la lista de argumentos tal cual se pasa a
   `subprocess`.
3. Qué devuelve: código de salida, si es síncrona o vuelve al momento, y si
   requiere interacción del usuario (SSO, MFA, aceptar un aviso).
4. Comportamiento al desconectar, que es lo que fija `DisconnectStrategy`.
   `TERMINATE` solo se pone si se ha comprobado que ese cliente concreto
   sobrevive a que lo maten sin dejar rutas ni adaptadores a medias.

## Notas por cliente

### IAP Desktop

No es una VPN. Reenvía TCP por aplicación sobre GCP IAP. `TunnelType.APP`, queda
**siempre fuera del árbitro de túnel** y no aplica rutas ni DNS: convive con
cualquier perfil `FULL` o `SPLIT` sin conflicto.

### Azure VPN Client

App MSIX de Store: no tiene una ruta de ejecutable utilizable, se lanza por su
Package Family Name (`LaunchKind.MSIX`, target `<PFN>!<AppId>`). Se asume solo
lanzado mientras nadie compruebe lo contrario.

### FortiClient VPN

Con SSO la automatización puede ser directamente imposible. Si es el caso, se
queda en `LAUNCH` y se documenta aquí para que no vuelva a intentarse cada seis
meses.
