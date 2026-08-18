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
| FortiClient VPN | Corporativo | Media o nula (nula con SSO) | Se abre desde su carpeta (18/08/2026) | `LAUNCH` |
| Forcepoint VPN | Corporativo | Sin verificar, asumir solo lanzado | — | — |
| Azure VPN Client | MSIX de Store | Solo lanzado, `shell:AppsFolder\<PFN>!App` | — | — |
| IAP Desktop | No es VPN | Túnel TCP por app sobre GCP IAP | — | — |

## Rutas candidatas de instalación

`connectors/providers.py` lleva, por cliente, una lista de rutas donde **suele**
instalarse. El editor del catálogo las usa para rellenar el ejecutable solo, en
vez de hacer teclear `C:\Program Files (x86)\Common Files\Pulse Secure\...` a
mano.

**Ninguna está verificada**, igual que el resto de esta página. No hace falta que
lo estén: no se usan como dato, sino como sitios donde mirar. `detect()` solo
devuelve la que existe de verdad en esa máquina, y si no hay ninguna, el
formulario deja el campo vacío y el usuario la busca con «Examinar…». Una
candidata equivocada no rompe nada, simplemente no aparece.

Si encuentras la ruta real de un cliente en un puesto, añádela **la primera** de
su lista y anótalo aquí. Forcepoint no tiene ninguna: nadie ha mirado dónde se
instala, y una ruta inventada solo serviría para no encontrarlo con más
ceremonia.

## El nombre de la conexión dentro del cliente

`Profile.client_profile_name` es cómo se llama esa conexión **en el cliente
oficial**. Un FortiClient con tres túneles configurados se abre igual para los
tres; sin este campo, tres perfiles del mismo cliente serían indistinguibles en
la ventana.

Es un selector, no configuración de conexión. **La dirección del gateway, el
puerto, el usuario y el certificado no entran aquí ni entrarán**: viven en el
almacén del cliente oficial. Si el catálogo los guardara, habría que pasárselos
al cliente por línea de comandos, y ese es justo el camino que convierte el pipe
en una escalada de privilegios.

Hoy solo se muestra. Cuando un conector se verifique y sepa pedir una conexión
concreta, este es el valor que le pasaría, como un elemento más de la lista de
argumentos — nunca concatenado en una línea, y nunca recibido por el pipe.

Cómo lo llama cada cliente (`Provider.connection_word`) se usa para etiquetar el
campo: «túnel» en WireGuard, «perfil (.ovpn)» en OpenVPN, «portal» en
GlobalProtect.

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

**Hay que arrancarlo desde su propia carpeta y con el entorno limpio.** Es una
app Electron, y lanzado desde otro proceso revienta antes de abrir su ventana:

```
A JavaScript error occurred in the main process
TypeError: Cannot read properties of null (reading 'TraceLog')
    at new Logger (...\FortiClient\resources\app.asar\assets\js\main.js)
```

Ese `TraceLog` de `null` es el síntoma, no la causa. La causa está unas líneas
antes, al cargar su módulo nativo:

```
Error: Cannot open ...\assets\js\guimessenger64.node:
    No se puede encontrar el módulo especificado.
Error: Cannot open ...\assets\js\guimessenger32.node: Error: error: 126
```

**126 es `ERROR_MOD_NOT_FOUND`**, y no dice que falte ese `.node`: dice que falta
una DLL de la que ese `.node` depende. Al fallar los dos, el loader devuelve
`null` y `new Logger` revienta leyendo `TraceLog`.

Windows resuelve esas dependencias por el directorio del ejecutable, los del
sistema, el directorio actual y el **`PATH`**. Ahí estaban las dos causas:

1. **El directorio de trabajo.** `subprocess.Popen` hereda el de quien lanza; un
   acceso directo lleva su «Iniciar en» apuntando a la carpeta del programa.
2. **El `PATH` heredado.** VPN Manager es un bundle de PyInstaller con su propio
   `VCRUNTIME140.dll`, `MSVCP140.dll` y las DLL de Qt. El cliente heredaba ese
   `PATH` y cargaba las nuestras en vez de las suyas.

Por eso arrancaba bien desde PowerShell y no desde el programa **aun con el
directorio correcto**: la segunda causa sobrevivió al primer arreglo.

`WindowsProcessLauncher` arranca ahora con `cwd` en la carpeta del ejecutable y
con `clean_environment()`, que quita del `PATH` todo lo que caiga dentro de
nuestro bundle y borra las variables que PyInstaller, Qt y certifi añaden. No es
un apaño para Fortinet: ningún cliente tiene por qué heredar nuestras librerías.

Visto en un puesto real (18/08/2026).

Instalado en el puesto de pruebas en
`C:\Program Files\Fortinet\FortiClient\FortiClient.exe`.
