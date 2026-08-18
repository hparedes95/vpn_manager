# Plan de pruebas

Marcado por estado real, no por lo que debería funcionar:

- ✅ **comprobado en un puesto**
- ⚠️ **escrito y corregido a partir de un fallo real, pero sin volver a probar**
- ❌ **nunca ejecutado**

**No pruebes en el PC de oficina.** Una VM con acceso por consola, donde perder
la red no cueste un viaje.

---

## 0. Orden para descartar rápido

Si solo vas a hacer una pasada, hazla en este orden: cada paso descarta una
capa entera, y parar en el primero que falle ahorra el resto.

```powershell
# 1. ¿Se instaló donde toca, y QUÉ build es?
Get-ChildItem "C:\Program Files\VpnManager" -Recurse -Filter *.exe |
    Select-Object FullName, LastWriteTime
Get-Content "C:\Program Files\VpnManager\ui\_internal\vpnmanager\VERSION"
#    Sale algo como 0.1.0-dev+c3910c9: el hash identifica el commit exacto.
#    También está en el título de la ventana y en la primera línea de los logs.

# 2. ¿El servicio existe y arranca? (PowerShell: sc.exe, NO sc)
sc.exe query VpnManagerSvc
Start-Service VpnManagerSvc
Get-Service VpnManagerSvc

# 3. ¿Está escuchando de verdad? — esto es lo que hay que mirar, no el log
[System.IO.Directory]::GetFiles("\\.\pipe\") -match "vpnmgr"
#    Tiene que salir \\.\pipe\vpnmgr. Si no sale, no escucha, diga lo que diga
#    `Get-Service`: el Administrador de servicios da por RUNNING un proceso que
#    se registró, aunque después se le haya caído todo por dentro.

Get-Content C:\ProgramData\VpnManager\vpnmgr-svc.log -Tail 30
#    Buscas: "escuchando en \\.\pipe\vpnmgr". Si se repite cada 2 s, algo falla
#    en cada vuelta; si hay una traza, ahí está el motivo.

# 4. ¿La interfaz habla con él?
Start-Process "C:\Program Files\VpnManager\ui\vpnmgr-ui.exe"
Get-Content "$env:LOCALAPPDATA\VpnManager\vpnmgr-ui.log" -Tail 30
#    Buscas: la ventana con los 4 perfiles del ejemplo.

# 5. ¿La red se puede restaurar? — ANTES de tocar ningún túnel
#    Con la ruta completa y sin `cd`: si el `cd` se pierde, `-File .\algo.ps1`
#    falla diciendo que el fichero no existe, que parece un fallo de la
#    instalación y no lo es.
$ps = "C:\Program Files\VpnManager\svc\_internal\vpnmanager\net\ps"
$f  = "$env:TEMP\estado.json"

& powershell -ExecutionPolicy Bypass -File "$ps\Get-NetState.ps1" | Set-Content $f -Encoding UTF8
route add 10.99.0.0 mask 255.255.0.0 192.168.0.9
& powershell -ExecutionPolicy Bypass -File "$ps\Restore-NetState.ps1" -StatePath $f
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' }

# 6. ¿La sonda distingue conectado de caído?
& powershell -ExecutionPolicy Bypass -File "$ps\Test-TunnelState.ps1" `
    -ProbeIp 192.168.0.9 -TargetNetworks 192.168.0.0/24
& powershell -ExecutionPolicy Bypass -File "$ps\Test-TunnelState.ps1" `
    -ProbeIp 10.255.255.254 -TargetNetworks 192.168.0.0/24
```

Si el paso 5 deja la ruta de prueba puesta porque algo falló, quítala a mano
antes de seguir:

```powershell
route delete 10.99.0.0
```

Si el servicio no arranca (paso 2), lánzalo en consola como administrador para
ver el error sin filtros:

```powershell
& "C:\Program Files\VpnManager\svc\vpnmgr-svc.exe" --allow-unsigned-catalog
```

Los detalles de cada paso, y qué significa que falle, están abajo.

## 1. Instalación

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ⚠️ | Instalar sobre una versión anterior | Termina sin errores; los `.exe` quedan en `svc\` y `ui\` |
| ❌ | Marcar «Instalar el servicio» | `sc.exe query VpnManagerSvc` dice `RUNNING` |
| ⚠️ | Marcar «aceptar el catálogo sin firma» | Aparece `C:\ProgramData\VpnManager\ALLOW_UNSIGNED_CATALOG` |
| ⚠️ | Tu `profiles.json` sobrevive a reinstalar | Sigue con tus ediciones |

El instalador **no está firmado**: SmartScreen avisará. Es esperado.

## 2. El servicio

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ✅ | En consola como administrador | `escuchando en \\.\pipe\vpnmgr` sin trazas repitiéndose |
| ✅ | **Como servicio de Windows** | `Get-Service` dice `Running`, sin el error 1053 |
| ⚠️ | El servicio llega a escuchar | El pipe existe **y** el log lo dice |
| ✅ | Log en fichero | `C:\ProgramData\VpnManager\vpnmgr-svc.log` con lo mismo que la consola |
| ❌ | Parar el servicio con un túnel conectado | En el log: `reversion al parar` y `servicio parado` |

**`Running` no significa escuchando.** El Administrador de servicios da por
arrancado a un proceso que se registró a tiempo; lo que pase después dentro del
proceso no lo mira nadie. La comprobación buena es que exista el pipe:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") -match "vpnmgr"
```

En consola:

```powershell
& "C:\Program Files\VpnManager\svc\vpnmgr-svc.exe" --allow-unsigned-catalog
```

**El servicio de Windows es lo más nuevo y lo que menos confianza me da.** Si falla, mira el estado y el log:

```powershell
sc.exe start VpnManagerSvc
sc.exe query VpnManagerSvc
Get-Content C:\ProgramData\VpnManager\vpnmgr-svc.log -Tail 20
```

**Ojo con `sc` en PowerShell**: es un alias de `Set-Content`, asi que
`sc query X` no consulta nada — crea un fichero llamado `query`. Hay que
escribir `sc.exe`, o usar `Start-Service` y `Get-Service`.

## 3. La interfaz

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | La ventana se abre sola al arrancar | Tabla con los 4 perfiles del ejemplo |
| ❌ | Tipos y estados | «Completo ⚠», «Parcial», «Por aplicación»; estado en color |
| ❌ | Dos botones por fila | «Abrir cliente…» (configurar) y el de conectar, separados |
| ❌ | Botón de conectar | Dice «Abrir cliente» (ningún conector verificado) |
| ❌ | **«Abrir cliente…»** | Se abre la ventana del cliente oficial, en tu sesión |
| ❌ | Si el `.exe` no está donde dice el catálogo | Sale un error diciéndolo, **no** un «lanzando» que no hace nada |
| ❌ | Un perfil sin IP testigo, abierto | Estado «abierto — sin comprobar», en ámbar; el botón dice «Abierto» |
| ❌ | Volver a pulsarlo | Lo rechaza: «su cliente ya está abierto» (no lo abre dos veces) |
| ❌ | Icono en la bandeja | Círculo azul con «V»; puede estar bajo la flecha `^` |
| ❌ | Clic izquierdo en el icono | Abre la ventana |
| ❌ | Clic derecho en el icono | Menú con «Abrir VPN Manager» y los perfiles |
| ❌ | Cerrar la ventana | La aplicación **sigue** en la bandeja |
| ❌ | Bandeja → Salir | Ahora sí se cierra del todo |
| ❌ | Parar el servicio con la ventana abierta | En 10 s: «Sin conexión con el servicio» y la tabla se vacía |
| ❌ | Volver a arrancarlo | En 10 s se rellena sola; en Actividad: «recuperada la conexión» |

## 4. La red — lo que puede dejarte sin conexión

**Esto es lo más importante de todo el plan.** Hazlo antes de conectar ningún
túnel.

Con ruta completa y sin `cd`: si el `cd` se pierde, `-File .\algo.ps1` falla
diciendo que el fichero no existe, y eso parece un fallo de la instalación sin
serlo.

```powershell
$ps = "C:\Program Files\VpnManager\svc\_internal\vpnmanager\net\ps"
$f  = "$env:TEMP\estado.json"
```

### 4.1 Fotografiar el estado ✅

```powershell
& powershell -ExecutionPolicy Bypass -File "$ps\Get-NetState.ps1" | Set-Content $f -Encoding UTF8
Get-Content $f
```

Ya validado: devuelve JSON con rutas, DNS y adaptadores.

Cada entrada de `dns` lleva ahora `static`: `true` si esos servidores están
puestos a mano, `false` si vienen del DHCP, `null` si no se ha podido averiguar.
Es lo que decide cómo se devuelven a su sitio.

### 4.2 Restaurar — rutas ✅

```powershell
# Romper algo, como haría un túnel: una ruta con salto real
route add 10.99.0.0 mask 255.255.0.0 192.168.0.9

& powershell -ExecutionPolicy Bypass -File "$ps\Restore-NetState.ps1" -StatePath $f

# Comprobar
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' }
```

**Tiene que pasar**: `ok = true`, `removedRoutes = 1`, la `10.99.0.0/16`
desaparece y **tu ruta por defecto sigue**.

Comprobado en un puesto: quitó la ruta inyectada y dejó la legítima.

Si `ok` es `false`, mira el campo `failures`: dice qué parte no se pudo.

**Si esto no funciona, no conectes ningún túnel completo.**

### 4.3 Restaurar — DNS ⚠️

Lo del DNS es más traicionero que lo de las rutas, porque **escribirlo no es
inocuo**: `Set-DnsClientServerAddress -ServerAddresses` deja el adaptador
configurado **a mano**. Un adaptador que tomaba el DNS por DHCP y al que se le
reescriben «los mismos» servidores no vuelve a como estaba: se queda clavado en
esos, y deja de seguir al DHCP.

La primera versión reaplicaba el DNS de todos los adaptadores en cada
restauración, tocara o no el túnel el DNS. Ahora solo escribe **lo que ha
cambiado**, y la foto anota si cada adaptador lo tenía a mano o por DHCP para
devolverlo a lo que era.

```powershell
# Sin tocar el DNS: la restauración no debe escribir nada
& powershell -ExecutionPolicy Bypass -File "$ps\Get-NetState.ps1" | Set-Content $f -Encoding UTF8
& powershell -ExecutionPolicy Bypass -File "$ps\Restore-NetState.ps1" -StatePath $f
```

**Tiene que pasar**: `restoredDns = 0`. Si sale distinto de cero sin haber
tocado el DNS, está volviendo a escribir lo que ya estaba bien.

Y con el DNS movido a mano, que es el caso que sí tiene que arreglar:

```powershell
# Mira cómo está antes (Ethernet o el que uses)
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceIndex, InterfaceAlias, ServerAddresses

# Rompe uno, como haría un túnel
Set-DnsClientServerAddress -InterfaceIndex 10 -ServerAddresses 10.99.0.53

& powershell -ExecutionPolicy Bypass -File "$ps\Restore-NetState.ps1" -StatePath $f

# Y comprueba que volvió a lo que era
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceIndex, InterfaceAlias, ServerAddresses
Get-NetIPInterface -InterfaceIndex 10 -AddressFamily IPv4 | Format-List InterfaceAlias, Dhcp
```

**Tiene que pasar**: `restoredDns = 1`, el `10.99.0.53` desaparece, y si ese
adaptador tomaba el DNS por DHCP **vuelve a tomarlo por DHCP**, no clavado.

### 4.4 La sonda ❌

Es lo que decide si un perfil está conectado de verdad. **Nunca se ha
ejecutado.**

Además de las tres comprobaciones devuelve `viaSpecificRoute` y `sameInterface`,
que no deciden nada: están para ver *por qué* salió lo que salió.

**a) Sin ningún túnel, con tu LAN.** Es el caso que más importa, porque es el
que antes daba un falso positivo:

```powershell
& powershell -ExecutionPolicy Bypass -File "$ps\Test-TunnelState.ps1" `
    -ProbeIp 192.168.0.9 -TargetNetworks 192.168.0.0/24
```

**Tiene que pasar**: `connected` a `true` si esa IP responde — es tu propia
LAN, con ruta concreta, así que es correcto que salga conectado.

**b) Una IP que no responde:**

```powershell
& powershell -ExecutionPolicy Bypass -File "$ps\Test-TunnelState.ps1" `
    -ProbeIp 10.255.255.254 -TargetNetworks 10.255.255.0/24
```

**Tiene que pasar**: `connected` a `false` y `probeAnswers` a `false`. Y
**`routed` también a `false`**, porque no hay ruta concreta hacia esa red: sale
por la de por defecto, que encaja con todo y no demuestra nada.

Ese último punto es el que arreglé sin poder probarlo. Si `routed` sale `true`
ahí, la ruta por defecto se está colando y un equipo sin VPN aparecería como
«conectado con avisos» en vez de «caído».

**c) Con tu VPN de Forti levantada**, y una IP interna de verdad:

```powershell
& powershell -ExecutionPolicy Bypass -File "$ps\Test-TunnelState.ps1" `
    -ProbeIp <ip-interna> -TargetNetworks <red-del-cliente>/24
```

**Tiene que pasar**: los tres a `true`. Y luego desconecta en FortiClient y
repítelo: `probeAnswers` a `false`.

Esa diferencia entre b) y c) es la que separa un aviso de una caída, y es toda
la razón de ser de la sonda.

## 5. El catálogo

### 5.1 Desde la interfaz ❌

El botón **«Gestionar VPN…»** de la ventana vuelve a lanzar la aplicación
pidiendo elevación: el editor corre en **otro proceso, como administrador**. La
ventana normal no escribe el catálogo, y eso es a propósito — ese fichero decide
qué binario ejecuta un servicio como SYSTEM.

**Qué se pide y qué no.** El formulario enseña cuatro campos: cliente, nombre,
nombre de la conexión dentro de ese cliente, y tipo de túnel. La dirección del
gateway, el puerto, el usuario y el certificado **no están** y no van a estar:
eso se configura en el cliente oficial. Un FortiClient con dos gateways sigue
siendo una conexión suya, con failover suyo.

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | Pulsar «Gestionar VPN…» | Sale el aviso de UAC; al aceptar, se abre el editor |
| ❌ | Cancelar el UAC | La ventana normal sigue funcionando, sin editor |
| ❌ | El desplegable de clientes | Cada uno dice «— instalado» o «— no encontrado» según lo que haya en **esta** máquina |
| ❌ | Elegir un cliente instalado | El campo «Ejecutable» (en avanzadas) se rellena solo con su ruta |
| ❌ | Elegir uno no instalado | Se queda vacío; **no** se inventa una ruta |
| ❌ | Escribir el nombre visible | El identificador sale solo: «Ivanti — Cliente B» → `ivanti-cliente-b` |
| ❌ | Editar el identificador a mano | Deja de seguir al nombre |
| ❌ | Etiqueta del nombre de conexión | Cambia con el cliente: «túnel» en WireGuard, «perfil (.ovpn)» en OpenVPN |
| ❌ | Elegir túnel «Completo» | Se marca solo «corta la conectividad local» |
| ❌ | Guardar sin IP testigo | **Deja guardar**, avisando de que nunca dirá «conectado» |
| ❌ | Guardar un `FULL` sin IP testigo | El aviso dice además que el watchdog lo deshará a los 90 s |
| ❌ | Guardar con una ruta relativa | Lo rechaza y enseña **todos** los fallos juntos, no solo el primero |
| ❌ | Guardar | Ofrece reiniciar el servicio |
| ❌ | Aceptar el reinicio | Al volver a la ventana, el perfil nuevo está en la tabla |
| ❌ | Mirar `profiles.json` después | JSON legible, sin los campos que van por defecto |

**El caso que importa probar de verdad**: añade una VPN tuya real sabiendo solo
qué cliente es y cómo se llama la conexión dentro de él. Sin IP testigo, sin
redes, sin tocar avanzadas. Tiene que dejarte, y el perfil tiene que salir en la
ventana como **«abierto — sin comprobar»** al abrirlo, nunca como «conectado».

Después, con la VPN levantada, averigua una IP interna que responda a ping,
vuelve al editor y rellénala. Ahí es cuando el estado empieza a significar algo.

Que el editor pida UAC no le da permisos nuevos a nadie: quien puede pasar por
UAC ya podía abrir ese fichero con el Bloc de notas. Lo que evita es que el
proceso sin privilegios lo toque.

### 5.2 A mano ⚠️

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ⚠️ | Meter una errata a propósito | El servicio las lista **todas** y **no carga ningún perfil** |
| ⚠️ | Arreglarla | Al reiniciar, los perfiles aparecen |
| ❌ | Añadir una VPN tuya real | Sale en la ventana |

Edita `C:\ProgramData\VpnManager\profiles.json` (necesitas administrador).
Reinicia el servicio después de cada cambio: **el catálogo se lee al arrancar**.

## 6. Con una VPN de verdad

Empieza por una **`SPLIT`**. No toca la ruta por defecto, así que no puede
dejarte fuera.

### 6.1 El recorrido completo, en orden

Este es el flujo para el que está pensado el programa. La configuración de la
VPN —usuario, gateway, certificado, SSO, IPSec— **se hace una vez en el cliente
oficial**, que es el único que la entiende. VPN Manager no la reimplementa ni
la guarda; abre el sitio donde se hace y luego gestiona la conexión.

1. Da de alta el perfil en **«Gestionar VPN…»** con lo mínimo: cliente, nombre,
   nombre de la conexión y tipo de túnel.
2. Pulsa **«Abrir cliente…»** en su fila.
3. Configura la VPN **dentro del cliente oficial** y **guárdala allí**.
4. Conéctala a mano en el cliente, una vez, para comprobar que la configuración
   es correcta.
5. Con ella levantada, averigua una IP interna que responda a ping.
6. Vuelve al editor y ponla como IP testigo.

A partir de ahí el estado del perfil significa algo.

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | **«Abrir cliente…»** en un `SPLIT` | Se abre el cliente oficial **en tu sesión**, con su ventana |
| ❌ | El cliente no está donde dice el catálogo | Error explícito, no un «lanzando» silencioso |
| ❌ | Configurar y guardar en el cliente | La configuración sobrevive al cerrar el cliente |
| ❌ | Conectar a mano en el cliente | La ventana pasa a «conectado» en 10 s |
| ❌ | Estado real | Si desconectas desde el cliente, pasa a «caído» |

Ese último punto es la prueba de fuego de la sonda: el estado tiene que venir
de la red, no de lo que diga el cliente.

### 6.2 Abrir el cliente de un perfil que corta la red

Abrir un cliente no conecta nada — salvo que ese cliente esté configurado para
conectar al arrancar, y eso desde aquí no se puede saber.

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | «Abrir cliente…» en un perfil `FULL` que corta la red | Avisa **antes** y se puede cancelar |
| ❌ | Cancelarlo | No se abre nada; en Actividad: «cancelado por el usuario» |
| ❌ | Aceptarlo | Se abre el cliente |

**No** se arma el watchdog al abrir un cliente, porque no se está conectando
nada. Si tu cliente conecta solo al arrancar y el perfil es `FULL`, ahí no hay
red de seguridad: hazlo con la VM delante.

## 7. El watchdog — provócalo a propósito

**Antes de fiarte de él**, y con la VM delante.

1. Añade a tu `profiles.json` un perfil `FULL` con
   `"breaks_local_connectivity": true`.
2. Púlsalo en la ventana → tiene que salir el aviso de que perderás la sesión
   remota. **Cancélalo una vez** para ver que respeta el «no».
3. Acéptalo.
4. **Cierra la aplicación entera** (bandeja → Salir).
5. Espera 90 segundos mirando el log del servicio.

**Tiene que pasar**: una línea de reversión y la red como estaba.

Si no aparece, el watchdog no protege nada y no debe salir de la VM.

## 8. El árbitro

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | Dos perfiles `FULL`, conectar el segundo | Rechaza y dice cuál cerrar a mano |
| ❌ | Un `SPLIT` con un `FULL` conectado | Conecta, con el aviso de que sus rutas no encaminan nada |
| ❌ | Un `APP` con un `FULL` conectado | Conecta sin avisos |

Con todos los conectores sin verificar, el rechazo del primer caso es el
esperado: ninguno sabe desconectar solo.

## 9. Qué anotar

- Cada cliente VPN que pruebes → `docs/CONECTORES.md`: versión exacta, orden
  probada, qué devuelve, si pide interacción.
- Todo lo que falle: la línea del log tal cual. Están escritas para decir qué
  parte no se pudo, no solo que algo no fue.

## Lo que esta versión NO es

- **Sin firmar**, ni el ejecutable ni el catálogo.
- Con el catálogo sin verificar, quien pueda escribir `profiles.json` elige qué
  ejecuta el servicio como SYSTEM. En una VM da igual; en un equipo de la
  empresa, no.
- El pipe admite a **cualquiera que haya iniciado sesión** en la máquina, no a
  un grupo de AD. Es más amplio de lo que será en producción.

Nada de esto se despliega hasta que haya certificado y grupo de AD.
