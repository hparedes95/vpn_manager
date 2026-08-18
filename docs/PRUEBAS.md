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
# 1. ¿Se instaló donde toca?
Get-ChildItem "C:\Program Files\VpnManager" -Recurse -Filter *.exe |
    Select-Object FullName

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
| ❌ | Botones | Todos dicen «Abrir cliente» (ningún conector verificado) |
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

```powershell
cd "C:\Program Files\VpnManager\svc\_internal\vpnmanager\net\ps"
```

### 4.1 Fotografiar el estado ✅

```powershell
$f = "$env:TEMP\estado.json"
& powershell -ExecutionPolicy Bypass -File .\Get-NetState.ps1 | Set-Content $f -Encoding UTF8
Get-Content $f
```

Ya validado: devuelve JSON con rutas, DNS y adaptadores.

### 4.2 Restaurar ⚠️

```powershell
# Romper algo, como haría un túnel: una ruta con salto real
route add 10.99.0.0 mask 255.255.0.0 192.168.0.9

& powershell -ExecutionPolicy Bypass -File .\Restore-NetState.ps1 -StatePath $f

# Comprobar
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' }
```

**Tiene que pasar**: `ok = true`, la `10.99.0.0/16` desaparece, y **tus dos
rutas por defecto siguen** (`192.168.59.2` y `192.168.0.9`).

Si `ok` es `false`, mira el campo `failures`: dice qué parte no se pudo.

**Si esto no funciona, no conectes ningún túnel completo.**

### 4.3 La sonda ❌

Con una IP que responda a ping y una red que exista en tu tabla de rutas:

```powershell
& powershell -ExecutionPolicy Bypass -File .\Test-TunnelState.ps1 `
    -ProbeIp 192.168.0.9 -TargetNetworks 192.168.0.0/24
```

**Tiene que pasar**: `adapterUp`, `routed` y `probeAnswers` a `true`, y
`connected` a `true`.

Prueba también con una IP que no responda: `connected` a `false` y
`probeAnswers` a `false`, pero los otros dos a `true`. Esa diferencia es la que
separa un aviso de una caída.

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

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | Pulsar «Abrir cliente» en un `SPLIT` | Se abre el cliente oficial **en tu sesión** |
| ❌ | Conectar a mano en el cliente | La ventana pasa a «conectado» en 10 s |
| ❌ | Estado real | Si desconectas desde el cliente, pasa a «caído» |

Ese segundo punto es la prueba de fuego de la sonda: el estado tiene que venir
de la red, no de lo que diga el cliente.

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
