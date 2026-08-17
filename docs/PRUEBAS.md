# Plan de pruebas

Marcado por estado real, no por lo que debería funcionar:

- ✅ **comprobado en un puesto**
- ⚠️ **escrito y corregido a partir de un fallo real, pero sin volver a probar**
- ❌ **nunca ejecutado**

**No pruebes en el PC de oficina.** Una VM con acceso por consola, donde perder
la red no cueste un viaje.

---

## 1. Instalación

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ⚠️ | Instalar sobre una versión anterior | Termina sin errores; los `.exe` quedan en `svc\` y `ui\` |
| ❌ | Marcar «Instalar el servicio» | `sc query VpnManagerSvc` dice `RUNNING` |
| ⚠️ | Marcar «aceptar el catálogo sin firma» | Aparece `C:\ProgramData\VpnManager\ALLOW_UNSIGNED_CATALOG` |
| ⚠️ | Tu `profiles.json` sobrevive a reinstalar | Sigue con tus ediciones |

El instalador **no está firmado**: SmartScreen avisará. Es esperado.

## 2. El servicio

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ✅ | En consola como administrador | `escuchando en el pipe` sin trazas repitiéndose |
| ❌ | **Como servicio de Windows** | Arranca sin el error 1053 |
| ❌ | Log en fichero | `C:\ProgramData\VpnManager\vpnmgr-svc.log` con lo mismo que la consola |
| ❌ | Parar el servicio con un túnel conectado | En el log: `reversion al parar` |

En consola:

```powershell
& "C:\Program Files\VpnManager\svc\vpnmgr-svc.exe" --allow-unsigned-catalog
```

**El servicio de Windows es lo más nuevo y lo que menos confianza me da.** Si
falla, `sc query VpnManagerSvc` y el log de arriba.

## 3. La interfaz

| | Qué | Cómo se ve que está bien |
|---|---|---|
| ❌ | La ventana se abre sola al arrancar | Tabla con los 4 perfiles del ejemplo |
| ❌ | Tipos y estados | «Completo ⚠», «Parcial», «Por aplicación»; estado en color |
| ❌ | Botones | Todos dicen «Abrir cliente» (ningún conector verificado) |
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
