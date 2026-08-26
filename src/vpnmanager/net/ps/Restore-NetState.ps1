<#
.SYNOPSIS
    Devuelve la red al estado que fotografio Get-NetState.ps1.

.DESCRIPTION
    Es el script que corre cuando la interfaz no confirma una conexion dentro
    de la ventana del watchdog. Si esto no funciona, el equipo se queda
    inalcanzable hasta que alguien vaya fisicamente hasta el, asi que aqui hay
    dos reglas por encima de todo:

    1. Se intenta todo, aunque algo falle por el camino. Rendirse en el primer
       error dejaria la red a medio restaurar, que es peor que como estaba.
    2. Se informa de cada parte por separado. "No se pudo restaurar" sin decir
       que parte no se pudo no sirve de nada a las tres de la manana.

    La foto llega en un fichero y no como argumento: pasar el JSON por la
    linea de comandos lo destroza. PowerShell reinterpreta las comillas de los
    argumentos de -File con sus propias reglas, asi que lo que llegaba ya no
    era JSON valido; y una tabla de rutas grande se acerca al limite de
    longitud de la linea de comandos.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $StatePath
)

$ErrorActionPreference = 'Stop'

function Write-Result {
    param([hashtable] $Result)
    Write-Output ($Result | ConvertTo-Json -Depth 6 -Compress)
}

try {
    $snapshot = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
}
catch {
    Write-Result @{ ok = $false; error = 'no se pudo leer la foto de red guardada' }
    exit 1
}

# Solo se gestionan las rutas con salto real. Las de salto 0.0.0.0 son
# "on-link" y las pone Windows solo por cada adaptador levantado: la de
# loopback, las de subred, la de multidifusion, la de difusion. Intentar
# recrearlas falla, y cada fallo se contaria como una restauracion incompleta
# aunque la red estuviera perfecta.
#
# Lo que un tunel desplaza —la ruta por defecto y las rutas hacia las redes
# del cliente— tiene salto, asi que este filtro cubre justo lo que importa.
function Test-Managed {
    param($NextHop)
    return $NextHop -and $NextHop -ne '0.0.0.0' -and $NextHop -ne '::'
}

$failures = New-Object System.Collections.ArrayList
$restoredRoutes = 0
$removedRoutes = 0
$restoredDns = 0

# --- Rutas ---------------------------------------------------------------
# Se quitan las que hay ahora y no estaban, en vez de borrarlo todo y
# reconstruir: si el borrado falla a mitad, al menos lo que quedo es lo que
# habia, no una tabla vacia.

try {
    $wanted = @{}
    $knownInterfaces = @{}
    foreach ($route in @($snapshot.routes)) {
        $knownInterfaces[[int] $route.interfaceIndex] = $true
        if (Test-Managed $route.next_hop) {
            $wanted["$($route.interfaceIndex)|$($route.destination)|$($route.next_hop)"] = $true
        }
    }

    # Solo se tocan los interfaces que ya existian cuando se saco la foto. Un
    # adaptador que ha aparecido despues —wifi que asocia, DHCP que renueva,
    # una dock que se enchufa— trae rutas legitimas que no estaban, y
    # borrarlas dejaria el equipo peor de lo que lo dejo el tunel.
    foreach ($current in @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)) {
        if (-not $knownInterfaces.ContainsKey([int] $current.InterfaceIndex)) { continue }
        if (-not (Test-Managed $current.NextHop)) { continue }
        $key = "$([int] $current.InterfaceIndex)|$($current.DestinationPrefix)|$($current.NextHop)"
        if (-not $wanted.ContainsKey($key)) {
            try {
                Remove-NetRoute -InputObject $current -Confirm:$false -ErrorAction Stop
                # Se cuenta aparte de las que se vuelven a poner. Quitar es lo
                # que de verdad deshace un tunel —el tunel ANADE una ruta por
                # defecto— asi que sin este contador el JSON decia
                # "restoredRoutes: 0" justo cuando acababa de hacer su trabajo,
                # y no habia forma de distinguirlo de no haber hecho nada.
                $removedRoutes++
            }
            catch {
                [void] $failures.Add("no se pudo quitar una ruta sobrante")
            }
        }
    }

    foreach ($route in @($snapshot.routes)) {
        if (-not (Test-Managed $route.next_hop)) { continue }
        $exists = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                [int] $_.InterfaceIndex -eq [int] $route.interfaceIndex -and
                $_.DestinationPrefix -eq $route.destination -and
                $_.NextHop -eq $route.next_hop
            }

        if (-not $exists) {
            try {
                New-NetRoute -DestinationPrefix $route.destination `
                             -InterfaceIndex ([int] $route.interfaceIndex) `
                             -NextHop $route.next_hop `
                             -RouteMetric ([int] $route.metric) `
                             -Confirm:$false -ErrorAction Stop | Out-Null
                $restoredRoutes++
            }
            catch {
                [void] $failures.Add("no se pudo devolver una ruta a su sitio")
            }
        }
    }
}
catch {
    [void] $failures.Add('no se pudo leer la tabla de rutas para restaurarla')
}

# --- DNS -----------------------------------------------------------------
# Solo se toca lo que ha cambiado. Escribir el DNS de un adaptador NO es una
# operacion inocua: `Set-DnsClientServerAddress -ServerAddresses` lo clava a
# mano, asi que reaplicar a ciegas los servidores de la foto convertia todos
# los adaptadores que tomaban el DNS por DHCP en adaptadores configurados a
# mano, congelados en lo que hubiera en ese momento. En un portatil que cambia
# de red, eso es quedarse sin resolucion al salir de la oficina.
#
# Antes esto pasaba en CADA reversion, tocara o no el tunel el DNS.

function Get-CurrentDns {
    param([int] $InterfaceIndex)
    try {
        $current = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex `
                                              -AddressFamily IPv4 -ErrorAction Stop
        # La coma de delante NO sobra. `return @($vacio)` no devuelve un array
        # vacio: PowerShell lo desenrolla y devuelve $null, indistinguible de
        # "no se pudo mirar". Con eso, un adaptador SIN servidores DNS parecia
        # haber cambiado siempre, y la restauracion le hacia un
        # -ResetServerAddresses en cada vuelta: justo lo que la comparacion
        # venia a evitar.
        return ,@($current.ServerAddresses)
    }
    catch {
        return $null  # no se pudo mirar: distinto de "no tiene ninguno"
    }
}

function Test-SameServers {
    param($Left, $Right)
    # Solo $null a la izquierda significa "no se pudo mirar"; a la derecha
    # viene de la foto, donde la ausencia de servidores es un dato valido.
    if ($null -eq $Left) { return $false }
    $a = @($Left)
    $b = @($Right)
    if ($a.Count -ne $b.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) {
        if ([string] $a[$i] -ne [string] $b[$i]) { return $false }
    }
    return $true
}

foreach ($entry in @($snapshot.dns)) {
    $index = [int] $entry.interfaceIndex
    $wantedServers = @($entry.servers)

    if (Test-SameServers (Get-CurrentDns $index) $wantedServers) {
        continue  # nadie lo ha movido: no hay nada que devolver a su sitio
    }

    try {
        # `static` puede no venir en una foto vieja, y entonces vale $null. En
        # ese caso se escriben los servidores en vez de resetear: en plena
        # reversion, recuperar la resolucion pesa mas que conservar el DHCP, y
        # equivocarse hacia el reset deja el equipo sin DNS si eran estaticos.
        $wasStatic = if ($null -eq $entry.static) { $wantedServers.Count -gt 0 } `
                     else { [bool] $entry.static }

        if ($wasStatic -and $wantedServers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $index `
                                       -ServerAddresses $wantedServers -ErrorAction Stop
        }
        else {
            # Los tomaba del DHCP: se le devuelve al DHCP, no se le clavan los
            # que tenia. Es la unica forma de dejarlo como estaba de verdad.
            Set-DnsClientServerAddress -InterfaceIndex $index `
                                       -ResetServerAddresses -ErrorAction Stop
        }
        $restoredDns++
    }
    catch {
        [void] $failures.Add("no se pudo devolver el DNS de un adaptador")
    }
}

try {
    Clear-DnsClientCache -ErrorAction Stop
}
catch {
    [void] $failures.Add('no se pudo vaciar la cache de DNS')
}

Write-Result @{
    ok             = ($failures.Count -eq 0)
    restoredRoutes = $restoredRoutes
    removedRoutes  = $removedRoutes
    restoredDns    = $restoredDns
    failures       = @($failures)
    error          = if ($failures.Count -eq 0) { '' } else { 'la red no se restauro del todo' }
}

if ($failures.Count -gt 0) { exit 1 }
