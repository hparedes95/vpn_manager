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

foreach ($entry in @($snapshot.dns)) {
    try {
        $servers = @($entry.servers)
        if ($servers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex ([int] $entry.interfaceIndex) `
                                       -ServerAddresses $servers -ErrorAction Stop
        }
        else {
            # Sin servidores en la foto: el adaptador los tomaba por DHCP.
            Set-DnsClientServerAddress -InterfaceIndex ([int] $entry.interfaceIndex) `
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
    restoredDns    = $restoredDns
    failures       = @($failures)
    error          = if ($failures.Count -eq 0) { '' } else { 'la red no se restauro del todo' }
}

if ($failures.Count -gt 0) { exit 1 }
