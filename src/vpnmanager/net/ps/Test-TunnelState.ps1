<#
.SYNOPSIS
    Comprueba si un tunel esta conectado de verdad.

.DESCRIPTION
    Las tres comprobaciones, por separado y todas: adaptador activo, ruta
    hacia la red destino, y respuesta de la IP testigo interna. El icono del
    cliente oficial no entra en esto, porque no es fuente de verdad.

    Se devuelven las tres por separado y no un si o un no, para poder
    distinguir "el tunel esta pero no responde" de "no hay tunel". Esa
    diferencia es la que separa DEGRADED de DOWN.

    Las rutas se resuelven con Find-NetRoute, que hace lo mismo que la pila de
    red: prefijo mas largo. Comparar DestinationPrefix a mano exigia que la
    ruta fuese exactamente el prefijo declarado, y un perfil que declara
    172.16.4.0/24 contra un cliente que instala 172.16.0.0/16 salia "sin ruta"
    con el tunel montado.

    Ademas de las tres, se devuelven `viaSpecificRoute` y `sameInterface`, que
    no deciden nada: estan para poder ver en un puesto POR QUE salio lo que
    salio, sin volver a lanzar el script a mano.

    -TargetNetworks admite varias redes separadas por coma. Los valores salen
    del catalogo firmado y llegan como un solo parametro, nunca concatenados
    dentro de una orden.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F:.]{1,45}$')]
    [string] $ProbeIp,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9a-fA-F:./,]{0,512}$')]
    [string] $TargetNetworks = '',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int] $TimeoutSeconds = 5
)

$ErrorActionPreference = 'Stop'

function Write-Result {
    param([hashtable] $Result)
    Write-Output ($Result | ConvertTo-Json -Depth 4 -Compress)
}

# Por que interfaz saldria el trafico hacia una direccion, si es que saldria.
#
# `Find-NetRoute` resuelve como lo hace la pila de red: prefijo mas largo, con
# la metrica y el estado de cada adaptador. Comparar `DestinationPrefix` a mano
# no vale, porque exige que la ruta sea EXACTAMENTE el prefijo declarado: un
# perfil que declara 172.16.4.0/24 contra un cliente que instala 172.16.0.0/16
# daria "sin ruta" con el tunel perfectamente montado. Y quien rellena el
# catalogo declara la red a la que quiere llegar, no el prefijo que le vaya a
# poner el cliente.
function Get-RouteTo {
    param([string] $Address)
    try {
        $found = Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop |
            Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } |
            Select-Object -First 1 InterfaceIndex, DestinationPrefix
        if ($null -eq $found) { return $null }
        return [pscustomobject] @{
            InterfaceIndex = [int] $found.InterfaceIndex
            # La ruta por defecto encaja con TODO, asi que encontrar ruta no
            # demuestra nada por si solo: sin ningun tunel tambien se
            # encuentra. Lo que distingue es que haya una ruta mas concreta.
            IsDefault      = ([string] $found.DestinationPrefix -in @('0.0.0.0/0', '::/0'))
        }
    }
    catch {
        # Sin ruta hacia ahi. No es un fallo del script: es la respuesta.
        return $null
    }
}

try {
    $networks = @($TargetNetworks -split ',' | Where-Object { $_ })

    # 1. Por donde sale el trafico hacia la IP testigo. Todo lo demas se mide
    #    contra esto: es el interfaz que de verdad se esta usando.
    $probeRoute = Get-RouteTo $ProbeIp
    $probeInterface = if ($null -eq $probeRoute) { $null } else { $probeRoute.InterfaceIndex }

    # 2. Hay un adaptador levantado que lleve a la IP testigo. Contar cualquier
    #    adaptador 'Up' no dice nada: en un portatil con wifi siempre hay uno,
    #    y la comprobacion seria cierta con el tunel caido.
    $adapterUp = $false
    if ($null -ne $probeInterface) {
        $adapterUp = @(
            Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Up' -and [int] $_.ifIndex -eq $probeInterface }
        ).Count -gt 0
    }

    # 3. El trafico hacia cada red declarada sale por ese mismo interfaz, y por
    #    una ruta concreta y no por la de por defecto.
    #
    #    Lo segundo hace falta porque la ruta por defecto encaja con todo: sin
    #    ningun tunel, preguntar "por donde voy a 10.0.0.0" tambien contesta, y
    #    contestaria lo mismo que para la IP testigo. Sin esta condicion, un
    #    equipo pelado daba `routed` cierto y el perfil aparecia como
    #    "conectado con avisos" en vez de "caido".
    #
    #    Un tunel completo puede no instalar mas ruta que la de por defecto, y
    #    entonces `specific` es falso aunque el tunel exista. Para ese caso vale
    #    que la IP testigo conteste: si contesta una IP interna, hay tunel. Es
    #    la unica prueba que queda, y por eso entra aqui.
    $sameInterface = ($null -ne $probeInterface)
    $specific = ($null -ne $probeRoute -and -not $probeRoute.IsDefault)
    foreach ($network in $networks) {
        # La direccion de red basta para preguntar por donde se sale.
        $route = Get-RouteTo (($network.Trim() -split '/')[0])
        if ($null -eq $route -or $route.InterfaceIndex -ne $probeInterface) {
            $sameInterface = $false
        }
        elseif (-not $route.IsDefault) {
            $specific = $true
        }
    }

    # 4. La IP testigo interna responde. Es la unica que demuestra que por el
    #    tunel pasa trafico de verdad y no solo que exista un adaptador.
    #    Test-Connection cambia de parametros entre Windows PowerShell 5.1 y
    #    PowerShell 7 (-ComputerName frente a -TargetName, y -TimeoutSeconds
    #    no existe en 5.1). Se usa Ping directamente, que es igual en las dos
    #    y ademas permite fijar el tiempo de espera de verdad.
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $ping.Send($ProbeIp, $TimeoutSeconds * 1000)
        $answers = ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    }
    catch {
        $answers = $false
    }
    finally {
        $ping.Dispose()
    }

    # `specific` o, si no lo hay, que conteste una IP interna. Cualquiera de
    # las dos demuestra tunel; ninguna de las dos, no hay nada que demostrar.
    $routed = ($sameInterface -and ($specific -or $answers))

    Write-Result @{
        ok           = $true
        adapterUp    = [bool] $adapterUp
        routed       = [bool] $routed
        probeAnswers = [bool] $answers
        connected    = ([bool] $adapterUp -and [bool] $routed -and [bool] $answers)
        # Para el log y para depurar en un puesto: dice POR QUE salio lo que
        # salio, sin tener que volver a lanzarlo a mano.
        viaSpecificRoute = [bool] $specific
        sameInterface    = [bool] $sameInterface
    }
}
catch {
    Write-Result @{
        ok    = $false
        error = 'no se pudo comprobar el estado del tunel'
    }
    exit 1
}
