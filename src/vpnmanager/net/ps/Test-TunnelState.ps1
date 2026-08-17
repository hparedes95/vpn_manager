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

    -TargetNetwork admite varias redes separadas por coma. Los valores salen
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

try {
    # 1. Hay un adaptador levantado que lleve a la red destino. Contar
    #    cualquier adaptador 'Up' no dice nada: en un portatil con wifi
    #    siempre hay uno, y la comprobacion seria cierta con el tunel caido.
    #    Se mira el interfaz por el que sale la ruta hacia cada red destino.
    $networks = @($TargetNetworks -split ',' | Where-Object { $_ })
    $tunnelInterfaces = @()
    foreach ($network in $networks) {
        $tunnelInterfaces += @(
            Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $network.Trim() -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty InterfaceIndex
        )
    }
    $adapterUp = if ($tunnelInterfaces.Count -gt 0) {
        @(
            Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Up' -and $tunnelInterfaces -contains [int] $_.ifIndex }
        ).Count -gt 0
    } else {
        $false
    }

    # 2. Hay ruta hacia cada red destino declarada en el perfil. Sin redes
    #    declaradas no se puede afirmar nada: mejor decir que no que dar por
    #    buena una comprobacion que no se ha hecho.
    $routed = ($networks.Count -gt 0)
    foreach ($network in $networks) {
        $hasRoute = @(
            Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.DestinationPrefix -eq $network.Trim() }
        ).Count -gt 0
        if (-not $hasRoute) { $routed = $false }
    }

    # 3. La IP testigo interna responde. Es la unica que demuestra que por el
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

    Write-Result @{
        ok         = $true
        adapterUp  = [bool] $adapterUp
        routed     = [bool] $routed
        probeAnswers = [bool] $answers
        connected  = ([bool] $adapterUp -and [bool] $routed -and [bool] $answers)
    }
}
catch {
    Write-Result @{
        ok    = $false
        error = 'no se pudo comprobar el estado del tunel'
    }
    exit 1
}
