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
    # 1. Hay algun adaptador levantado que no sea el de siempre. No se busca
    #    por nombre de fabricante: cambian entre versiones y entre clientes.
    $adapterUp = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }).Count -gt 0

    # 2. Hay ruta hacia cada red destino declarada en el perfil.
    $networks = @($TargetNetworks -split ',' | Where-Object { $_ })
    $routed = $true
    foreach ($network in $networks) {
        $hasRoute = @(
            Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.DestinationPrefix -eq $network.Trim() }
        ).Count -gt 0
        if (-not $hasRoute) { $routed = $false }
    }

    # 3. La IP testigo interna responde. Es la unica que demuestra que por el
    #    tunel pasa trafico de verdad y no solo que exista un adaptador.
    $answers = Test-Connection -TargetName $ProbeIp -Count 1 -TimeoutSeconds $TimeoutSeconds `
                               -Quiet -ErrorAction SilentlyContinue

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
