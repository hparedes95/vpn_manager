<#
.SYNOPSIS
    Fotografia el estado de red que hay que poder restaurar.

.DESCRIPTION
    Devuelve rutas y DNS por adaptador, en JSON. Es lo que el servicio guarda
    antes de conectar un tunel completo y lo que le devuelve a
    Restore-NetState.ps1 si nadie confirma la conexion.

    Salida siempre JSON, tambien cuando falla. Un throw a secas dejaria al
    servicio adivinando.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Write-Result {
    param([hashtable] $Result)
    # -Compress: el salto de linea es el separador de mensajes del lado Python.
    Write-Output ($Result | ConvertTo-Json -Depth 6 -Compress)
}

try {
    $routes = @(
        Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -and $_.InterfaceIndex } |
            ForEach-Object {
                @{
                    destination    = $_.DestinationPrefix
                    next_hop       = $_.NextHop
                    interfaceIndex = [int] $_.InterfaceIndex
                    metric         = [int] $_.RouteMetric
                    store          = [string] $_.Store
                }
            }
    )

    $dns = @(
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object {
                @{
                    interfaceIndex = [int] $_.InterfaceIndex
                    interfaceAlias = [string] $_.InterfaceAlias
                    servers        = @($_.ServerAddresses)
                }
            }
    )

    $adapters = @(
        Get-NetAdapter -ErrorAction Stop |
            Where-Object { $_.Status -eq 'Up' } |
            ForEach-Object {
                @{
                    interfaceIndex = [int] $_.ifIndex
                    name           = [string] $_.Name
                }
            }
    )

    Write-Result @{
        ok       = $true
        routes   = $routes
        dns      = $dns
        adapters = $adapters
    }
}
catch {
    # Sin detalles del sistema: el mensaje acaba en el log del servicio y
    # puede arrastrar nombres de adaptador o rutas internas.
    Write-Result @{
        ok    = $false
        error = 'no se pudo leer el estado de red'
    }
    exit 1
}
