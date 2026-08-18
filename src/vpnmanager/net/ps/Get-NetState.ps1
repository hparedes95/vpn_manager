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

# Si el DNS de un adaptador esta puesto a mano o lo da el DHCP.
#
# `Get-DnsClientServerAddress` devuelve los servidores que estan EN USO, sin
# decir de donde salen. La diferencia importa al restaurar: volver a escribir
# unos servidores que venian por DHCP no los devuelve a su sitio, los clava a
# mano, y el adaptador deja de seguir al DHCP para siempre.
#
# El registro es lo unico que lo distingue: `NameServer` solo tiene valor
# cuando alguien los puso a mano; los del DHCP viven en `DhcpNameServer`.
function Test-StaticDns {
    param([int] $InterfaceIndex, [hashtable] $GuidByIndex)

    $guid = $GuidByIndex[$InterfaceIndex]
    if (-not $guid) { return $null }  # no se sabe; no es lo mismo que "no"

    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
    try {
        $value = (Get-ItemProperty -LiteralPath $key -Name 'NameServer' -ErrorAction Stop).NameServer
        return -not [string]::IsNullOrWhiteSpace($value)
    }
    catch {
        return $null
    }
}

try {
    $guidByIndex = @{}
    foreach ($adapter in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
        if ($adapter.InterfaceGuid) {
            $guidByIndex[[int] $adapter.ifIndex] = [string] $adapter.InterfaceGuid
        }
    }

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
                    # $true a mano, $false por DHCP, $null si no se ha podido
                    # averiguar. Los tres casos se tratan distinto al restaurar.
                    static         = (Test-StaticDns ([int] $_.InterfaceIndex) $guidByIndex)
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
