"""Los clientes VPN que se gobiernan, y lo que se sabe de cada uno.

**Los ocho son `LauncherConnector`.** Ninguno declara `CONNECT` ni
`DISCONNECT`, porque ninguno se ha comprobado en un puesto real. La interfaz
ofrecera "Abrir cliente" para todos, y eso es exactamente lo que el software
sabe hacer hoy.

No hay ocho modulos con una clase vacia cada uno: hoy los ocho son el mismo
conector con distinto nombre, y ocho ficheros identicos no serian codigo, solo
decorado. Cuando de uno se compruebe algo —que `pulselauncher.exe` acepta una
orden de conexion, por ejemplo— ese se muda a su propio modulo con su
implementacion, y aqui se deja de construir el generico.

Lo que se sabe y lo que no de cada cliente se anota en `docs/CONECTORES.md`.
Aqui solo esta el nombre, que es lo que casa con `Profile.connector`, y una
linea de por que sigue siendo un simple lanzador.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from vpnmanager.connectors.base import (
    Connector,
    ConnectorRegistry,
    LauncherConnector,
    ProcessLauncher,
)


@dataclass(frozen=True)
class Provider:
    """Un cliente VPN de la lista, y en que estado esta su automatizacion."""

    name: str  # casa con `Profile.connector`
    display_name: str
    pending: str  # que habria que comprobar para que deje de ser un lanzador


PROVIDERS: Final = (
    Provider(
        "wireguard",
        "WireGuard",
        "se espera automatizacion total con /installtunnelservice; sin comprobar",
    ),
    Provider(
        "openvpn",
        "OpenVPN",
        "se espera automatizacion total con --command connect; sin comprobar",
    ),
    Provider(
        "ivanti",
        "Ivanti Secure Access",
        "pulselauncher.exe promete mucho en la documentacion; sin comprobar",
    ),
    Provider(
        "globalprotect",
        "GlobalProtect",
        "lo que admita depende de la version instalada; sin comprobar",
    ),
    Provider(
        "forticlient",
        "FortiClient VPN",
        "con SSO la automatizacion puede ser directamente imposible",
    ),
    Provider(
        "forcepoint",
        "Forcepoint VPN",
        "nadie ha mirado si expone algo; se asume que solo se abre",
    ),
    Provider(
        "azure",
        "Azure VPN Client",
        "app MSIX de Store: se abre por Package Family Name y poco mas",
    ),
    Provider(
        "iap",
        "IAP Desktop",
        "no es una VPN: reenvio TCP por aplicacion, fuera del arbitro de tunel",
    ),
)


def build_registry(launcher: ProcessLauncher) -> ConnectorRegistry:
    """Monta el registro con todos los conectores conocidos.

    Se llama una vez al arrancar el servicio, con conectores definidos en
    codigo. Nunca con nada que venga del pipe.
    """
    registry = ConnectorRegistry()
    for provider in PROVIDERS:
        registry.register(build_connector(provider, launcher))
    return registry


def build_connector(provider: Provider, launcher: ProcessLauncher) -> Connector:
    """El conector de un proveedor.

    Hoy siempre el generico. Cuando alguno se verifique, aqui se elegira su
    clase en vez de esta, y sera un cambio de una linea con un test detras.
    """
    return LauncherConnector(name=provider.name, launcher=launcher)
