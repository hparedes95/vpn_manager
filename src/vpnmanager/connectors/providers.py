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

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vpnmanager.connectors.base import (
    Connector,
    ConnectorRegistry,
    LauncherConnector,
    ProcessLauncher,
)
from vpnmanager.core.models import LaunchKind


@dataclass(frozen=True)
class Provider:
    """Un cliente VPN de la lista, y en que estado esta su automatizacion."""

    name: str  # casa con `Profile.connector`
    display_name: str
    pending: str  # que habria que comprobar para que deje de ser un lanzador
    # Donde SUELE instalarse. Son candidatas, no verdades: ninguna se ha
    # comprobado contra los equipos reales, que es lo que CLAUDE.md prohibe dar
    # por hecho. Por eso no se usan como dato, sino como sitios donde mirar:
    # `detect` solo devuelve la que existe en ESTA maquina, y si no hay
    # ninguna, el usuario la busca a mano. Una candidata equivocada no rompe
    # nada, simplemente no aparece.
    candidates: tuple[str, ...] = ()
    launch_kind: LaunchKind = LaunchKind.EXE
    # Como se llama en su cliente lo que aqui es un perfil. Cambia de uno a
    # otro —tunel, conexion, VPN— y decirlo con su palabra ahorra dudas.
    connection_word: str = "conexion"


PROVIDERS: Final = (
    Provider(
        "wireguard",
        "WireGuard",
        "se espera automatizacion total con /installtunnelservice; sin comprobar",
        candidates=(r"C:\Program Files\WireGuard\wireguard.exe",),
        connection_word="tunel",
    ),
    Provider(
        "openvpn",
        "OpenVPN",
        "se espera automatizacion total con --command connect; sin comprobar",
        candidates=(
            r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe",
        ),
        connection_word="perfil (.ovpn)",
    ),
    Provider(
        "ivanti",
        "Ivanti Secure Access",
        "pulselauncher.exe promete mucho en la documentacion; sin comprobar",
        # Dos marcas para el mismo producto: Pulse Secure paso a ser Ivanti y
        # segun cuando se instalara el cliente, la carpeta lleva un nombre u
        # otro.
        candidates=(
            r"C:\Program Files (x86)\Common Files\Ivanti\Integration\pulselauncher.exe",
            r"C:\Program Files (x86)\Common Files\Pulse Secure\Integration\pulselauncher.exe",
            r"C:\Program Files (x86)\Ivanti\Secure Access Client\pulseUi.exe",
            r"C:\Program Files (x86)\Pulse Secure\Pulse\pulseUi.exe",
        ),
    ),
    Provider(
        "globalprotect",
        "GlobalProtect",
        "lo que admita depende de la version instalada; sin comprobar",
        candidates=(
            r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe",
            r"C:\Program Files (x86)\Palo Alto Networks\GlobalProtect\PanGPA.exe",
        ),
        connection_word="portal",
    ),
    Provider(
        "forticlient",
        "FortiClient VPN",
        "con SSO la automatizacion puede ser directamente imposible",
        candidates=(
            r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe",
            r"C:\Program Files (x86)\Fortinet\FortiClient\FortiClient.exe",
        ),
        connection_word="conexion VPN",
    ),
    Provider(
        "forcepoint",
        "Forcepoint VPN",
        "nadie ha mirado si expone algo; se asume que solo se abre",
        # Sin candidatas: nadie ha mirado donde se instala, y una ruta
        # inventada aqui solo serviria para no encontrarlo con mas ceremonia.
    ),
    Provider(
        "azure",
        "Azure VPN Client",
        "app MSIX de Store: se abre por Package Family Name y poco mas",
        # Una app de Store no tiene ruta que comprobar. Se ofrece su Package
        # Family Name y ya dira el propio Windows si no esta instalada.
        candidates=("Microsoft.AzureVpn_8wekyb3d8bbwe!App",),
        launch_kind=LaunchKind.MSIX,
    ),
    Provider(
        "iap",
        "IAP Desktop",
        "no es una VPN: reenvio TCP por aplicacion, fuera del arbitro de tunel",
        # Suele instalarse por usuario, no para toda la maquina.
        candidates=(
            r"C:\Program Files\Google\IAP Desktop\IapDesktop.exe",
            r"C:\Program Files (x86)\Google\IAP Desktop\IapDesktop.exe",
        ),
        connection_word="proyecto",
    ),
)

PROVIDERS_BY_NAME: Final = {provider.name: provider for provider in PROVIDERS}


def detect(provider: Provider, exists: Callable[[str], bool] | None = None) -> str | None:
    """Donde esta instalado este cliente en ESTA maquina, si es que esta.

    Mira, no supone. Devuelve la primera candidata que existe de verdad, o
    `None` para que la interfaz pida la ruta a mano en vez de rellenar algo
    que no esta.

    Las MSIX se devuelven tal cual: no son una ruta y no hay nada que mirar en
    el disco. Es el unico caso en que esto no comprueba nada, y por eso es el
    unico que puede devolver algo que no exista.
    """
    if not provider.candidates:
        return None
    if provider.launch_kind is LaunchKind.MSIX:
        return provider.candidates[0]

    check = _exists if exists is None else exists
    return next((candidate for candidate in provider.candidates if check(candidate)), None)


def _exists(candidate: str) -> bool:
    """Solo mira si hay un fichero ahi. No ejecuta nada ni lo abre."""
    try:
        return Path(candidate).is_file()
    except OSError:
        # Una ruta que el sistema no puede ni evaluar no es una candidata.
        return False


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
