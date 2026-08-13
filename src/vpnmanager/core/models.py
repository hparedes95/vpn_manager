"""Modelos de dominio del orquestador.

Nada de este módulo toca Windows ni la red: es lógica pura y por tanto
testeable en CI sin un cliente VPN instalado.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import PureWindowsPath

# `ipaddress` y `PureWindowsPath` solo parsean: no resuelven nombres, no tocan
# red y no miran el disco. Se comportan igual en el runner de Linux que en un
# puesto, que es justo lo que hace falta aqui.


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_network(value: str) -> bool:
    """CIDR bien formado, con los bits de host a cero.

    `10.0.0.5/8` se rechaza a proposito: en una tabla de rutas eso siempre es
    una errata, y una errata en el catalogo la paga el usuario sin red.
    """
    try:
        ipaddress.ip_network(value)
    except ValueError:
        return False
    return True


class Capability(Enum):
    """Lo que un conector puede hacer de verdad con su cliente oficial.

    La interfaz se construye a partir de esto: si un conector no declara
    CONNECT, el botón dice "Abrir cliente", no "Conectar". Prometer
    automatización que no existe es peor que no tenerla.
    """

    LAUNCH = auto()  # abrir el cliente oficial
    CONNECT = auto()  # además, pedirle que conecte a un perfil concreto
    DISCONNECT = auto()  # además, pedirle que desconecte
    STATUS = auto()  # el cliente reporta su propio estado


class TunnelType(Enum):
    FULL = "full"  # captura todo el tráfico: entra en el árbitro
    SPLIT = "split"  # solo rutas concretas: convive con otros
    APP = "app"  # reenvío TCP por aplicación (IAP Desktop): nunca entra en el árbitro


class ConnectionState(Enum):
    DISCONNECTED = "desconectado"
    LAUNCHING = "lanzando"
    WAITING_AUTH = "esperando autenticacion del usuario"
    CONNECTED = "conectado"
    DEGRADED = "conectado con avisos"
    DOWN = "caido"
    ERROR = "error"


class LaunchKind(Enum):
    """Cómo se arranca el binario oficial.

    MSIX existe por el Azure VPN Client: es app de Store, no tiene ruta de
    ejecutable utilizable y se lanza por su Package Family Name.
    """

    EXE = "exe"
    MSIX = "msix"


@dataclass(frozen=True)
class LaunchSpec:
    kind: LaunchKind
    target: str  # ruta al .exe, o PFN!AppId para MSIX
    args: tuple[str, ...] = ()

    def validate(self) -> list[str]:
        issues: list[str] = []
        if not self.target:
            issues.append("target vacio")
        if self.kind is LaunchKind.MSIX and "!" not in self.target:
            issues.append("un target MSIX debe tener el formato <PackageFamilyName>!<AppId>")
        if self.kind is LaunchKind.EXE and not self.target.lower().endswith(".exe"):
            issues.append("un target EXE debe apuntar a un .exe")
        elif self.kind is LaunchKind.EXE:
            issues.extend(self._path_issues())
        return issues

    def _path_issues(self) -> list[str]:
        """Dónde puede estar el binario.

        Lo ejecuta un servicio en SYSTEM, así que el sitio importa tanto como
        el nombre. Una ruta relativa se resolvería contra el directorio de
        trabajo del servicio, y ahí un usuario sin privilegios puede dejar su
        propio `wireguard.exe`. Un recurso de red (`\\\\servidor\\...`) lo
        controla quien controle ese servidor, que no somos nosotros.
        """
        path = PureWindowsPath(self.target)
        if path.drive.startswith("\\\\"):
            return ["un target EXE no puede estar en un recurso de red"]
        if not path.is_absolute():
            return ["un target EXE debe ser una ruta absoluta"]
        return []


class DisconnectStrategy(Enum):
    """Qué hacer al desconectar cuando el cliente no expone una orden para ello."""

    NONE = "none"  # no se puede: se avisa al usuario y punto
    CLI = "cli"  # el cliente admite una orden de desconexión
    TERMINATE = "terminate"  # matar el proceso. Contundente; solo si está validado para ese cliente


@dataclass(frozen=True)
class Profile:
    """Una VPN de un cliente concreto.

    Se carga del catálogo firmado (ADR-003). El usuario no lo edita:
    define qué binario ejecuta un servicio en SYSTEM.
    """

    id: str
    display_name: str
    connector: str  # nombre del conector que lo gobierna
    launch: LaunchSpec
    tunnel_type: TunnelType
    target_networks: tuple[str, ...] = ()  # CIDR alcanzables a traves del tunel
    probe_ip: str | None = None  # IP testigo interna para verificar estado real
    dns: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    post_connect_apps: tuple[LaunchSpec, ...] = ()
    expected_client_version: str | None = None
    breaks_local_connectivity: bool = False  # exige confirmacion explicita (HU-03)
    disconnect_strategy: DisconnectStrategy = DisconnectStrategy.NONE
    notes: str = ""

    def validate(self) -> list[str]:
        issues = list(self.launch.validate())
        if not self.id:
            issues.append("id vacio")
        if not self.display_name:
            issues.append("display_name vacio: la interfaz no tendria como llamarlo")
        if not self.connector:
            issues.append("connector vacio: nadie gobernaria este perfil")
        # Las aplicaciones posteriores a la conexion las lanza el mismo
        # servicio en SYSTEM que el cliente VPN: pasan el mismo filtro.
        for index, app in enumerate(self.post_connect_apps):
            issues.extend(f"post_connect_apps[{index}]: {issue}" for issue in app.validate())
        if self.tunnel_type is TunnelType.APP:
            if self.routes:
                issues.append("un perfil de tipo APP no debe aplicar rutas")
            if self.dns:
                issues.append("un perfil de tipo APP no debe aplicar DNS")
        if self.probe_ip is None and self.tunnel_type is not TunnelType.APP:
            issues.append("sin probe_ip no se puede verificar el estado real (HU-02)")
        elif self.probe_ip is not None and not is_ip_address(self.probe_ip):
            issues.append(f"probe_ip '{self.probe_ip}' no es una IP")
        issues.extend(self._address_issues())
        return issues

    def _address_issues(self) -> list[str]:
        """Formato de lo que acabará en la tabla de rutas y en la config de DNS.

        Se valida aquí, en logica pura, y no cuando ya se está ejecutando un
        `.ps1` como SYSTEM con esos valores por parámetro.
        """
        issues: list[str] = []
        for field_name, values in (
            ("target_networks", self.target_networks),
            ("routes", self.routes),
        ):
            issues.extend(
                f"{field_name}: '{value}' no es una red en formato CIDR"
                for value in values
                if not is_network(value)
            )
        issues.extend(
            f"dns: '{value}' no es una IP" for value in self.dns if not is_ip_address(value)
        )
        return issues


@dataclass
class Session:
    """Estado vivo de un perfil. Lo mantiene el servicio, no la interfaz."""

    profile_id: str
    state: ConnectionState = ConnectionState.DISCONNECTED
    pid: int | None = None
    applied_routes: list[str] = field(default_factory=list)
    applied_dns: list[str] = field(default_factory=list)
    message: str = ""


@dataclass(frozen=True)
class Result:
    ok: bool
    state: ConnectionState
    message: str = ""
    pid: int | None = None  # el proceso que se arranco, si se arranco alguno

    @staticmethod
    def failure(message: str) -> Result:
        return Result(ok=False, state=ConnectionState.ERROR, message=message)

    @staticmethod
    def success(state: ConnectionState, message: str = "", pid: int | None = None) -> Result:
        return Result(ok=True, state=state, message=message, pid=pid)
