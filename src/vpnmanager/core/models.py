"""Modelos de dominio del orquestador.

Nada de este módulo toca Windows ni la red: es lógica pura y por tanto
testeable en CI sin un cliente VPN instalado.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


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
        return issues


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
        if self.tunnel_type is TunnelType.APP and self.routes:
            issues.append("un perfil de tipo APP no debe aplicar rutas")
        if self.probe_ip is None and self.tunnel_type is not TunnelType.APP:
            issues.append("sin probe_ip no se puede verificar el estado real (HU-02)")
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

    @staticmethod
    def failure(message: str) -> Result:
        return Result(ok=False, state=ConnectionState.ERROR, message=message)
