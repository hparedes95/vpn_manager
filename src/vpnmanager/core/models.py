"""Modelos de dominio del orquestador.

Nada de este módulo toca Windows ni la red: es lógica pura y por tanto
testeable en CI sin un cliente VPN instalado.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import PureWindowsPath

# El id de un perfil es lo unico que viaja de la interfaz al servicio. Se
# restringe aqui, en el modelo, para que el catalogo y el protocolo del pipe
# no puedan discrepar: si el pipe aceptase menos que el catalogo, habria
# perfiles inalcanzables; si aceptase mas, seria un agujero.
PROFILE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def is_valid_profile_id(value: str) -> bool:
    return PROFILE_ID_PATTERN.match(value) is not None


def suggest_profile_id(display_name: str) -> str:
    """Un id valido a partir del nombre que ha escrito una persona.

    Existe para que nadie tenga que inventarse un identificador: quien da de
    alta una VPN escribe «Ivanti — Cliente B» y el id sale solo. Sigue siendo
    editable, porque el id es lo unico que viaja por el pipe y quien sepa lo
    que hace puede querer elegirlo.

    Se quitan los acentos en vez de rechazarlos: los nombres van a venir en
    español y «Conexión» tiene que poder dar `conexion`, no un error.

    Devuelve cadena vacia si no queda nada aprovechable. No se inventa un id de
    relleno: un `perfil-1` automatico es justo el nombre que nadie reconoce
    despues en un log.
    """
    stripped = unicodedata.normalize("NFKD", display_name)
    ascii_only = "".join(
        character for character in stripped if not unicodedata.combining(character)
    )
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", ascii_only).strip("-._").lower()
    slug = re.sub(r"-{2,}", "-", slug)[:64].strip("-._")
    return slug if is_valid_profile_id(slug) else ""


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
    # Se abrio el cliente y no hay forma de comprobar si el tunel esta en pie:
    # al perfil le falta la IP testigo. No es un estado bueno ni malo, es la
    # ausencia de dato, y por eso tiene nombre propio.
    #
    # Existe para poder dar de alta una VPN sin saberlo todo de ella. Sin este
    # estado la unica alternativa honesta era exigir la IP testigo al crear el
    # perfil, y eso es un pez que se muerde la cola: la IP interna que responde
    # solo se averigua conectando la VPN, y la VPN no se podia dar de alta sin
    # ella. Nunca se confunde con CONNECTED, que sigue exigiendo las tres
    # comprobaciones.
    UNVERIFIED = "abierto - sin comprobar"
    ERROR = "error"


class LaunchKind(Enum):
    """Cómo se arranca el binario oficial.

    MSIX existe por el Azure VPN Client: es app de Store, no tiene ruta de
    ejecutable utilizable y se lanza por su Package Family Name.
    """

    EXE = "exe"
    MSIX = "msix"


class LaunchContext(Enum):
    """En que proceso se ejecuta el binario. Lo decide el catalogo, por perfil.

    Los clientes VPN con interfaz tienen que aparecer en la sesion del usuario:
    el servicio corre en SYSTEM, en la sesion 0, donde no hay escritorio. Un
    cliente lanzado ahi seria invisible y no podria pedir credenciales ni MFA,
    ademas de no alcanzar el almacen de credenciales del usuario.

    Por eso `USER_SESSION` es el valor por defecto y el habitual: el servicio
    manda a la interfaz la orden de lanzar y la interfaz arranca el proceso con
    los permisos que el usuario ya tiene. El dato viaja del proceso
    privilegiado al que no lo es, nunca al reves, asi que no hay escalada: la
    interfaz no puede lanzar nada que el usuario no pudiera lanzar solo.

    `SERVICE` es para lo que de verdad necesita privilegio y no es interactivo,
    como `wireguard.exe /installtunnelservice`. Lo ejecuta SYSTEM y por eso es
    la opcion que hay que justificar, no la que se coge por comodidad.
    """

    USER_SESSION = "user_session"
    SERVICE = "service"


@dataclass(frozen=True)
class LaunchSpec:
    kind: LaunchKind
    target: str  # ruta al .exe, o PFN!AppId para MSIX
    args: tuple[str, ...] = ()
    context: LaunchContext = LaunchContext.USER_SESSION

    def validate(self) -> list[str]:
        issues: list[str] = []
        if not self.target:
            issues.append("target vacio")
        if self.kind is LaunchKind.MSIX and "!" not in self.target:
            issues.append("un target MSIX debe tener el formato <PackageFamilyName>!<AppId>")
        if self.kind is LaunchKind.MSIX and self.context is LaunchContext.SERVICE:
            # Una app de Store se resuelve contra el usuario que la tiene
            # instalada. Desde SYSTEM no hay tal usuario.
            issues.append("un target MSIX solo se puede lanzar en la sesion del usuario")
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
    # Como se llama esta conexion DENTRO del cliente oficial. Un FortiClient
    # con tres tuneles configurados se abre igual para los tres; sin esto, tres
    # perfiles del mismo cliente serian indistinguibles.
    #
    # Es un selector, no configuracion de conexion: aqui no entran la direccion
    # del gateway, el usuario ni el certificado. Eso vive en el almacen del
    # cliente oficial y de ahi no se mueve.
    client_profile_name: str = ""
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
        elif not is_valid_profile_id(self.id):
            issues.append(
                "el id solo admite letras, digitos, punto, guion y guion bajo, hasta 64 caracteres"
            )
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
        # Que falte la IP testigo NO invalida el perfil: lo deja sin verificar,
        # que es un estado con nombre propio (UNVERIFIED) y se ve en la
        # interfaz. Rechazarlo aqui obligaria a conocer una IP interna que solo
        # se averigua conectando la VPN, y la VPN no se podria dar de alta sin
        # ella. Va en `warnings()`. Lo que si es un error es una que no es una
        # IP: eso no es un dato que falta, es un dato mal puesto.
        if self.probe_ip is not None and not is_ip_address(self.probe_ip):
            issues.append(f"probe_ip '{self.probe_ip}' no es una IP")
        issues.extend(self._client_profile_name_issues())
        issues.extend(self._address_issues())
        return issues

    def warnings(self) -> list[str]:
        """Lo que cojea sin impedir que el perfil se cargue.

        Separado de `validate()` a proposito: el catalogo es todo o nada, asi
        que meter aqui algo que solo es una carencia dejaria al equipo sin
        ninguna VPN por un perfil al que le falta un dato opcional.
        """
        issues: list[str] = []
        if not self.needs_verification:
            return issues
        if not self.can_verify_state and self.tunnel_type is TunnelType.FULL:
            issues.append(
                "un tunel COMPLETO sin probe_ip se deshara solo a los 90 s: la "
                "interfaz solo confirma lo que puede comprobar, y sin confirmacion "
                "el watchdog revierte. Ponle una IP testigo antes de usarlo"
            )
        elif not self.can_verify_state:
            issues.append(
                "sin probe_ip no se puede verificar el estado real (HU-02): "
                "se abrira el cliente, pero nunca dira 'conectado'"
            )
        if self.can_verify_state and not self.target_networks:
            issues.append(
                "sin target_networks no se puede comprobar la ruta: el estado "
                "se apoyara solo en que la IP testigo responda"
            )
        return issues

    @property
    def can_verify_state(self) -> bool:
        """Si hay con que comprobar el estado real de este perfil."""
        return self.probe_ip is not None

    @property
    def needs_verification(self) -> bool:
        """Si a este perfil le corresponde tener estado real que comprobar.

        Un APP no monta adaptador ni pone rutas —es reenvio TCP por
        aplicacion— asi que no es que le falte la IP testigo: es que no aplica.

        Existe como propiedad porque esa excepcion estaba repetida en cuatro
        sitios como `... and tunnel_type is not APP`, y en uno de ellos se
        habia olvidado: un APP con IP testigo y sin redes recibia el aviso de
        que no se podia comprobar la ruta, cuando la sonda ni llega a mirarla.
        """
        return self.tunnel_type is not TunnelType.APP

    def _client_profile_name_issues(self) -> list[str]:
        """El nombre de la conexion dentro del cliente oficial.

        Sale del catalogo firmado, igual que `launch.target` y `launch.args`, y
        el dia que un conector verificado sepa pedir una conexion concreta sera
        un elemento mas de la lista de argumentos. Nunca una linea de comandos
        montada por concatenacion, y nunca algo que llegue por el pipe.

        Aun asi se acota: un salto de linea o un caracter de control en un
        argumento no tiene ningun uso legitimo y si complica leer un log.
        """
        if not self.client_profile_name:
            return []
        if len(self.client_profile_name) > 128:
            return ["client_profile_name: demasiado largo (maximo 128 caracteres)"]
        if any(character < " " or character == "\x7f" for character in self.client_profile_name):
            return ["client_profile_name: no puede llevar caracteres de control"]
        return []

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


@dataclass(frozen=True)
class ProbeResult:
    """Las tres comprobaciones del estado real, por separado.

    Por separado y no un si o un no, porque la diferencia entre "el tunel esta
    montado pero no pasa trafico" y "no hay tunel" es la que separa un aviso
    de una caida, y al usuario le cambia mucho lo que tiene que hacer.
    """

    adapter_up: bool = False
    routed: bool = False
    probe_answers: bool = False
    # False si la comprobacion no se pudo hacer. No es lo mismo que fallar:
    # no saber no es lo mismo que saber que no.
    checked: bool = True

    @property
    def connected(self) -> bool:
        return self.adapter_up and self.routed and self.probe_answers

    def state(self, *, previous: ConnectionState) -> ConnectionState:
        """El estado que corresponde. `previous` se conserva si no se pudo mirar."""
        if not self.checked:
            return previous
        if self.connected:
            return ConnectionState.CONNECTED
        if self.adapter_up and self.routed:
            # El tunel esta montado y la ruta puesta, pero la IP testigo no
            # contesta: hay algo, y no sirve del todo.
            return ConnectionState.DEGRADED
        return ConnectionState.DOWN


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
