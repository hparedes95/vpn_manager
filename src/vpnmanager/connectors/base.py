"""Interfaz comun de los conectores y el conector minimo.

Un conector gobierna un cliente VPN **oficial ya instalado**: lo abre y, si
se ha comprobado que ese cliente obedece, le pide conectar o desconectar. No
implementa el tunel ni parsea protocolos propietarios.

Tres decisiones que conviene entender antes de tocar nada:

**El conector no arranca procesos, se los pide a un puerto.** `ProcessLauncher`
se inyecta. Asi este modulo es logica pura —se testea en CI sobre Linux, sin
Windows y sin ningun cliente instalado— y la creacion de procesos queda en un
unico sitio, que es el que hay que auditar.

**Las comprobaciones estan en la clase base, no en cada proveedor.** Los
metodos publicos (`launch`, `connect`, `disconnect`, `status`) verifican
capacidad, propiedad del perfil y validez del perfil, y solo entonces delegan
en el `_launch`/`_connect`/... del proveedor. Un conector nuevo no puede
saltarse la comprobacion por descuido: para llegar a ejecutar algo tiene que
haber pasado por aqui.

**Lo unico que entra es un `Profile` del catalogo firmado.** Ninguna funcion de
este modulo acepta una ruta, un argumento ni un comando sueltos. Si algun dia
una firma de este fichero admite un `str` que acabe en una linea de comandos,
es una escalada de privilegios local: el servicio corre en SYSTEM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    DisconnectStrategy,
    LaunchSpec,
    Profile,
    Result,
)


@dataclass(frozen=True)
class LaunchOutcome:
    """Lo que responde un lanzador cuando se le pide arrancar algo.

    `pid` puede ser None aunque `started` sea True: una app MSIX se lanza a
    traves del shell y no devuelve un pid utilizable.
    """

    started: bool
    pid: int | None = None
    detail: str = ""


class ProcessLauncher(Protocol):
    """Puerto: quien sabe arrancar un binario en este sistema.

    La implementacion real vive fuera del nucleo y depende de Windows. Los
    tests inyectan una que no arranca nada y anota lo que se le pidio.
    """

    def start(self, spec: LaunchSpec) -> LaunchOutcome: ...


class Connector(ABC):
    """Base de todos los conectores.

    Un conector declara en `capabilities` lo que su cliente hace **de verdad**,
    no lo que promete su documentacion. La interfaz se dibuja a partir de esa
    declaracion: sin `CONNECT` el boton dice "Abrir cliente".
    """

    # Identificador del conector. Coincide con `Profile.connector`.
    name: str = ""

    # Vacio a proposito: un conector que no declara nada no pasa
    # `validate_declaration()` y el registro lo rechaza.
    capabilities: frozenset[Capability] = frozenset()

    def supports(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def validate_declaration(self) -> list[str]:
        """Comprueba que el conector puede cumplir lo que declara.

        Declarar `CONNECT` sin implementar `_connect` es la forma facil de
        acabar con un boton que no hace nada y un estado que no avanza. Se
        detecta aqui, y el registro no admite un conector con incidencias.
        """
        issues: list[str] = []
        if not self.name:
            issues.append("nombre de conector vacio")
        if Capability.LAUNCH not in self.capabilities:
            issues.append("todo conector debe declarar LAUNCH: como minimo sabe abrir el cliente")
        for capability, method in (
            (Capability.CONNECT, "_connect"),
            (Capability.DISCONNECT, "_disconnect"),
            (Capability.STATUS, "_status"),
        ):
            if capability in self.capabilities and not self._overrides(method):
                issues.append(f"declara {capability.name} pero no implementa {method}")
        return issues

    # -- API publica -------------------------------------------------------
    #
    # El orden de las comprobaciones es siempre el mismo: primero si la
    # operacion es posible, luego si el perfil es de este conector, y por
    # ultimo si el perfil es valido. Las tres tienen que pasar antes de que
    # el proveedor vea nada.

    def launch(self, profile: Profile) -> Result:
        """Abre el cliente oficial. Lo unico que sabe hacer todo conector."""
        refusal = self._refusal(profile, Capability.LAUNCH)
        return refusal if refusal is not None else self._launch(profile)

    def connect(self, profile: Profile) -> Result:
        """Pide al cliente que conecte un perfil concreto."""
        refusal = self._refusal(profile, Capability.CONNECT)
        return refusal if refusal is not None else self._connect(profile)

    def disconnect(self, profile: Profile) -> Result:
        """Pide al cliente que desconecte."""
        refusal = self._refusal(profile, Capability.DISCONNECT)
        return refusal if refusal is not None else self._disconnect(profile)

    def status(self, profile: Profile) -> Result:
        """Lo que el cliente dice de si mismo.

        No es el estado real: eso son adaptador, ruta e IP testigo, y lo
        resuelve `net/`. Esto sirve para dar detalle al usuario, no para
        decidir si un perfil esta conectado.
        """
        refusal = self._refusal(profile, Capability.STATUS)
        return refusal if refusal is not None else self._status(profile)

    # -- Puntos de extension ----------------------------------------------

    @abstractmethod
    def _launch(self, profile: Profile) -> Result: ...

    def _connect(self, profile: Profile) -> Result:
        raise NotImplementedError

    def _disconnect(self, profile: Profile) -> Result:
        raise NotImplementedError

    def _status(self, profile: Profile) -> Result:
        raise NotImplementedError

    # -- Interno -----------------------------------------------------------

    def _overrides(self, method: str) -> bool:
        return getattr(type(self), method) is not getattr(Connector, method)

    def _refusal(self, profile: Profile, capability: Capability) -> Result | None:
        """Devuelve el motivo por el que no se hace nada, o None si se puede."""
        if capability not in self.capabilities:
            return Result.failure(
                f"el conector '{self.name}' no declara {capability.name}: "
                f"ese cliente no admite esa operacion desde aqui"
            )
        if profile.connector != self.name:
            return Result.failure(
                f"el perfil '{profile.id}' lo gobierna el conector "
                f"'{profile.connector}', no '{self.name}'"
            )
        issues = profile.validate()
        if issues:
            return Result.failure(f"perfil '{profile.id}' invalido: {'; '.join(issues)}")
        return None


class LauncherConnector(Connector):
    """El conector minimo: abre el cliente oficial y ya.

    Aqui empieza todo conector nuevo. Solo declara `LAUNCH`, asi que la
    interfaz ofrece "Abrir cliente" y el usuario termina la conexion en el
    cliente de siempre. Es honesto y no se rompe cuando el fabricante cambia
    su CLI.

    Un proveedor asciende de aqui heredando y anadiendo capacidades, y solo
    despues de comprobarlas en un puesto real y anotar la version en
    `docs/CONECTORES.md`.
    """

    capabilities = frozenset({Capability.LAUNCH})

    def __init__(self, name: str, launcher: ProcessLauncher) -> None:
        self.name = name
        self._launcher = launcher

    def _launch(self, profile: Profile) -> Result:
        outcome = self._launcher.start(profile.launch)
        if not outcome.started:
            detail = f": {outcome.detail}" if outcome.detail else ""
            return Result.failure(
                f"no se pudo abrir el cliente de '{profile.display_name}'{detail}"
            )
        return Result.success(
            state=ConnectionState.LAUNCHING,
            message=f"cliente de '{profile.display_name}' abierto; "
            f"completa la conexion en su propia ventana",
            # Puede venir vacio: una app MSIX se lanza por el shell y no
            # devuelve un pid utilizable. Quien dependa de el debe contar con
            # que no siempre esta.
            pid=outcome.pid,
        )


class ConnectorRegistry:
    """Traduce el `connector` de un perfil al objeto que lo gobierna.

    El registro se llena al arrancar el servicio, con conectores definidos en
    codigo. Nunca con datos que vengan del pipe.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        """Registra un conector. Falla fuerte: esto ocurre al arrancar.

        Un conector mal declarado es un error de programacion, no una
        incidencia de uso. Mejor que el servicio no arranque a que arranque
        con un boton que miente.
        """
        issues = connector.validate_declaration()
        if issues:
            raise ValueError(f"conector '{connector.name}' mal declarado: {'; '.join(issues)}")
        if connector.name in self._connectors:
            raise ValueError(f"ya hay un conector registrado como '{connector.name}'")
        self._connectors[connector.name] = connector

    def get(self, name: str) -> Connector | None:
        return self._connectors.get(name)

    def for_profile(self, profile: Profile) -> Connector | None:
        """El conector de un perfil, o None si el catalogo nombra uno que no existe."""
        return self._connectors.get(profile.connector)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._connectors))

    def validate_catalog(self, profiles: Iterable[Profile]) -> list[str]:
        """Comprueba que los conectores registrados pueden cumplir el catalogo.

        Un perfil describe lo que quiere; un conector, lo que puede. Nadie
        cruzaba las dos cosas: un perfil con `DisconnectStrategy.CLI` gobernado
        por un conector que no declara `DISCONNECT` pasa la validacion del
        perfil, pasa la del conector, y falla el dia que alguien pulsa
        desconectar. Se llama al cargar el catalogo, no en caliente.
        """
        issues: list[str] = []
        for profile in profiles:
            connector = self._connectors.get(profile.connector)
            if connector is None:
                issues.append(
                    f"perfil '{profile.id}': no hay ningun conector registrado como "
                    f"'{profile.connector}'"
                )
                continue
            if profile.disconnect_strategy is DisconnectStrategy.CLI and not connector.supports(
                Capability.DISCONNECT
            ):
                issues.append(
                    f"perfil '{profile.id}': pide desconexion por CLI y el conector "
                    f"'{connector.name}' no declara DISCONNECT"
                )
        return issues

    def __contains__(self, name: str) -> bool:
        return name in self._connectors

    def __len__(self) -> int:
        return len(self._connectors)
