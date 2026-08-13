"""El que decide que pasa cuando llega una peticion.

Aqui se juntan las piezas: el arbitro dice que estorba, el registro dice quien
gobierna cada perfil, el watchdog vigila que la conexion se confirme y el
protocolo pone las palabras. Este modulo es el unico que las conoce a todas, y
por eso es el unico de `service/` que puede importar de varias capas.

Sigue sin tocar Windows. Lo que hace falta de la maquina —leer y restaurar la
red, y comprobar si un tunel esta vivo de verdad— entra por dos puertos que
implementara `net/`. Asi el flujo entero, incluido lo que pasa cuando la
interfaz no confirma a tiempo, se prueba en CI sin un cliente VPN delante.

Dos ideas que conviene tener claras porque se confunden con facilidad:

**El watchdog vigila que se pueda llegar al equipo; la sonda, que el tunel
sirva.** Son cosas distintas. Que la interfaz confirme demuestra que la
maquina sigue alcanzable, y eso desarma el watchdog aunque el tunel no
responda. Un tunel que no pasa la sonda queda `DOWN`, que es un problema del
usuario, no una emergencia.

`ConnectionState.DEGRADED` no se usa todavia: haria falta que la sonda
distinguiera entre "el adaptador y la ruta estan pero la IP testigo no
responde" y "no hay nada", y hoy devuelve un booleano. Cuando `net/` exista
con las tres comprobaciones por separado, ese estado tendra sentido.

**Confirmar no es aceptar.** `user_confirmed` en la peticion es el usuario
diciendo "se que voy a perder la red local" antes de conectar (HU-03).
`Command.CONFIRM` es la interfaz diciendo "sigo viva" despues. La primera
autoriza; la segunda desarma.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from vpnmanager.connectors.base import ConnectorRegistry
from vpnmanager.core.arbiter import TunnelArbiter
from vpnmanager.core.models import Capability, ConnectionState, Profile, Session
from vpnmanager.core.protocol import (
    Command,
    ProfileSummary,
    Request,
    Response,
)
from vpnmanager.core.watchdog import NetworkSnapshot, Watchdog


class NetworkController(Protocol):
    """Puerto: quien sabe fotografiar la red y devolverla a como estaba.

    Lo implementa `net/` con los `.ps1`. Aqui solo se le pide la foto antes de
    tocar nada y se le devuelve cuando hay que deshacer.
    """

    def snapshot(self) -> NetworkSnapshot: ...

    def restore(self, snapshot: NetworkSnapshot) -> bool: ...


class ConnectionProbe(Protocol):
    """Puerto: quien sabe si un perfil esta conectado **de verdad**.

    Adaptador activo, ruta hacia la red destino y respuesta de la IP testigo.
    Las tres. El icono del cliente oficial no es fuente de verdad y por eso no
    aparece por ningun lado en este modulo.
    """

    def is_really_connected(self, profile: Profile) -> bool: ...


class Orchestrator:
    """Traduce peticiones en acciones sobre el estado real de la maquina."""

    def __init__(
        self,
        catalog: Mapping[str, Profile],
        registry: ConnectorRegistry,
        network: NetworkController,
        probe: ConnectionProbe,
        watchdog: Watchdog | None = None,
    ) -> None:
        self._catalog = dict(catalog)
        self._registry = registry
        self._network = network
        self._probe = probe
        self._watchdog = Watchdog() if watchdog is None else watchdog
        self._arbiter = TunnelArbiter(self._catalog)
        self._sessions: dict[str, Session] = {}

    # -- Entrada -----------------------------------------------------------

    def handle(self, request: Request) -> Response:
        """Atiende una peticion ya decodificada y validada por el protocolo."""
        if request.command is Command.LIST:
            return self._list()

        # El resto de comandos hablan de un perfil concreto. Que venga y que
        # tenga buena pinta lo garantiza `Request.decode`; que exista, no.
        profile = self._catalog.get(request.profile_id or "")
        if profile is None:
            return Response.failure("ese perfil no esta en el catalogo firmado")

        match request.command:
            case Command.LAUNCH:
                return self._launch(profile)
            case Command.CONNECT:
                return self._connect(profile, user_confirmed=request.user_confirmed)
            case Command.DISCONNECT:
                return self._disconnect(profile)
            case Command.STATUS:
                return self._status(profile)
            case Command.CONFIRM:
                return self._confirm(profile)
            case Command.LIST:  # pragma: no cover - resuelto arriba
                return self._list()

    def tick(self) -> tuple[Response, ...]:
        """Lo que hay que hacer sin que nadie lo pida: revertir lo no confirmado.

        El servicio la llama en su propio ciclo. Devuelve una respuesta por
        reversion para que quede registrada; nadie la esta esperando al otro
        lado del pipe, porque justo el problema es que puede que ya no haya
        nadie al otro lado.
        """
        reversions = []
        for reversion in self._watchdog.collect_expired():
            profile = self._catalog.get(reversion.profile_id)
            if profile is not None:
                self._force_disconnect(profile)
            restored = self._network.restore(reversion.snapshot)
            self._session(reversion.profile_id).state = ConnectionState.DISCONNECTED
            reversions.append(
                Response(
                    ok=restored,
                    message=(
                        reversion.reason
                        if restored
                        else f"{reversion.reason}. La red NO se pudo restaurar del todo"
                    ),
                    state=ConnectionState.DISCONNECTED,
                )
            )
        return tuple(reversions)

    # -- Comandos ----------------------------------------------------------

    def _list(self) -> Response:
        return Response(
            ok=True,
            profiles=tuple(self._summary(profile) for profile in self._catalog.values()),
        )

    def _launch(self, profile: Profile) -> Response:
        """Abrir el cliente oficial. No conecta nada, y no lo finge."""
        connector = self._registry.for_profile(profile)
        if connector is None:
            return self._orphan(profile)

        result = connector.launch(profile)
        session = self._session(profile.id)
        session.state = result.state
        session.pid = result.pid
        return Response(ok=result.ok, message=result.message, state=result.state)

    def _connect(self, profile: Profile, *, user_confirmed: bool) -> Response:
        plan = self._arbiter.plan_connection(profile.id, self._sessions.values())
        if not plan.allowed:
            return Response(
                ok=False,
                message=plan.refusal,
                manual_disconnect_first=plan.manual_disconnect_first,
            )

        if plan.needs_confirmation and not user_confirmed:
            # El servicio no se fia de que la interfaz haya preguntado: quien
            # pulsa suele estar dentro de la sesion RDP que se va a cortar.
            return Response(ok=False, message=plan.confirmation_reason)

        connector = self._registry.for_profile(profile)
        if connector is None:
            return self._orphan(profile)

        for victim_id in plan.disconnect_first:
            self._force_disconnect(self._catalog[victim_id])

        # La foto se toma antes de tocar nada, y el watchdog se arma antes de
        # conectar: si la conexion deja el equipo incomunicado, la reversion ya
        # esta programada.
        if plan.needs_watchdog:
            self._watchdog.arm(profile.id, self._network.snapshot())

        result = (
            connector.connect(profile)
            if connector.supports(Capability.CONNECT)
            else connector.launch(profile)
        )

        session = self._session(profile.id)
        session.state = result.state
        session.pid = result.pid
        if not result.ok:
            # No se deja armado algo que no llego a conectarse: la reversion
            # caeria sobre una red que nadie ha tocado.
            self._watchdog.cancel(profile.id)

        return Response(
            ok=result.ok,
            message=result.message,
            state=result.state,
            warnings=plan.warnings,
        )

    def _disconnect(self, profile: Profile) -> Response:
        connector = self._registry.for_profile(profile)
        if connector is None:
            return self._orphan(profile)

        self._watchdog.cancel(profile.id)
        if not connector.supports(Capability.DISCONNECT):
            # No se marca como desconectado lo que sigue conectado: el estado
            # tiene que seguir siendo el real, aunque sea incomodo.
            return Response(
                ok=False,
                message=(
                    f"'{profile.display_name}' hay que desconectarlo desde su propio "
                    f"cliente: este no admite que se le pida"
                ),
                state=self._session(profile.id).state,
                manual_disconnect_first=(profile.id,),
            )

        result = connector.disconnect(profile)
        session = self._session(profile.id)
        session.state = ConnectionState.DISCONNECTED if result.ok else result.state
        if result.ok:
            session.pid = None
        return Response(ok=result.ok, message=result.message, state=session.state)

    def _status(self, profile: Profile) -> Response:
        state = self._refresh(profile)
        return Response(ok=True, state=state, message=self._session(profile.id).message)

    def _confirm(self, profile: Profile) -> Response:
        """La interfaz sigue viva, luego al equipo se puede llegar."""
        disarmed = self._watchdog.confirm(profile.id)
        state = self._refresh(profile)
        if not disarmed:
            return Response(
                ok=False,
                message=(
                    "no habia ninguna ventana de confirmacion abierta para este perfil, "
                    "o ya habia vencido"
                ),
                state=state,
            )
        return Response(ok=True, state=state)

    # -- Interno -----------------------------------------------------------

    def _refresh(self, profile: Profile) -> ConnectionState:
        """El estado real, no el que dijo el cliente la ultima vez.

        Solo se sondea lo que dice estar en marcha: sondear un perfil parado
        seria gastar una comprobacion de red para confirmar lo que ya se sabe.
        """
        session = self._session(profile.id)
        if session.state in (ConnectionState.DISCONNECTED, ConnectionState.ERROR):
            return session.state
        if session.state in (ConnectionState.LAUNCHING, ConnectionState.WAITING_AUTH):
            # Todavia esta en ello: si ya responde, es que ha terminado.
            if self._probe.is_really_connected(profile):
                session.state = ConnectionState.CONNECTED
            return session.state

        session.state = (
            ConnectionState.CONNECTED
            if self._probe.is_really_connected(profile)
            else ConnectionState.DOWN
        )
        return session.state

    def _force_disconnect(self, profile: Profile) -> None:
        """Desconecta sin responder a nadie. Para desalojos y reversiones."""
        connector = self._registry.for_profile(profile)
        if connector is not None and connector.supports(Capability.DISCONNECT):
            connector.disconnect(profile)
        self._watchdog.cancel(profile.id)
        session = self._session(profile.id)
        session.state = ConnectionState.DISCONNECTED
        session.pid = None

    def _orphan(self, profile: Profile) -> Response:
        return Response(
            ok=False,
            message=(
                f"el catalogo dice que '{profile.id}' lo gobierna el conector "
                f"'{profile.connector}', y no hay ninguno registrado con ese nombre"
            ),
        )

    def _session(self, profile_id: str) -> Session:
        session = self._sessions.get(profile_id)
        if session is None:
            session = Session(profile_id=profile_id)
            self._sessions[profile_id] = session
        return session

    def _summary(self, profile: Profile) -> ProfileSummary:
        connector = self._registry.for_profile(profile)
        # Sin conector registrado no hay capacidades, asi que la interfaz lo
        # pinta sin botones en vez de ofrecer algo que fallaria al pulsarlo.
        capabilities = () if connector is None else tuple(sorted(connector.capabilities, key=str))
        return ProfileSummary(
            id=profile.id,
            display_name=profile.display_name,
            tunnel_type=profile.tunnel_type,
            state=self._session(profile.id).state,
            capabilities=capabilities,
            needs_confirmation=profile.breaks_local_connectivity,
        )
