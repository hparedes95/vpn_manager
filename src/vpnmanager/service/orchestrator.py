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

import threading
from collections.abc import Mapping
from typing import Protocol

from vpnmanager.connectors.base import ConnectorRegistry
from vpnmanager.core.arbiter import TunnelArbiter
from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    ProbeResult,
    Profile,
    Session,
    TunnelType,
)
from vpnmanager.core.protocol import (
    Command,
    ProfileSummary,
    Request,
    Response,
)
from vpnmanager.core.watchdog import NetworkSnapshot, Reversion, Watchdog


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
    Las tres, y por separado. El icono del cliente oficial no es fuente de
    verdad y por eso no aparece por ningun lado en este modulo.
    """

    def check(self, profile: Profile) -> ProbeResult: ...


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
        # El servicio atiende el pipe en un hilo y vigila el watchdog en otro,
        # y los dos tocan estas sesiones. Sin esto, un CONFIRM que llega
        # mientras se recogen las ventanas vencidas revienta con "dictionary
        # changed size during iteration", el hilo del watchdog muere, y desde
        # ese momento no se revierte nada nunca mas sin mas rastro que una
        # traza en el log.
        self._lock = threading.RLock()

    # -- Entrada -----------------------------------------------------------

    def handle(self, request: Request) -> Response:
        """Atiende una peticion ya decodificada y validada por el protocolo."""
        with self._lock:
            return self._handle(request)

    def _handle(self, request: Request) -> Response:
        if request.command is Command.LIST:
            return self._list()

        # El resto de comandos hablan de un perfil concreto. Que venga y que
        # tenga buena pinta lo garantiza `Request.decode`; que exista, no.
        profile = self._catalog.get(request.profile_id or "")
        if profile is None:
            return Response.failure("ese perfil no esta en el catalogo firmado")

        match request.command:
            case Command.LAUNCH:
                return self._launch(profile, user_confirmed=request.user_confirmed)
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
        with self._lock:
            return self._revert(self._watchdog.collect_expired())

    def shutdown(self) -> tuple[Response, ...]:
        """Deshace todo lo armado antes de irse, haya vencido o no.

        Una ventana abierta solo protege mientras alguien la vigila. Al parar
        el servicio no queda nadie, asi que dejar un tunel completo arriba es
        dejarlo sin marcha atras hasta que alguien vaya hasta el equipo.
        """
        with self._lock:
            return self._revert(
                self._watchdog.revert_all("el servicio se esta parando: se deshace la conexion")
            )

    def _revert(self, reversions_to_do: tuple[Reversion, ...]) -> tuple[Response, ...]:
        reversions = []
        for reversion in reversions_to_do:
            profile = self._catalog.get(reversion.profile_id)
            if profile is not None:
                self._force_disconnect(profile)
                self._session(reversion.profile_id).pid = None
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

    def _launch(self, profile: Profile, *, user_confirmed: bool = False) -> Response:
        """Abrir el cliente oficial, para configurarlo. No conecta nada.

        Es el camino que hace falta para dar de alta una VPN: la configuracion
        de verdad —SSO, IPSec, certificados, gateways— se hace una vez en el
        cliente del fabricante, que es el unico que la entiende. Este programa
        no la reimplementa ni la guarda; solo abre el sitio donde se hace.

        No pasa por el arbitro a proposito: abrir una ventana no ocupa la
        maquina y no desaloja a nadie. Con una excepcion, que es la que puede
        costar cara.
        """
        connector = self._registry.for_profile(profile)
        if connector is None:
            return self._orphan(profile)

        # Abrir no es conectar... salvo que el cliente este configurado para
        # conectar al abrirse, cosa que aqui no se puede saber. Si ese perfil
        # corta la conectividad local, la diferencia entre las dos cosas es la
        # sesion remota de quien lo pulse, asi que se exige la misma
        # confirmacion que para conectar. Preguntar de mas cuesta un clic.
        if profile.breaks_local_connectivity and not user_confirmed:
            return Response(
                ok=False,
                message=(
                    "este perfil corta la conectividad local. Abrir su cliente no deberia "
                    "conectar nada, pero si el cliente esta configurado para conectar al "
                    "arrancar, perderas la red. Hace falta confirmarlo"
                ),
            )

        result = connector.launch(profile)
        session = self._session(profile.id)
        session.state = self._claimed(profile, result.state)
        session.pid = result.pid
        return Response(ok=result.ok, message=result.message, state=session.state)

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
            if not self._force_disconnect(self._catalog[victim_id]):
                # Sin desalojar no se conecta: quedarian dos tuneles completos.
                return Response.failure(
                    f"no se pudo desconectar '{self._catalog[victim_id].display_name}', "
                    f"asi que no se conecta nada encima"
                )

        # La foto se toma antes de tocar nada, y el watchdog se arma antes de
        # conectar: si la conexion deja el equipo incomunicado, la reversion ya
        # esta programada.
        if plan.needs_watchdog:
            snapshot = self._network.snapshot()
            if not snapshot.usable:
                # Sin foto no hay marcha atras, y un tunel completo sin marcha
                # atras es apostarse el equipo a que no falle nada. No se
                # conecta: es preferible quedarse sin VPN a quedarse sin equipo.
                return Response.failure(
                    "no se pudo guardar el estado de red, asi que no habria forma de "
                    "deshacer la conexion: no se conecta un tunel completo a ciegas"
                )
            self._watchdog.arm(profile.id, snapshot)

        result = (
            connector.connect(profile)
            if connector.supports(Capability.CONNECT)
            else connector.launch(profile)
        )

        session = self._session(profile.id)
        session.state = self._claimed(profile, result.state)
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
            # Solo ahora se desarma. Hacerlo antes dejaria sin marcha atras a
            # un tunel que sigue arriba, que es justo el caso en el que hace
            # falta: si ha cortado el RDP, ya no hay quien lo arregle.
            self._watchdog.cancel(profile.id)
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

    def _claimed(self, profile: Profile, state: ConnectionState) -> ConnectionState:
        """El estado que se apunta cuando quien lo afirma es el cliente oficial.

        Un conector puede devolver CONNECTED porque su cliente lo dice, y eso
        no basta: un FortiClient puede estar en verde con el tunel caido. Si el
        perfil no tiene con que comprobarlo, la afirmacion se degrada a
        UNVERIFIED en vez de propagarse como si fuera un hecho.

        Los APP son la excepcion, y no por comodidad: un reenvio TCP por
        aplicacion no monta adaptador ni pone rutas, asi que no hay sonda
        posible y el conector es la unica fuente que existe.
        """
        if state is not ConnectionState.CONNECTED:
            return state
        if profile.can_verify_state or profile.tunnel_type is TunnelType.APP:
            return state
        return ConnectionState.UNVERIFIED

    def _refresh(self, profile: Profile) -> ConnectionState:
        """El estado real, no el que dijo el cliente la ultima vez.

        Solo se sondea lo que dice estar en marcha: sondear un perfil parado
        seria gastar una comprobacion de red para confirmar lo que ya se sabe.
        """
        session = self._session(profile.id)
        if session.state in (ConnectionState.DISCONNECTED, ConnectionState.ERROR):
            return session.state

        # Sin IP testigo no hay nada que sondear. Se dice, en vez de dejarlo
        # eternamente en "lanzando": ese estado promete que la cosa avanza, y
        # aqui no va a avanzar nunca porque no hay con que mirarlo.
        #
        # Los APP quedan fuera: un reenvio TCP por aplicacion no monta
        # adaptador ni pone rutas, asi que no le falta el dato, es que no
        # aplica.
        if not profile.can_verify_state and profile.tunnel_type is not TunnelType.APP:
            session.state = ConnectionState.UNVERIFIED
            return session.state

        probed = self._probe.check(profile)
        if session.state in (ConnectionState.LAUNCHING, ConnectionState.WAITING_AUTH):
            # Todavia esta en ello. Solo se avanza si responde del todo: un
            # tunel a medio montar sigue estando a medio montar.
            if probed.connected:
                session.state = ConnectionState.CONNECTED
            return session.state

        session.state = probed.state(previous=session.state)
        return session.state

    def _force_disconnect(self, profile: Profile) -> bool:
        """Desconecta sin responder a nadie. Dice si de verdad lo consiguio.

        Devolver siempre exito seria peor que no intentarlo: el desalojo
        seguiria adelante y quedarian dos tuneles completos a la vez, con el
        servicio informando de que uno esta desconectado.
        """
        connector = self._registry.for_profile(profile)
        if connector is None or not connector.supports(Capability.DISCONNECT):
            return False

        result = connector.disconnect(profile)
        if not result.ok:
            self._session(profile.id).state = result.state
            return False

        self._watchdog.cancel(profile.id)
        session = self._session(profile.id)
        session.state = ConnectionState.DISCONNECTED
        session.pid = None
        return True

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
