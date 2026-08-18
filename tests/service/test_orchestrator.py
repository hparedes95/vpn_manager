"""Tests del orquestador: el flujo entero, sin Windows.

Aqui es donde se ve si las piezas encajan. Los conectores no arrancan nada, la
red es de mentira y el reloj se mueve a mano, pero el recorrido es el de
verdad: llega una peticion, el arbitro decide, el watchdog se arma, y si nadie
confirma, la conexion se deshace sola.
"""

from __future__ import annotations

import pytest

from vpnmanager.connectors.base import (
    Connector,
    ConnectorRegistry,
    LauncherConnector,
    LaunchOutcome,
)
from vpnmanager.core.arbiter import is_occupying
from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    DisconnectStrategy,
    LaunchKind,
    LaunchSpec,
    ProbeResult,
    Profile,
    Result,
    Session,
    TunnelType,
)
from vpnmanager.core.protocol import Command, Request
from vpnmanager.core.watchdog import NetworkSnapshot, Watchdog
from vpnmanager.service.orchestrator import Orchestrator

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
SNAPSHOT = NetworkSnapshot(
    routes=("0.0.0.0/0 via 192.168.1.1",),
    dns=("192.168.1.1",),
    # Sin payload la foto no sirve para restaurar, y el orquestador se
    # niega a conectar un tunel completo sin marcha atras.
    payload='{"ok":true,"routes":[],"dns":[]}',
)


# --------------------------------------------------------------------------
# Dobles
# --------------------------------------------------------------------------


class FakeLauncher:
    def __init__(self) -> None:
        self.calls: list[LaunchSpec] = []

    def start(self, spec: LaunchSpec) -> LaunchOutcome:
        self.calls.append(spec)
        return LaunchOutcome(started=True, pid=4242)


class FullConnector(LauncherConnector):
    """Un conector verificado: sabe conectar y desconectar."""

    capabilities = frozenset({Capability.LAUNCH, Capability.CONNECT, Capability.DISCONNECT})

    def __init__(self, name: str, launcher: FakeLauncher) -> None:
        super().__init__(name=name, launcher=launcher)
        self.connected: list[str] = []
        self.disconnected: list[str] = []
        self.connect_fails = False

    def _connect(self, profile: Profile) -> Result:
        self.connected.append(profile.id)
        if self.connect_fails:
            return Result.failure("el cliente rechazo la orden")
        return Result.success(ConnectionState.CONNECTED, "conectado", pid=4242)

    def _disconnect(self, profile: Profile) -> Result:
        self.disconnected.append(profile.id)
        return Result.success(ConnectionState.DISCONNECTED, "desconectado")


class FakeNetwork:
    def __init__(self) -> None:
        self.snapshots = 0
        self.restored: list[NetworkSnapshot] = []
        self.restore_works = True
        self.snapshot_works = True

    def snapshot(self) -> NetworkSnapshot:
        self.snapshots += 1
        return SNAPSHOT if self.snapshot_works else NetworkSnapshot()

    def restore(self, snapshot: NetworkSnapshot) -> bool:
        self.restored.append(snapshot)
        return self.restore_works


class FakeProbe:
    """La sonda de red. Por defecto dice que las tres comprobaciones pasan."""

    def __init__(self, connected: bool = True) -> None:
        self.result = ProbeResult(adapter_up=connected, routed=connected, probe_answers=connected)
        self.calls: list[str] = []

    def check(self, profile: Profile) -> ProbeResult:
        self.calls.append(profile.id)
        return self.result

    @property
    def connected(self) -> bool:
        return self.result.connected

    @connected.setter
    def connected(self, value: bool) -> None:
        self.result = ProbeResult(adapter_up=value, routed=value, probe_answers=value)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --------------------------------------------------------------------------
# Catalogo
# --------------------------------------------------------------------------


def make_profile(
    profile_id: str,
    tunnel_type: TunnelType = TunnelType.FULL,
    *,
    connector: str = "wireguard",
    breaks_local_connectivity: bool = False,
    disconnect_strategy: DisconnectStrategy = DisconnectStrategy.CLI,
    probe_ip: str | None = "10.20.0.1",
) -> Profile:
    return Profile(
        id=profile_id,
        display_name=f"Perfil {profile_id}",
        connector=connector,
        launch=LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE),
        tunnel_type=tunnel_type,
        probe_ip=None if tunnel_type is TunnelType.APP else probe_ip,
        breaks_local_connectivity=breaks_local_connectivity,
        disconnect_strategy=disconnect_strategy,
    )


FULL_A = make_profile("full-a")
FULL_B = make_profile("full-b")
FULL_RDP = make_profile("full-rdp", breaks_local_connectivity=True)
SPLIT_A = make_profile("split-a", TunnelType.SPLIT)
ONLY_LAUNCH = make_profile("solo-abrir", connector="forcepoint")
ORPHAN = make_profile("huerfano", connector="nadie")
# Recien dado de alta: se sabe que cliente lo abre y nada mas. Es el caso que
# permite anadir una VPN sin haberla conectado nunca.
NO_WITNESS = make_profile("sin-testigo", TunnelType.SPLIT, probe_ip=None)

CATALOG = {p.id: p for p in (FULL_A, FULL_B, FULL_RDP, SPLIT_A, ONLY_LAUNCH, ORPHAN, NO_WITNESS)}


@pytest.fixture
def launcher() -> FakeLauncher:
    return FakeLauncher()


@pytest.fixture
def wireguard(launcher: FakeLauncher) -> FullConnector:
    return FullConnector(name="wireguard", launcher=launcher)


@pytest.fixture
def registry(wireguard: FullConnector, launcher: FakeLauncher) -> ConnectorRegistry:
    registry = ConnectorRegistry()
    registry.register(wireguard)
    # Forcepoint sin verificar: solo sabe abrir el cliente.
    registry.register(LauncherConnector(name="forcepoint", launcher=launcher))
    return registry


@pytest.fixture
def network() -> FakeNetwork:
    return FakeNetwork()


@pytest.fixture
def probe() -> FakeProbe:
    return FakeProbe()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def orchestrator(
    registry: ConnectorRegistry,
    network: FakeNetwork,
    probe: FakeProbe,
    clock: FakeClock,
) -> Orchestrator:
    return Orchestrator(
        catalog=CATALOG,
        registry=registry,
        network=network,
        probe=probe,
        watchdog=Watchdog(window_seconds=90.0, clock=clock),
    )


def connect(profile_id: str, *, confirmed: bool = False) -> Request:
    return Request(command=Command.CONNECT, profile_id=profile_id, user_confirmed=confirmed)


# --------------------------------------------------------------------------
# LIST
# --------------------------------------------------------------------------


def test_list_returns_every_profile_with_its_state(orchestrator: Orchestrator) -> None:
    response = orchestrator.handle(Request(command=Command.LIST))

    assert response.ok
    assert len(response.profiles) == len(CATALOG)
    assert all(p.state is ConnectionState.DISCONNECTED for p in response.profiles)


def test_list_reports_the_capabilities_the_interface_needs(orchestrator: Orchestrator) -> None:
    """Sin CONNECT el boton dice "Abrir cliente": la interfaz lo sabe por aqui."""
    summaries = {p.id: p for p in orchestrator.handle(Request(command=Command.LIST)).profiles}

    assert Capability.CONNECT in summaries["full-a"].capabilities
    assert Capability.CONNECT not in summaries["solo-abrir"].capabilities


def test_a_profile_without_a_connector_offers_nothing(orchestrator: Orchestrator) -> None:
    """Mejor sin botones que con un boton que fallaria al pulsarlo."""
    summaries = {p.id: p for p in orchestrator.handle(Request(command=Command.LIST)).profiles}

    assert summaries["huerfano"].capabilities == ()


def test_list_marks_what_will_ask_for_confirmation(orchestrator: Orchestrator) -> None:
    summaries = {p.id: p for p in orchestrator.handle(Request(command=Command.LIST)).profiles}

    assert summaries["full-rdp"].needs_confirmation is True
    assert summaries["full-a"].needs_confirmation is False


# --------------------------------------------------------------------------
# Conectar
# --------------------------------------------------------------------------


def test_connecting_a_full_arms_the_watchdog_before_connecting(
    orchestrator: Orchestrator, network: FakeNetwork
) -> None:
    """La foto se toma antes de tocar nada: es lo que se restaura si falla."""
    response = orchestrator.handle(connect("full-a"))

    assert response.ok
    assert network.snapshots == 1


def test_connecting_a_split_does_not_arm_the_watchdog(
    orchestrator: Orchestrator, network: FakeNetwork
) -> None:
    orchestrator.handle(connect("split-a"))

    assert network.snapshots == 0


def test_a_second_full_evicts_the_first(
    orchestrator: Orchestrator, wireguard: FullConnector
) -> None:
    orchestrator.handle(connect("full-a"))

    response = orchestrator.handle(connect("full-b"))

    assert response.ok
    assert wireguard.disconnected == ["full-a"]


def test_the_evicted_one_ends_up_disconnected(orchestrator: Orchestrator) -> None:
    orchestrator.handle(connect("full-a"))
    orchestrator.handle(connect("full-b"))

    summaries = {p.id: p for p in orchestrator.handle(Request(command=Command.LIST)).profiles}

    assert summaries["full-a"].state is ConnectionState.DISCONNECTED


def test_a_profile_that_breaks_the_network_is_not_connected_without_confirmation(
    orchestrator: Orchestrator, wireguard: FullConnector, network: FakeNetwork
) -> None:
    """El servicio no se fia de que la interfaz haya preguntado (HU-03)."""
    response = orchestrator.handle(connect("full-rdp"))

    assert not response.ok
    assert "escritorio remoto" in response.message
    assert wireguard.connected == []
    assert network.snapshots == 0


def test_with_confirmation_it_does_connect(
    orchestrator: Orchestrator, wireguard: FullConnector
) -> None:
    response = orchestrator.handle(connect("full-rdp", confirmed=True))

    assert response.ok
    assert wireguard.connected == ["full-rdp"]


def test_a_connector_without_connect_only_opens_the_client(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    """No se finge una conexion que nadie ha pedido al cliente."""
    response = orchestrator.handle(connect("solo-abrir"))

    assert response.ok
    assert response.state is ConnectionState.LAUNCHING
    assert launcher.calls == [ONLY_LAUNCH.launch]


def test_a_failed_connection_disarms_the_watchdog(
    orchestrator: Orchestrator, wireguard: FullConnector, network: FakeNetwork, clock: FakeClock
) -> None:
    """No se deja armado algo que no llego a conectarse."""
    wireguard.connect_fails = True

    response = orchestrator.handle(connect("full-a"))
    assert not response.ok

    clock.advance(120.0)
    assert orchestrator.tick() == ()
    assert network.restored == []


def test_a_full_is_not_connected_when_the_network_cannot_be_photographed(
    orchestrator: Orchestrator, network: FakeNetwork, wireguard: FullConnector
) -> None:
    """Sin foto no hay marcha atras, y sin marcha atras no se apuesta el equipo."""
    network.snapshot_works = False

    response = orchestrator.handle(connect("full-a"))

    assert not response.ok
    assert "deshacer la conexion" in response.message
    assert wireguard.connected == []


def test_a_split_connects_even_without_a_photograph(
    orchestrator: Orchestrator, network: FakeNetwork
) -> None:
    """Un SPLIT no arma watchdog porque no puede dejar el equipo incomunicado."""
    network.snapshot_works = False

    assert orchestrator.handle(connect("split-a")).ok


def test_a_tunnel_that_is_up_but_does_not_answer_is_degraded(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """La ruta esta y el adaptador tambien, pero por ahi no pasa trafico."""
    orchestrator.handle(connect("full-a"))
    probe.result = ProbeResult(adapter_up=True, routed=True, probe_answers=False)

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="full-a"))

    assert response.state is ConnectionState.DEGRADED


def test_a_probe_that_could_not_run_does_not_change_the_state(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """No saber no es lo mismo que saber que no: un fallo de la sonda no
    puede verse como un tunel roto y disparar desconexiones que nadie pidio."""
    orchestrator.handle(connect("full-a"))
    probe.result = ProbeResult(checked=False)

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="full-a"))

    assert response.state is ConnectionState.CONNECTED


def test_a_profile_governed_by_nobody_cannot_be_connected(orchestrator: Orchestrator) -> None:
    response = orchestrator.handle(connect("huerfano"))

    assert not response.ok
    assert "nadie" in response.message


def test_a_profile_outside_the_catalog_is_refused(orchestrator: Orchestrator) -> None:
    response = orchestrator.handle(connect("el-que-me-invente"))

    assert not response.ok
    assert "catalogo firmado" in response.message


def test_the_arbiter_warnings_reach_the_interface(orchestrator: Orchestrator) -> None:
    orchestrator.handle(connect("full-a"))

    response = orchestrator.handle(connect("split-a"))

    assert response.ok
    assert len(response.warnings) == 1
    assert "no encaminan nada" in response.warnings[0]


def test_an_undisconnectable_tunnel_blocks_and_says_which_one(
    registry: ConnectorRegistry, network: FakeNetwork, probe: FakeProbe
) -> None:
    """El caso del cliente con SSO: el plan se rechaza y se dice que cerrar."""
    stubborn = make_profile("full-sso", disconnect_strategy=DisconnectStrategy.NONE)
    catalog = {**CATALOG, stubborn.id: stubborn}
    orchestrator = Orchestrator(catalog, registry, network, probe)
    orchestrator.handle(connect("full-sso"))

    response = orchestrator.handle(connect("full-a"))

    assert not response.ok
    assert response.manual_disconnect_first == ("full-sso",)


# --------------------------------------------------------------------------
# Desconectar
# --------------------------------------------------------------------------


def test_disconnecting_asks_the_connector(
    orchestrator: Orchestrator, wireguard: FullConnector
) -> None:
    orchestrator.handle(connect("full-a"))

    response = orchestrator.handle(Request(command=Command.DISCONNECT, profile_id="full-a"))

    assert response.ok
    assert response.state is ConnectionState.DISCONNECTED
    assert wireguard.disconnected == ["full-a"]


def test_a_client_that_cannot_be_told_to_disconnect_says_so(orchestrator: Orchestrator) -> None:
    """Y no se marca como desconectado lo que sigue conectado."""
    orchestrator.handle(connect("solo-abrir"))

    response = orchestrator.handle(Request(command=Command.DISCONNECT, profile_id="solo-abrir"))

    assert not response.ok
    assert response.manual_disconnect_first == ("solo-abrir",)
    assert response.state is not ConnectionState.DISCONNECTED


def test_disconnecting_disarms_the_watchdog(
    orchestrator: Orchestrator, network: FakeNetwork, clock: FakeClock
) -> None:
    orchestrator.handle(connect("full-a"))
    orchestrator.handle(Request(command=Command.DISCONNECT, profile_id="full-a"))

    clock.advance(120.0)

    assert orchestrator.tick() == ()
    assert network.restored == []


# --------------------------------------------------------------------------
# Estado real
# --------------------------------------------------------------------------


def test_status_asks_the_probe_and_not_the_client(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    orchestrator.handle(connect("full-a"))

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="full-a"))

    assert response.state is ConnectionState.CONNECTED
    assert probe.calls == ["full-a"]


def test_a_tunnel_that_stops_answering_is_down_even_if_it_said_connected(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """El icono del cliente oficial no es fuente de verdad."""
    orchestrator.handle(connect("full-a"))
    probe.connected = False

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="full-a"))

    assert response.state is ConnectionState.DOWN


def test_something_disconnected_is_not_probed(orchestrator: Orchestrator, probe: FakeProbe) -> None:
    """Gastar una comprobacion de red para confirmar lo que ya se sabe, no."""
    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="full-a"))

    assert response.state is ConnectionState.DISCONNECTED
    assert probe.calls == []


def test_a_client_being_opened_becomes_connected_when_it_answers(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """Un conector que solo abre no sabe cuando conecto: lo dice la sonda."""
    orchestrator.handle(connect("solo-abrir"))

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="solo-abrir"))

    assert response.state is ConnectionState.CONNECTED


def test_a_client_being_opened_that_does_not_answer_yet_stays_launching(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    orchestrator.handle(connect("solo-abrir"))
    probe.connected = False

    response = orchestrator.handle(Request(command=Command.STATUS, profile_id="solo-abrir"))

    assert response.state is ConnectionState.LAUNCHING


# --------------------------------------------------------------------------
# Confirmar y revertir: el recorrido que justifica todo lo demas
# --------------------------------------------------------------------------


def test_confirming_disarms_the_watchdog(
    orchestrator: Orchestrator, network: FakeNetwork, clock: FakeClock
) -> None:
    orchestrator.handle(connect("full-rdp", confirmed=True))
    clock.advance(30.0)

    response = orchestrator.handle(Request(command=Command.CONFIRM, profile_id="full-rdp"))
    assert response.ok

    clock.advance(120.0)
    assert orchestrator.tick() == ()
    assert network.restored == []


def test_confirming_disarms_even_if_the_tunnel_is_not_healthy(
    orchestrator: Orchestrator, probe: FakeProbe, network: FakeNetwork, clock: FakeClock
) -> None:
    """El watchdog vigila que se pueda llegar al equipo, no que el tunel sirva.

    Si la interfaz confirma, la maquina es alcanzable. Que el tunel vaya mal es
    un problema del usuario, no una emergencia.
    """
    orchestrator.handle(connect("full-rdp", confirmed=True))
    probe.connected = False

    response = orchestrator.handle(Request(command=Command.CONFIRM, profile_id="full-rdp"))

    assert response.ok
    assert response.state is ConnectionState.DOWN

    clock.advance(120.0)
    assert orchestrator.tick() == ()


def test_nobody_confirms_and_the_connection_is_undone(
    orchestrator: Orchestrator,
    wireguard: FullConnector,
    network: FakeNetwork,
    clock: FakeClock,
) -> None:
    """El recorrido entero: sin esto, hay que ir andando hasta el equipo."""
    orchestrator.handle(connect("full-rdp", confirmed=True))

    clock.advance(91.0)
    reversions = orchestrator.tick()

    assert len(reversions) == 1
    assert reversions[0].ok
    assert wireguard.disconnected == ["full-rdp"]
    assert network.restored == [SNAPSHOT]
    assert reversions[0].state is ConnectionState.DISCONNECTED


def test_a_reversion_that_cannot_restore_the_network_says_it_loudly(
    orchestrator: Orchestrator, network: FakeNetwork, clock: FakeClock
) -> None:
    """Es el peor caso posible: hay que poder verlo en el log."""
    network.restore_works = False
    orchestrator.handle(connect("full-rdp", confirmed=True))

    clock.advance(91.0)
    reversions = orchestrator.tick()

    assert not reversions[0].ok
    assert "NO se pudo restaurar" in reversions[0].message


def test_a_reversion_happens_only_once(orchestrator: Orchestrator, clock: FakeClock) -> None:
    orchestrator.handle(connect("full-rdp", confirmed=True))
    clock.advance(91.0)

    assert len(orchestrator.tick()) == 1
    assert orchestrator.tick() == ()


def test_confirming_after_the_window_does_not_stop_the_reversion(
    orchestrator: Orchestrator, network: FakeNetwork, clock: FakeClock
) -> None:
    orchestrator.handle(connect("full-rdp", confirmed=True))
    clock.advance(91.0)

    response = orchestrator.handle(Request(command=Command.CONFIRM, profile_id="full-rdp"))

    assert not response.ok
    assert len(orchestrator.tick()) == 1
    assert network.restored == [SNAPSHOT]


def test_confirming_something_that_was_never_armed(orchestrator: Orchestrator) -> None:
    response = orchestrator.handle(Request(command=Command.CONFIRM, profile_id="split-a"))

    assert not response.ok
    assert "ventana de confirmacion" in response.message


def test_nothing_to_revert_when_nothing_is_armed(orchestrator: Orchestrator) -> None:
    assert orchestrator.tick() == ()


# --------------------------------------------------------------------------
# Abrir el cliente
# --------------------------------------------------------------------------


def test_launch_opens_the_official_client(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    response = orchestrator.handle(Request(command=Command.LAUNCH, profile_id="full-a"))

    assert response.ok
    assert response.state is ConnectionState.LAUNCHING
    assert launcher.calls == [FULL_A.launch]


def test_launch_does_not_arm_the_watchdog(orchestrator: Orchestrator, network: FakeNetwork) -> None:
    """Abrir un cliente no toca la red, asi que no hay nada que revertir."""
    orchestrator.handle(Request(command=Command.LAUNCH, profile_id="full-rdp"))

    assert network.snapshots == 0


def test_every_command_is_handled(orchestrator: Orchestrator) -> None:
    """Si se añade un comando al protocolo, este test lo caza sin excusas."""
    for command in Command:
        request = (
            Request(command=command)
            if command is Command.LIST
            else Request(command=command, profile_id="full-a")
        )

        assert isinstance(orchestrator.handle(request), type(orchestrator.handle(request)))


def test_the_orchestrator_does_not_hold_the_caller_catalog(
    registry: ConnectorRegistry, network: FakeNetwork, probe: FakeProbe
) -> None:
    catalog = dict(CATALOG)
    orchestrator = Orchestrator(catalog, registry, network, probe)

    catalog.clear()

    assert orchestrator.handle(connect("full-a")).ok


def test_an_unregistered_connector_is_reported_for_every_command(
    orchestrator: Orchestrator,
) -> None:
    for command in (Command.LAUNCH, Command.CONNECT, Command.DISCONNECT):
        response = orchestrator.handle(Request(command=command, profile_id="huerfano"))

        assert not response.ok
        assert "no hay ninguno registrado" in response.message


def test_the_connector_interface_is_the_only_way_in(orchestrator: Orchestrator) -> None:
    """El orquestador no habla con procesos: habla con conectores."""
    assert issubclass(FullConnector, Connector)


# --------------------------------------------------------------------------
# Fallos encontrados en la revision: que no vuelvan
# --------------------------------------------------------------------------


class StubbornConnector(FullConnector):
    """Acepta la orden de desconectar y no la cumple. Pasa de verdad."""

    def _disconnect(self, profile: Profile) -> Result:
        self.disconnected.append(profile.id)
        return Result.failure("el cliente no solto el tunel")


def test_a_failed_eviction_does_not_let_a_second_full_connect(
    launcher: FakeLauncher, network: FakeNetwork, probe: FakeProbe
) -> None:
    """Dos tuneles completos a la vez es justo lo que el arbitro existe para impedir."""
    stubborn = StubbornConnector(name="wireguard", launcher=launcher)
    registry = ConnectorRegistry()
    registry.register(stubborn)
    orchestrator = Orchestrator(CATALOG, registry, network, probe)
    orchestrator.handle(connect("full-a"))

    response = orchestrator.handle(connect("full-b"))

    assert not response.ok
    assert "no se pudo desconectar" in response.message
    assert stubborn.connected == ["full-a"]


def test_disconnecting_a_client_that_cannot_be_told_keeps_the_watchdog(
    orchestrator: Orchestrator, network: FakeNetwork, clock: FakeClock
) -> None:
    """Desarmar un tunel que sigue arriba deja el equipo sin marcha atras.

    `solo-abrir` lo gobierna un conector sin DISCONNECT, asi que pedir la
    desconexion no la consigue: el tunel sigue montado y la ventana tiene que
    seguir armada.
    """
    orchestrator.handle(connect("solo-abrir"))
    response = orchestrator.handle(Request(command=Command.DISCONNECT, profile_id="solo-abrir"))
    assert not response.ok

    clock.advance(120.0)

    assert len(orchestrator.tick()) == 1
    assert network.restored == [SNAPSHOT]


def test_stopping_the_service_undoes_what_is_still_armed(
    orchestrator: Orchestrator, network: FakeNetwork, wireguard: FullConnector
) -> None:
    """Al parar no queda nadie vigilando: la ventana ya no protege de nada."""
    orchestrator.handle(connect("full-rdp", confirmed=True))

    reversions = orchestrator.shutdown()

    assert len(reversions) == 1
    assert "parando" in reversions[0].message
    assert network.restored == [SNAPSHOT]
    assert wireguard.disconnected == ["full-rdp"]


def test_stopping_with_nothing_armed_does_nothing(orchestrator: Orchestrator) -> None:
    assert orchestrator.shutdown() == ()


# --------------------------------------------------------------------------
# Perfiles sin IP testigo
# --------------------------------------------------------------------------


def test_a_profile_without_a_witness_ip_is_never_probed(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """No hay nada que preguntarle a la red: preguntarlo seria gastarlo en balde."""
    orchestrator.handle(connect("sin-testigo"))

    orchestrator.handle(Request(command=Command.LIST))

    assert "sin-testigo" not in probe.calls


def test_a_profile_without_a_witness_ip_reports_unverified(
    orchestrator: Orchestrator,
) -> None:
    """Ni conectado ni caido: abierto y sin forma de saberlo."""
    orchestrator.handle(connect("sin-testigo"))

    response = orchestrator.handle(Request(command=Command.LIST))
    summary = next(p for p in response.profiles if p.id == "sin-testigo")

    assert summary.state is ConnectionState.UNVERIFIED


def test_a_profile_without_a_witness_ip_never_reports_connected(
    orchestrator: Orchestrator, probe: FakeProbe
) -> None:
    """La regla del estado real sigue en pie.

    Aunque la sonda dijese que si a todo —que aqui no se la llega a preguntar—
    un perfil sin testigo no puede afirmar que esta conectado. Es la garantia
    que hace aceptable dejar el campo vacio.
    """
    probe.connected = True
    orchestrator.handle(connect("sin-testigo"))

    for _ in range(3):
        response = orchestrator.handle(Request(command=Command.LIST))

    summary = next(p for p in response.profiles if p.id == "sin-testigo")
    assert summary.state is not ConnectionState.CONNECTED


def test_an_unverified_profile_is_not_relaunched(orchestrator: Orchestrator) -> None:
    """Volver a pulsarlo no abre el cliente por segunda vez."""
    orchestrator.handle(connect("sin-testigo"))

    response = orchestrator.handle(connect("sin-testigo"))

    assert not response.ok
    assert "ya esta abierto" in response.message


def test_an_unverified_profile_still_occupies_the_machine(
    orchestrator: Orchestrator,
) -> None:
    """Sin poder comprobarlo hay que dar por hecho que ocupa, no lo contrario.

    Un perfil abierto del que no se sabe nada pudo dejar rutas puestas. Tratarlo
    como libre porque no se puede mirar seria justo la suposicion peligrosa.
    """
    unverified = CATALOG["sin-testigo"]
    session = Session(profile_id=unverified.id, state=ConnectionState.UNVERIFIED)

    assert is_occupying(session)


def test_an_app_profile_is_not_reported_as_unverified(
    registry: ConnectorRegistry, network: FakeNetwork, probe: FakeProbe
) -> None:
    """A un APP no le falta el testigo: es que no monta tunel que sondear."""
    app = make_profile("app-iap", TunnelType.APP)
    orchestrator = Orchestrator(
        catalog={**CATALOG, app.id: app},
        registry=registry,
        network=network,
        probe=probe,
    )
    orchestrator.handle(connect("app-iap"))

    response = orchestrator.handle(Request(command=Command.LIST))
    summary = next(p for p in response.profiles if p.id == "app-iap")

    assert summary.state is not ConnectionState.UNVERIFIED


# --------------------------------------------------------------------------
# Abrir el cliente para configurarlo
# --------------------------------------------------------------------------


def launch(profile_id: str, *, confirmed: bool = False) -> Request:
    return Request(command=Command.LAUNCH, profile_id=profile_id, user_confirmed=confirmed)


def test_opening_a_client_does_not_go_through_the_arbiter(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    """Abrir una ventana no ocupa la maquina ni desaloja a nadie.

    Es el camino que hace falta para dar de alta una VPN: la configuracion
    —SSO, IPSec, certificados, gateways— se hace en el cliente del fabricante,
    que es el unico que la entiende.
    """
    orchestrator.handle(connect("full-a"))
    calls_before = len(launcher.calls)

    response = orchestrator.handle(launch("split-a"))

    assert response.ok
    assert len(launcher.calls) == calls_before + 1


def test_opening_a_client_takes_no_photograph_of_the_network(
    orchestrator: Orchestrator, network: FakeNetwork
) -> None:
    """No conecta nada, asi que no hay nada que deshacer despues."""
    orchestrator.handle(launch("split-a"))

    assert network.snapshots == 0


def test_opening_a_client_that_breaks_the_network_needs_confirmation(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    """Abrir no es conectar, salvo que el cliente conecte solo al arrancar.

    Desde aqui no se puede saber, y la diferencia es la sesion remota de quien
    lo pulse. Preguntar de mas cuesta un clic.
    """
    response = orchestrator.handle(launch("full-rdp"))

    assert not response.ok
    assert "corta la conectividad local" in response.message
    assert launcher.calls == []


def test_with_confirmation_the_client_does_open(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    response = orchestrator.handle(launch("full-rdp", confirmed=True))

    assert response.ok
    assert len(launcher.calls) == 1


def test_opening_a_client_never_claims_to_be_connected(orchestrator: Orchestrator) -> None:
    """Abrir el cliente no dice nada sobre el tunel."""
    response = orchestrator.handle(launch("split-a"))

    assert response.state is not ConnectionState.CONNECTED


def test_opening_the_client_of_an_unverifiable_profile_says_so(
    orchestrator: Orchestrator,
) -> None:
    response = orchestrator.handle(launch("sin-testigo"))

    assert response.ok
    assert response.state in (ConnectionState.LAUNCHING, ConnectionState.UNVERIFIED)


def test_a_profile_outside_the_catalog_is_not_opened(
    orchestrator: Orchestrator, launcher: FakeLauncher
) -> None:
    """La regla de siempre: solo ids del catalogo firmado."""
    response = orchestrator.handle(launch("no-existe"))

    assert not response.ok
    assert launcher.calls == []
