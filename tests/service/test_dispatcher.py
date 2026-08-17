"""Tests del manejador de conexion: de bytes a bytes.

Es el camino completo que recorrera cada peticion que llegue por el pipe, sin
el pipe. Lo que no se prueba aqui —abrir el pipe con su ACL, leer y escribir—
no decide nada.
"""

from __future__ import annotations

import pytest

from vpnmanager.connectors.base import ConnectorRegistry, LauncherConnector
from vpnmanager.core.models import (
    LaunchContext,
    LaunchKind,
    LaunchSpec,
    ProbeResult,
    Profile,
    TunnelType,
)
from vpnmanager.core.protocol import Command, ProtocolError, Request, Response
from vpnmanager.core.watchdog import NetworkSnapshot
from vpnmanager.service.dispatcher import ConnectionHandler, DeferredUserSession
from vpnmanager.service.orchestrator import Orchestrator

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
SNAPSHOT = NetworkSnapshot(payload='{"ok":true,"routes":[]}')


class ForwardingLauncher:
    """Un ProcessLauncher que manda todo a la sesion del usuario, como el real."""

    def __init__(self, user_session: DeferredUserSession) -> None:
        self._user_session = user_session

    def start(self, spec: LaunchSpec) -> object:
        return self._user_session.start_for_user(spec)


class FakeNetwork:
    def snapshot(self) -> NetworkSnapshot:
        return SNAPSHOT

    def restore(self, snapshot: NetworkSnapshot) -> bool:
        return True


class FakeProbe:
    def check(self, profile: Profile) -> ProbeResult:
        return ProbeResult(adapter_up=True, routed=True, probe_answers=True)


PROFILE = Profile(
    id="wireguard-corp",
    display_name="WireGuard corporativa",
    connector="wireguard",
    launch=LaunchSpec(
        kind=LaunchKind.EXE,
        target=WIREGUARD_EXE,
        args=("/installtunnelservice",),
        context=LaunchContext.USER_SESSION,
    ),
    tunnel_type=TunnelType.SPLIT,
    probe_ip="10.20.0.1",
)


@pytest.fixture
def user_session() -> DeferredUserSession:
    return DeferredUserSession()


@pytest.fixture
def handler(user_session: DeferredUserSession) -> ConnectionHandler:
    registry = ConnectorRegistry()
    registry.register(
        LauncherConnector(name="wireguard", launcher=ForwardingLauncher(user_session))  # type: ignore[arg-type]
    )
    orchestrator = Orchestrator(
        catalog={PROFILE.id: PROFILE},
        registry=registry,
        network=FakeNetwork(),
        probe=FakeProbe(),
    )
    return ConnectionHandler(orchestrator, user_session)


def answer(handler: ConnectionHandler, request: Request) -> Response:
    exchange = handler.feed(request.encode())

    assert len(exchange.replies) == 1
    return Response.decode(exchange.replies[0])


# --------------------------------------------------------------------------
# El camino normal
# --------------------------------------------------------------------------


def test_a_request_gets_one_answer(handler: ConnectionHandler) -> None:
    response = answer(handler, Request(command=Command.LIST))

    assert response.ok
    assert len(response.profiles) == 1


def test_several_requests_in_one_read_get_several_answers(handler: ConnectionHandler) -> None:
    """Un pipe es un flujo: pueden llegar dos peticiones juntas."""
    chunk = Request(command=Command.LIST).encode() + Request(command=Command.LIST).encode()

    exchange = handler.feed(chunk)

    assert len(exchange.replies) == 2
    assert exchange.keep_open


def test_a_partial_request_gets_no_answer_yet(handler: ConnectionHandler) -> None:
    encoded = Request(command=Command.LIST).encode()

    exchange = handler.feed(encoded[:6])

    assert exchange.replies == ()
    assert exchange.keep_open


# --------------------------------------------------------------------------
# La orden de arrancar el cliente
# --------------------------------------------------------------------------


def test_the_launch_order_rides_back_on_the_answer(handler: ConnectionHandler) -> None:
    """El servicio no puede lanzar un cliente con ventana; la interfaz si."""
    response = answer(handler, Request(command=Command.LAUNCH, profile_id="wireguard-corp"))

    assert response.ok
    assert response.launch is not None
    assert response.launch.target == WIREGUARD_EXE
    assert response.launch.args == ("/installtunnelservice",)


def test_the_order_comes_straight_from_the_signed_catalog(handler: ConnectionHandler) -> None:
    response = answer(handler, Request(command=Command.CONNECT, profile_id="wireguard-corp"))

    assert response.launch is not None
    assert response.launch.kind is PROFILE.launch.kind
    assert response.launch.target == PROFILE.launch.target


def test_an_order_is_handed_over_only_once(handler: ConnectionHandler) -> None:
    """Si se repitiera, la interfaz abriria el cliente dos veces."""
    answer(handler, Request(command=Command.LAUNCH, profile_id="wireguard-corp"))

    response = answer(handler, Request(command=Command.STATUS, profile_id="wireguard-corp"))

    assert response.launch is None


def test_a_command_that_launches_nothing_carries_no_order(handler: ConnectionHandler) -> None:
    assert answer(handler, Request(command=Command.LIST)).launch is None


def test_the_deferred_session_reports_the_launch_as_under_way() -> None:
    """El estado que corresponde es LAUNCHING; si arranco lo dira la sonda."""
    outcome = DeferredUserSession().start_for_user(PROFILE.launch)

    assert outcome.started
    assert "sesion del usuario" in outcome.detail


def test_taking_an_order_twice_gives_nothing_the_second_time() -> None:
    session = DeferredUserSession()
    session.start_for_user(PROFILE.launch)

    assert session.take() is not None
    assert session.take() is None


# --------------------------------------------------------------------------
# Lo que cierra la conexion
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b"no soy json\n",
        b'{"version":9,"command":"list"}\n',
        b'{"version":1,"command":"exec","profile_id":"x"}\n',
        b'{"version":1,"command":"connect","profile_id":"..\\\\cmd.exe"}\n',
    ],
)
def test_something_that_is_not_the_protocol_closes_the_connection(
    handler: ConnectionHandler, payload: bytes
) -> None:
    """Quien no habla el protocolo esta probando suerte: se contesta y se cuelga."""
    exchange = handler.feed(payload)

    assert not exchange.keep_open
    assert len(exchange.replies) == 1
    assert not Response.decode(exchange.replies[0]).ok


def test_a_flood_without_a_newline_closes_the_connection(handler: ConnectionHandler) -> None:
    """El limite se aplica mientras se acumula, no al tener el mensaje."""
    exchange = handler.feed(b"a" * 5000)

    assert not exchange.keep_open


def test_the_answer_to_garbage_never_repeats_the_garbage(handler: ConnectionHandler) -> None:
    secreto = "token-que-no-debe-acabar-en-el-log"

    exchange = handler.feed(f'{{"version":1,"command":"{secreto}"}}\n'.encode())

    assert secreto not in Response.decode(exchange.replies[0]).message


def test_the_valid_requests_before_the_bad_one_are_still_answered(
    handler: ConnectionHandler,
) -> None:
    """No se tira lo que ya estaba bien: se contesta y luego se cierra."""
    chunk = Request(command=Command.LIST).encode() + b"basura\n"

    exchange = handler.feed(chunk)

    assert len(exchange.replies) == 2
    assert Response.decode(exchange.replies[0]).ok
    assert not exchange.keep_open


def test_a_broken_stream_does_not_come_back(handler: ConnectionHandler) -> None:
    handler.feed(b"a" * 5000)

    exchange = handler.feed(Request(command=Command.LIST).encode())

    assert not exchange.keep_open


def test_the_protocol_error_message_is_safe_to_return() -> None:
    """Lo que justifica devolver `str(error)` tal cual desde el manejador."""
    with pytest.raises(ProtocolError) as error:
        Request.decode(b'{"version":1,"command":"connect","profile_id":"C:\\\\secreto.exe"}')

    assert "secreto" not in str(error.value)
