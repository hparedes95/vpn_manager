"""Tests del cliente de la interfaz.

El transporte y el lanzador son de mentira, asi que se puede probar entero el
lado de la interfaz sin Windows, sin servicio y sin PySide6. Lo que mas
importa de aqui es cuando **no** se confirma: ese silencio es lo que dispara
la reversion del watchdog.
"""

from __future__ import annotations

import pytest

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    LaunchKind,
    LaunchSpec,
    TunnelType,
)
from vpnmanager.core.protocol import (
    Command,
    LaunchOrder,
    ProfileSummary,
    Request,
    Response,
)
from vpnmanager.ui.client import (
    ServiceClient,
    action_label,
    is_open,
    needs_asking_first,
)

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"


class FakeTransport:
    """Un pipe de mentira: se le cargan respuestas y anota lo que se le manda."""

    def __init__(self, *responses: Response) -> None:
        self.sent: list[Request] = []
        self._pending = [response.encode() for response in responses]

    def send(self, payload: bytes) -> None:
        self.sent.append(Request.decode(payload.removesuffix(b"\n")))

    def receive(self) -> bytes:
        return self._pending.pop(0) if self._pending else Response(ok=True).encode()

    def commands(self) -> list[Command]:
        return [request.command for request in self.sent]


class FakeLauncher:
    def __init__(self) -> None:
        self.specs: list[LaunchSpec] = []

    def start_here(self, spec: LaunchSpec) -> LaunchOutcome:
        self.specs.append(spec)
        return LaunchOutcome(started=True, pid=4242)


def summary(
    *,
    state: ConnectionState = ConnectionState.DISCONNECTED,
    capabilities: tuple[Capability, ...] = (Capability.LAUNCH,),
    needs_confirmation: bool = False,
) -> ProfileSummary:
    return ProfileSummary(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        tunnel_type=TunnelType.FULL,
        state=state,
        capabilities=capabilities,
        needs_confirmation=needs_confirmation,
    )


@pytest.fixture
def launcher() -> FakeLauncher:
    return FakeLauncher()


# --------------------------------------------------------------------------
# Hablar con el servicio
# --------------------------------------------------------------------------


def test_listing_asks_for_the_list(launcher: FakeLauncher) -> None:
    transport = FakeTransport(Response(ok=True, profiles=(summary(),)))

    profiles = ServiceClient(transport, launcher).list_profiles()

    assert transport.commands() == [Command.LIST]
    assert profiles[0].id == "wireguard-corp"


def test_connecting_passes_the_user_confirmation(launcher: FakeLauncher) -> None:
    """Sin esto, el servicio rechaza un perfil que corta la red local."""
    transport = FakeTransport(Response(ok=True))

    ServiceClient(transport, launcher).connect("wireguard-corp", user_confirmed=True)

    assert transport.sent[0].user_confirmed is True


def test_a_response_split_across_reads_is_waited_for(launcher: FakeLauncher) -> None:
    """El pipe es un flujo: la respuesta puede llegar a trozos."""

    class SplittingTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            encoded = Response(ok=True, message="entera").encode()
            self._chunks = [encoded[:5], encoded[5:]]

        def receive(self) -> bytes:
            return self._chunks.pop(0)

    response = ServiceClient(SplittingTransport(), launcher).status("wireguard-corp")

    assert response.message == "entera"


# --------------------------------------------------------------------------
# Arrancar el cliente en la sesion del usuario
# --------------------------------------------------------------------------


def test_a_launch_order_is_run_here(launcher: FakeLauncher) -> None:
    """El servicio no puede: vive en la sesion 0, sin escritorio."""
    order = LaunchOrder(kind=LaunchKind.EXE, target=WIREGUARD_EXE, args=("/x",))
    transport = FakeTransport(Response(ok=True, launch=order))

    ServiceClient(transport, launcher).connect("wireguard-corp")

    assert len(launcher.specs) == 1
    assert launcher.specs[0].target == WIREGUARD_EXE
    assert launcher.specs[0].args == ("/x",)


def test_a_response_without_an_order_launches_nothing(launcher: FakeLauncher) -> None:
    ServiceClient(FakeTransport(Response(ok=True)), launcher).connect("wireguard-corp")

    assert launcher.specs == []


def test_the_launch_outcome_is_kept_for_the_interface(launcher: FakeLauncher) -> None:
    order = LaunchOrder(kind=LaunchKind.EXE, target=WIREGUARD_EXE)
    client = ServiceClient(FakeTransport(Response(ok=True, launch=order)), launcher)

    client.launch("wireguard-corp")

    assert client.last_launch is not None
    assert client.last_launch.started


# --------------------------------------------------------------------------
# Confirmar: lo que desarma el watchdog
# --------------------------------------------------------------------------


def test_confirming_only_happens_once_the_service_says_connected(
    launcher: FakeLauncher,
) -> None:
    transport = FakeTransport(
        Response(ok=True, state=ConnectionState.CONNECTED),
        Response(ok=True, state=ConnectionState.CONNECTED),
    )

    ServiceClient(transport, launcher).confirm_if_connected("wireguard-corp")

    assert transport.commands() == [Command.STATUS, Command.CONFIRM]


@pytest.mark.parametrize(
    "state",
    [
        ConnectionState.LAUNCHING,
        ConnectionState.WAITING_AUTH,
        ConnectionState.DEGRADED,
        ConnectionState.DOWN,
        ConnectionState.ERROR,
    ],
)
def test_nothing_is_confirmed_while_the_tunnel_is_not_up(
    launcher: FakeLauncher, state: ConnectionState
) -> None:
    """Confirmar antes de tiempo desarmaria el seguro antes de montar el tunel.

    Seria firmar el acuse antes de abrir el paquete: el watchdog se quedaria
    sin nada que vigilar justo en el rato en que hace falta.
    """
    transport = FakeTransport(Response(ok=True, state=state))

    ServiceClient(transport, launcher).confirm_if_connected("wireguard-corp")

    assert Command.CONFIRM not in transport.commands()


# --------------------------------------------------------------------------
# Lo que la bandeja pinta
# --------------------------------------------------------------------------


def test_a_connector_that_cannot_connect_says_abrir_cliente() -> None:
    """La regla del proyecto, aqui es donde se ve."""
    assert action_label(summary()) == "Abrir cliente"


def test_a_connector_that_can_connect_says_conectar() -> None:
    assert action_label(summary(capabilities=(Capability.LAUNCH, Capability.CONNECT))) == "Conectar"


def test_something_connected_that_can_be_disconnected() -> None:
    label = action_label(
        summary(
            state=ConnectionState.CONNECTED,
            capabilities=(Capability.LAUNCH, Capability.DISCONNECT),
        )
    )

    assert label == "Desconectar"


def test_something_connected_that_cannot_be_disconnected_offers_no_action() -> None:
    """Un boton "Desconectar" que no desconecta es peor que no tener boton."""
    assert action_label(summary(state=ConnectionState.CONNECTED)) == "Conectado"


def test_a_profile_that_breaks_the_network_is_asked_about_first() -> None:
    assert needs_asking_first(summary(needs_confirmation=True)) is True


def test_nothing_is_asked_for_a_normal_profile() -> None:
    assert needs_asking_first(summary()) is False


def test_nothing_is_asked_again_for_something_already_connected() -> None:
    """La red local ya se corto: preguntar ahora no evita nada."""
    assert (
        needs_asking_first(summary(state=ConnectionState.CONNECTED, needs_confirmation=True))
        is False
    )


# --------------------------------------------------------------------------
# Perfiles abiertos sin poder comprobarse
# --------------------------------------------------------------------------


def test_an_unverified_profile_counts_as_open() -> None:
    """Su cliente ya esta abierto: lo que toca ofrecer es cerrarlo."""
    assert is_open(summary(state=ConnectionState.UNVERIFIED))


def test_an_unverified_profile_offers_to_disconnect_when_it_can() -> None:
    assert (
        action_label(
            summary(state=ConnectionState.UNVERIFIED, capabilities=(Capability.DISCONNECT,))
        )
        == "Desconectar"
    )


def test_an_unverified_profile_does_not_claim_to_be_connected() -> None:
    """La diferencia con CONNECTED es justo lo que este estado existe para decir."""
    assert action_label(summary(state=ConnectionState.UNVERIFIED)) == "Abierto"
    assert action_label(summary(state=ConnectionState.CONNECTED)) == "Conectado"


def test_an_unverified_profile_is_not_asked_for_confirmation_again() -> None:
    """Ya se confirmo al abrirlo: volver a preguntar seria preguntar por nada."""
    assert not needs_asking_first(
        summary(state=ConnectionState.UNVERIFIED, needs_confirmation=True)
    )


def test_a_disconnected_profile_that_breaks_the_network_is_still_asked() -> None:
    assert needs_asking_first(summary(state=ConnectionState.DISCONNECTED, needs_confirmation=True))


def test_an_unverified_profile_is_never_confirmed(launcher: FakeLauncher) -> None:
    """Y por eso un FULL sin testigo acaba revertido, que es lo seguro.

    Confirmar sin haber comprobado nada seria firmar el acuse sin abrir el
    paquete: desarmaria el watchdog justo en el caso en el que nadie puede
    decir si el tunel dejo el equipo alcanzable.
    """
    transport = FakeTransport(Response(ok=True, state=ConnectionState.UNVERIFIED))

    ServiceClient(transport, launcher).confirm_if_connected("wireguard-corp")

    assert Command.CONFIRM not in transport.commands()
