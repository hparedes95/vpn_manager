"""Tests del arbitro de tunel.

El invariante que se protege aqui es de una linea —un solo tunel completo a la
vez— pero se rompe de muchas maneras: sesiones caidas que dejaron rutas, el
catalogo recargado mientras algo estaba conectado, dos pulsaciones seguidas del
mismo boton. Cada una tiene su caso.
"""

from __future__ import annotations

import dataclasses

import pytest

from vpnmanager.core.arbiter import ConnectionPlan, TunnelArbiter, is_occupying
from vpnmanager.core.models import (
    ConnectionState,
    LaunchKind,
    LaunchSpec,
    Profile,
    Session,
    TunnelType,
)

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"


def make_profile(
    profile_id: str,
    tunnel_type: TunnelType,
    *,
    breaks_local_connectivity: bool = False,
    launch: LaunchSpec | None = None,
    probe_ip: str | None = "10.20.0.1",
) -> Profile:
    return Profile(
        id=profile_id,
        display_name=f"Perfil {profile_id}",
        connector="wireguard",
        launch=LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE) if launch is None else launch,
        tunnel_type=tunnel_type,
        probe_ip=None if tunnel_type is TunnelType.APP else probe_ip,
        breaks_local_connectivity=breaks_local_connectivity,
    )


FULL_A = make_profile("full-a", TunnelType.FULL)
FULL_B = make_profile("full-b", TunnelType.FULL)
FULL_RDP = make_profile("full-rdp", TunnelType.FULL, breaks_local_connectivity=True)
SPLIT_A = make_profile("split-a", TunnelType.SPLIT)
SPLIT_B = make_profile("split-b", TunnelType.SPLIT)
APP_IAP = make_profile("app-iap", TunnelType.APP)
BROKEN = make_profile(
    "roto",
    TunnelType.FULL,
    launch=LaunchSpec(kind=LaunchKind.EXE, target=r"C:\temp\conectar.bat"),
)

CATALOG = {p.id: p for p in (FULL_A, FULL_B, FULL_RDP, SPLIT_A, SPLIT_B, APP_IAP, BROKEN)}


@pytest.fixture
def arbiter() -> TunnelArbiter:
    return TunnelArbiter(CATALOG)


def session(profile_id: str, state: ConnectionState = ConnectionState.CONNECTED) -> Session:
    return Session(profile_id=profile_id, state=state)


# --------------------------------------------------------------------------
# Lo que ni siquiera se planifica
# --------------------------------------------------------------------------


def test_unknown_id_is_refused(arbiter: TunnelArbiter) -> None:
    """Misma regla que el pipe: solo ids del catalogo firmado."""
    plan = arbiter.plan_connection("el-que-me-invente", [])

    assert not plan.allowed
    assert "catalogo firmado" in plan.refusal
    assert plan.disconnect_first == ()


def test_invalid_profile_is_refused_with_its_issues(arbiter: TunnelArbiter) -> None:
    """El catalogo deberia estar validado al cargarlo; esto es la ultima puerta."""
    plan = arbiter.plan_connection("roto", [])

    assert not plan.allowed
    assert "debe apuntar a un .exe" in plan.refusal


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (ConnectionState.CONNECTED, "ya esta conectado"),
        (ConnectionState.DEGRADED, "ya esta conectado, con avisos"),
        (ConnectionState.LAUNCHING, "ya se esta conectando"),
        (ConnectionState.WAITING_AUTH, "ya se esta conectando"),
    ],
)
def test_reconnecting_something_already_in_progress_is_refused(
    arbiter: TunnelArbiter, state: ConnectionState, expected: str
) -> None:
    """Una segunda pulsacion no vuelve a lanzar todo el proceso."""
    plan = arbiter.plan_connection("full-a", [session("full-a", state)])

    assert not plan.allowed
    assert expected in plan.refusal


@pytest.mark.parametrize("state", [ConnectionState.ERROR, ConnectionState.DOWN])
def test_retrying_a_failed_profile_is_allowed(
    arbiter: TunnelArbiter, state: ConnectionState
) -> None:
    """Reintentar lo que fallo o se cayo es justo lo que el usuario querra."""
    plan = arbiter.plan_connection("full-a", [session("full-a", state)])

    assert plan.allowed
    assert plan.disconnect_first == ()


def test_full_is_refused_when_something_unknown_is_still_alive(arbiter: TunnelArbiter) -> None:
    """Si el catalogo cambio bajo los pies, no se puede garantizar el invariante."""
    plan = arbiter.plan_connection("full-a", [session("perfil-de-otro-catalogo")])

    assert not plan.allowed
    assert "perfil-de-otro-catalogo" in plan.refusal


def test_split_ignores_an_unknown_occupant(arbiter: TunnelArbiter) -> None:
    """A un SPLIT le da igual: no echa a nadie, asi que no hay invariante que romper."""
    plan = arbiter.plan_connection("split-a", [session("perfil-de-otro-catalogo")])

    assert plan.allowed


def test_a_disconnected_unknown_session_does_not_block_anything(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection(
        "full-a", [session("perfil-de-otro-catalogo", ConnectionState.DISCONNECTED)]
    )

    assert plan.allowed


# --------------------------------------------------------------------------
# Un solo FULL a la vez
# --------------------------------------------------------------------------


def test_connecting_a_full_with_nothing_active(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("full-a", [])

    assert plan.allowed
    assert plan.disconnect_first == ()
    assert plan.needs_watchdog


def test_a_full_evicts_the_other_full(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("full-b", [session("full-a")])

    assert plan.disconnect_first == ("full-a",)


def test_a_full_does_not_evict_splits_or_apps(arbiter: TunnelArbiter) -> None:
    """Los SPLIT conviven y los APP nunca entran en el arbitro."""
    plan = arbiter.plan_connection(
        "full-a", [session("split-a"), session("split-b"), session("app-iap")]
    )

    assert plan.disconnect_first == ()


def test_a_full_evicts_only_the_full_among_several_actives(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection(
        "full-b", [session("split-a"), session("full-a"), session("app-iap")]
    )

    assert plan.disconnect_first == ("full-a",)


@pytest.mark.parametrize(
    "state",
    [ConnectionState.CONNECTED, ConnectionState.DEGRADED, ConnectionState.DOWN],
)
def test_a_full_that_is_not_cleanly_disconnected_still_has_to_go(
    arbiter: TunnelArbiter, state: ConnectionState
) -> None:
    """Un tunel caido pudo dejar rutas puestas: se limpia antes de montar otro."""
    plan = arbiter.plan_connection("full-b", [session("full-a", state)])

    assert plan.disconnect_first == ("full-a",)


def test_a_cleanly_disconnected_full_is_left_alone(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("full-b", [session("full-a", ConnectionState.DISCONNECTED)])

    assert plan.disconnect_first == ()


def test_an_inconsistent_state_with_two_fulls_evicts_both_in_order(
    arbiter: TunnelArbiter,
) -> None:
    """No deberia pasar nunca. Si pasa, se limpia todo, no la mitad."""
    plan = arbiter.plan_connection("full-rdp", [session("full-b"), session("full-a")])

    assert plan.disconnect_first == ("full-b", "full-a")


def test_a_repeated_session_is_only_disconnected_once(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection(
        "full-b", [session("full-a"), session("full-a", ConnectionState.DEGRADED)]
    )

    assert plan.disconnect_first == ("full-a",)


# --------------------------------------------------------------------------
# SPLIT y APP
# --------------------------------------------------------------------------


def test_a_split_coexists_with_an_active_full(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("split-a", [session("full-a")])

    assert plan.allowed
    assert plan.disconnect_first == ()


def test_a_split_coexists_with_another_split(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("split-b", [session("split-a")])

    assert plan.disconnect_first == ()


def test_an_app_tunnel_never_evicts_anything(arbiter: TunnelArbiter) -> None:
    """IAP Desktop no es una VPN: no toca rutas, no compite con nadie."""
    plan = arbiter.plan_connection("app-iap", [session("full-a"), session("split-a")])

    assert plan.allowed
    assert plan.disconnect_first == ()


@pytest.mark.parametrize("profile_id", ["split-a", "app-iap"])
def test_only_a_full_arms_the_watchdog(arbiter: TunnelArbiter, profile_id: str) -> None:
    """El watchdog existe por el tunel completo, que es el que corta el RDP."""
    plan = arbiter.plan_connection(profile_id, [])

    assert not plan.needs_watchdog


# --------------------------------------------------------------------------
# Confirmacion explicita (HU-03)
# --------------------------------------------------------------------------


def test_a_profile_that_breaks_local_connectivity_needs_confirmation(
    arbiter: TunnelArbiter,
) -> None:
    plan = arbiter.plan_connection("full-rdp", [])

    assert plan.needs_confirmation
    assert "escritorio remoto" in plan.confirmation_reason


def test_a_normal_profile_needs_no_confirmation(arbiter: TunnelArbiter) -> None:
    plan = arbiter.plan_connection("full-a", [])

    assert not plan.needs_confirmation
    assert plan.confirmation_reason == ""


def test_confirmation_is_decided_by_the_target_not_by_what_is_active(
    arbiter: TunnelArbiter,
) -> None:
    """Salir de un tunel que corta la red local no corta nada: la devuelve."""
    plan = arbiter.plan_connection("full-a", [session("full-rdp")])

    assert not plan.needs_confirmation
    assert plan.disconnect_first == ("full-rdp",)


# --------------------------------------------------------------------------
# Forma del plan
# --------------------------------------------------------------------------


def test_the_plan_is_immutable(arbiter: TunnelArbiter) -> None:
    """Se pasa del arbitro al servicio: por el camino no lo retoca nadie."""
    plan = arbiter.plan_connection("full-a", [])

    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.needs_confirmation = True  # type: ignore[misc]


def test_a_refused_plan_carries_nothing_to_execute() -> None:
    plan = ConnectionPlan.refused("full-a", "por algo")

    assert not plan.allowed
    assert plan.disconnect_first == ()
    assert not plan.needs_watchdog
    assert not plan.needs_confirmation


def test_the_arbiter_accepts_any_iterable_of_sessions(arbiter: TunnelArbiter) -> None:
    """El servicio puede pasarle un generador; se recorre mas de una vez dentro."""
    plan = arbiter.plan_connection("full-b", (s for s in [session("full-a")]))

    assert plan.allowed
    assert plan.disconnect_first == ("full-a",)


def test_the_arbiter_does_not_keep_a_reference_to_the_caller_catalog() -> None:
    """Si el catalogo se recarga, el arbitro vivo no cambia de opinion a medias."""
    catalog = {FULL_A.id: FULL_A}
    arbiter = TunnelArbiter(catalog)

    catalog.clear()

    assert arbiter.plan_connection("full-a", []).allowed


@pytest.mark.parametrize(
    ("state", "occupying"),
    [
        (ConnectionState.DISCONNECTED, False),
        (ConnectionState.LAUNCHING, True),
        (ConnectionState.WAITING_AUTH, True),
        (ConnectionState.CONNECTED, True),
        (ConnectionState.DEGRADED, True),
        (ConnectionState.DOWN, True),
        (ConnectionState.ERROR, True),
    ],
)
def test_only_a_cleanly_disconnected_session_frees_the_machine(
    state: ConnectionState, occupying: bool
) -> None:
    assert is_occupying(session("cualquiera", state)) is occupying
