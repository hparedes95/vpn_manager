"""Tests de `core.models`.

El nucleo es logica pura, asi que aqui se cubre lo unico que hace: validar
un perfil antes de que llegue a un servicio que corre en SYSTEM, y fijar los
valores serializados de los enums, que son contrato con el catalogo y con el
pipe.

Los nombres de los tests van en ingles (identificadores) y las docstrings en
espanol, como el resto del repositorio.
"""

from __future__ import annotations

import dataclasses

import pytest

from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    DisconnectStrategy,
    LaunchKind,
    LaunchSpec,
    Profile,
    Result,
    Session,
    TunnelType,
)

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
AZURE_PFN = "Microsoft.AzureVpn_8wekyb3d8bbwe!App"


def exe_spec(target: str = WIREGUARD_EXE) -> LaunchSpec:
    return LaunchSpec(kind=LaunchKind.EXE, target=target)


def msix_spec(target: str = AZURE_PFN) -> LaunchSpec:
    return LaunchSpec(kind=LaunchKind.MSIX, target=target)


def make_profile(
    *,
    profile_id: str = "wireguard-corp",
    launch: LaunchSpec | None = None,
    tunnel_type: TunnelType = TunnelType.FULL,
    probe_ip: str | None = "10.20.0.1",
    routes: tuple[str, ...] = (),
) -> Profile:
    """Perfil valido por defecto; cada test rompe solo lo que quiere probar."""
    return Profile(
        id=profile_id,
        display_name="WireGuard corporativa",
        connector="wireguard",
        launch=exe_spec() if launch is None else launch,
        tunnel_type=tunnel_type,
        probe_ip=probe_ip,
        routes=routes,
    )


def mentions(issues: list[str], fragment: str) -> bool:
    return any(fragment in issue for issue in issues)


# --------------------------------------------------------------------------
# LaunchSpec
# --------------------------------------------------------------------------


def test_valid_exe_spec_has_no_issues() -> None:
    assert exe_spec().validate() == []


def test_exe_extension_check_is_case_insensitive() -> None:
    """Windows no distingue mayusculas: `.EXE` es tan valido como `.exe`."""
    assert exe_spec(r"C:\Program Files\OpenVPN\bin\OPENVPN-GUI.EXE").validate() == []


def test_exe_spec_without_exe_extension_is_rejected() -> None:
    """Un .bat o un .cmd colado aqui es ejecucion arbitraria como SYSTEM."""
    issues = exe_spec(r"C:\temp\conectar.bat").validate()

    assert mentions(issues, "debe apuntar a un .exe")


def test_empty_exe_target_reports_both_issues() -> None:
    """Un target vacio incumple dos reglas a la vez y las dos se reportan."""
    issues = exe_spec("").validate()

    assert len(issues) == 2
    assert mentions(issues, "target vacio")
    assert mentions(issues, "debe apuntar a un .exe")


def test_valid_msix_spec_has_no_issues() -> None:
    """El Azure VPN Client es app de Store: se lanza por PFN!AppId."""
    assert msix_spec().validate() == []


def test_msix_target_without_separator_is_rejected() -> None:
    issues = msix_spec("Microsoft.AzureVpn_8wekyb3d8bbwe").validate()

    assert mentions(issues, "PackageFamilyName")


def test_empty_msix_target_reports_both_issues() -> None:
    issues = msix_spec("").validate()

    assert len(issues) == 2
    assert mentions(issues, "target vacio")
    assert mentions(issues, "PackageFamilyName")


def test_msix_spec_is_not_required_to_end_in_exe() -> None:
    """La regla del .exe es solo para EXE; un MSIX no tiene ruta de binario."""
    assert msix_spec("Fabrikam.Vpn_1234567890abc!App").validate() == []


def test_exe_spec_is_not_required_to_contain_a_separator() -> None:
    """Y al reves: la regla del `!` es solo para MSIX."""
    assert exe_spec().validate() == []


def test_launch_spec_defaults_to_no_arguments() -> None:
    assert exe_spec().args == ()


def test_launch_spec_is_immutable() -> None:
    """Congelado a proposito: lo que se lanza no se retoca sobre la marcha."""
    spec = exe_spec()

    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.target = r"C:\temp\otro.exe"  # type: ignore[misc]


def test_launch_spec_compares_by_value_and_is_hashable() -> None:
    assert exe_spec() == exe_spec()
    assert len({exe_spec(), exe_spec(), msix_spec()}) == 2


# --------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------


def test_valid_full_profile_has_no_issues() -> None:
    assert make_profile().validate() == []


def test_profile_without_id_is_rejected() -> None:
    """El id es lo unico que viaja por el pipe: sin el no hay nada que pedir."""
    issues = make_profile(profile_id="").validate()

    assert mentions(issues, "id vacio")


def test_app_profile_with_routes_is_rejected() -> None:
    """IAP Desktop reenvia TCP por aplicacion: no tiene rutas que aplicar."""
    issues = make_profile(
        tunnel_type=TunnelType.APP,
        probe_ip=None,
        routes=("10.0.0.0/8",),
    ).validate()

    assert mentions(issues, "no debe aplicar rutas")


def test_app_profile_without_probe_ip_is_accepted() -> None:
    """Excepcion deliberada: un tunel APP no tiene estado de red que sondear."""
    assert make_profile(tunnel_type=TunnelType.APP, probe_ip=None).validate() == []


@pytest.mark.parametrize("tunnel_type", [TunnelType.FULL, TunnelType.SPLIT])
def test_network_profile_without_probe_ip_is_rejected(tunnel_type: TunnelType) -> None:
    """Sin IP testigo el estado seria el que dice el cliente, no el real (HU-02)."""
    issues = make_profile(tunnel_type=tunnel_type, probe_ip=None).validate()

    assert mentions(issues, "no se puede verificar el estado real")


def test_profile_propagates_launch_issues() -> None:
    """Un perfil no puede ser valido si su forma de arrancar no lo es."""
    issues = make_profile(launch=exe_spec(r"C:\temp\conectar.cmd")).validate()

    assert mentions(issues, "debe apuntar a un .exe")


def test_profile_reports_every_issue_at_once() -> None:
    """Se devuelve la lista completa: quien edita el catalogo lo arregla de una."""
    issues = Profile(
        id="",
        display_name="Perfil roto",
        connector="desconocido",
        launch=LaunchSpec(kind=LaunchKind.MSIX, target=""),
        tunnel_type=TunnelType.FULL,
    ).validate()

    assert len(issues) == 4
    assert mentions(issues, "target vacio")
    assert mentions(issues, "PackageFamilyName")
    assert mentions(issues, "id vacio")
    assert mentions(issues, "no se puede verificar el estado real")


def test_profile_defaults_are_the_conservative_ones() -> None:
    """Por defecto un perfil no corta la red y no se sabe desconectar solo."""
    profile = make_profile()

    assert profile.breaks_local_connectivity is False
    assert profile.disconnect_strategy is DisconnectStrategy.NONE
    assert profile.target_networks == ()
    assert profile.dns == ()
    assert profile.routes == ()
    assert profile.post_connect_apps == ()
    assert profile.expected_client_version is None
    assert profile.notes == ""


def test_profile_is_immutable() -> None:
    """Viene del catalogo firmado: si se pudiera mutar, la firma no serviria."""
    profile = make_profile()

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.launch = exe_spec(r"C:\temp\otro.exe")  # type: ignore[misc]


def test_profile_accepts_post_connect_apps() -> None:
    profile = Profile(
        id="ivanti-cliente-b",
        display_name="Ivanti cliente B",
        connector="ivanti",
        launch=exe_spec(r"C:\Program Files\Common Files\Pulse Secure\pulselauncher.exe"),
        tunnel_type=TunnelType.SPLIT,
        probe_ip="172.16.4.1",
        post_connect_apps=(exe_spec(r"C:\Windows\System32\mstsc.exe"),),
    )

    assert profile.validate() == []
    assert len(profile.post_connect_apps) == 1


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


def test_new_session_starts_disconnected() -> None:
    session = Session(profile_id="wireguard-corp")

    assert session.state is ConnectionState.DISCONNECTED
    assert session.pid is None
    assert session.applied_routes == []
    assert session.applied_dns == []
    assert session.message == ""


def test_sessions_do_not_share_their_mutable_state() -> None:
    """Si las listas se compartieran, revertir una sesion tocaria las otras."""
    first = Session(profile_id="a")
    second = Session(profile_id="b")

    first.applied_routes.append("10.0.0.0/8")

    assert second.applied_routes == []


def test_session_is_mutable() -> None:
    """A diferencia del perfil: la sesion es estado vivo del servicio."""
    session = Session(profile_id="wireguard-corp")

    session.state = ConnectionState.CONNECTED
    session.pid = 4242

    assert session.state is ConnectionState.CONNECTED
    assert session.pid == 4242


# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------


def test_failure_result_carries_the_error_state() -> None:
    result = Result.failure("el cliente no esta instalado")

    assert result.ok is False
    assert result.state is ConnectionState.ERROR
    assert result.message == "el cliente no esta instalado"


def test_result_message_is_optional() -> None:
    result = Result(ok=True, state=ConnectionState.CONNECTED)

    assert result.message == ""


def test_result_is_immutable() -> None:
    result = Result.failure("fallo")

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.ok = True  # type: ignore[misc]


# --------------------------------------------------------------------------
# Enums: contrato con el catalogo, el pipe y la interfaz
# --------------------------------------------------------------------------


def test_capabilities_are_exactly_the_four_declared_ones() -> None:
    """La UI se dibuja a partir de esto; anadir una capacidad es cambiar la UI."""
    assert {c.name for c in Capability} == {"LAUNCH", "CONNECT", "DISCONNECT", "STATUS"}


def test_tunnel_type_values_are_stable() -> None:
    """Son claves del catalogo firmado: cambiarlas invalida los perfiles."""
    assert {t.name: t.value for t in TunnelType} == {
        "FULL": "full",
        "SPLIT": "split",
        "APP": "app",
    }


def test_launch_kind_values_are_stable() -> None:
    assert {k.name: k.value for k in LaunchKind} == {"EXE": "exe", "MSIX": "msix"}


def test_disconnect_strategy_values_are_stable() -> None:
    assert {s.name: s.value for s in DisconnectStrategy} == {
        "NONE": "none",
        "CLI": "cli",
        "TERMINATE": "terminate",
    }


def test_connection_state_values_are_stable() -> None:
    """Viajan por el pipe hacia la UI: son contrato entre los dos procesos."""
    assert {s.name: s.value for s in ConnectionState} == {
        "DISCONNECTED": "desconectado",
        "LAUNCHING": "lanzando",
        "WAITING_AUTH": "esperando autenticacion del usuario",
        "CONNECTED": "conectado",
        "DEGRADED": "conectado con avisos",
        "DOWN": "caido",
        "ERROR": "error",
    }
