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
    LaunchContext,
    LaunchKind,
    LaunchSpec,
    Profile,
    Result,
    Session,
    TunnelType,
    is_ip_address,
    is_network,
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


@pytest.mark.parametrize(
    "target",
    [
        "wireguard.exe",  # se resolveria contra el directorio de trabajo
        r"bin\wireguard.exe",
        r"C:wireguard.exe",  # relativa al directorio actual de la unidad C:
        r"..\wireguard.exe",
    ],
)
def test_relative_exe_target_is_rejected(target: str) -> None:
    """Lo ejecuta un servicio en SYSTEM: donde esta el binario importa.

    Una ruta relativa se resuelve contra el directorio de trabajo del
    servicio, y ahi un usuario sin privilegios puede dejar su propio
    `wireguard.exe`.
    """
    issues = exe_spec(target).validate()

    assert mentions(issues, "debe ser una ruta absoluta")


@pytest.mark.parametrize(
    "target",
    [
        r"\\servidor\reparto\vpn\wireguard.exe",
        r"\\10.0.0.9\share\openvpn-gui.exe",
    ],
)
def test_exe_target_on_a_network_share_is_rejected(target: str) -> None:
    """Un recurso de red lo controla quien controle ese servidor, no nosotros."""
    issues = exe_spec(target).validate()

    assert mentions(issues, "recurso de red")


def test_a_bad_extension_is_reported_without_piling_on_the_path_rules() -> None:
    """Un solo problema, un solo mensaje: el .bat no es ademas 'ruta relativa'."""
    issues = exe_spec("conectar.bat").validate()

    assert issues == ["un target EXE debe apuntar a un .exe"]


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


def test_a_launch_runs_in_the_user_session_unless_it_asks_otherwise() -> None:
    """Correr como SYSTEM hay que pedirlo a proposito, no cae por comodidad."""
    assert exe_spec().context is LaunchContext.USER_SESSION


def test_an_msix_cannot_be_launched_by_the_service() -> None:
    """Una app de Store se resuelve contra el usuario que la tiene instalada."""
    spec = LaunchSpec(kind=LaunchKind.MSIX, target=AZURE_PFN, context=LaunchContext.SERVICE)

    assert mentions(spec.validate(), "sesion del usuario")


def test_an_exe_may_be_launched_by_the_service() -> None:
    """`wireguard.exe /installtunnelservice` necesita privilegio y no es interactivo."""
    spec = LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE, context=LaunchContext.SERVICE)

    assert spec.validate() == []


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


def test_profile_without_display_name_is_rejected() -> None:
    issues = Profile(
        id="wireguard-corp",
        display_name="",
        connector="wireguard",
        launch=exe_spec(),
        tunnel_type=TunnelType.FULL,
        probe_ip="10.20.0.1",
    ).validate()

    assert mentions(issues, "display_name vacio")


def test_profile_without_connector_is_rejected() -> None:
    issues = Profile(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        connector="",
        launch=exe_spec(),
        tunnel_type=TunnelType.FULL,
        probe_ip="10.20.0.1",
    ).validate()

    assert mentions(issues, "connector vacio")


def test_post_connect_apps_pass_the_same_filter_as_the_client() -> None:
    """Las lanza el mismo servicio en SYSTEM: mismo filtro, sin excepciones."""
    profile = Profile(
        id="ivanti-cliente-b",
        display_name="Ivanti cliente B",
        connector="ivanti",
        launch=exe_spec(),
        tunnel_type=TunnelType.SPLIT,
        probe_ip="172.16.4.1",
        post_connect_apps=(
            exe_spec(r"C:\Windows\System32\mstsc.exe"),
            exe_spec(r"C:\temp\script.bat"),
        ),
    )

    issues = profile.validate()

    assert mentions(issues, "post_connect_apps[1]")
    assert mentions(issues, "debe apuntar a un .exe")
    assert not mentions(issues, "post_connect_apps[0]")


def test_app_profile_with_dns_is_rejected() -> None:
    """IAP Desktop no aplica DNS, igual que no aplica rutas."""
    issues = Profile(
        id="iap-produccion",
        display_name="IAP produccion",
        connector="iap",
        launch=exe_spec(),
        tunnel_type=TunnelType.APP,
        dns=("10.0.0.53",),
    ).validate()

    assert mentions(issues, "no debe aplicar DNS")


def test_app_profile_may_declare_target_networks() -> None:
    """`target_networks` es descriptivo, no se aplica: dice a donde se llega."""
    issues = Profile(
        id="iap-produccion",
        display_name="IAP produccion",
        connector="iap",
        launch=exe_spec(),
        tunnel_type=TunnelType.APP,
        target_networks=("10.128.0.0/20",),
    ).validate()

    assert issues == []


@pytest.mark.parametrize("value", ["10.20.0", "no-soy-una-ip", "10.20.0.1/32", "300.1.1.1", ""])
def test_malformed_probe_ip_is_rejected(value: str) -> None:
    issues = make_profile(probe_ip=value).validate()

    assert mentions(issues, "no es una IP")


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/8",
        "192.168.1.0/24",
        "172.16.4.7",  # una ruta a un solo host es un /32 valido
        "fd00::/8",
    ],
)
def test_well_formed_networks_are_accepted(value: str) -> None:
    assert make_profile(routes=(value,)).validate() == []


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/33",
        "10.0.0.5/8",  # bits de host puestos: siempre es una errata
        "10.0.0.0-10.0.0.255",
        "toda-la-oficina",
    ],
)
def test_malformed_routes_are_rejected(value: str) -> None:
    """Estos valores acabarian como parametro de un .ps1 ejecutado en SYSTEM."""
    issues = make_profile(routes=(value,)).validate()

    assert mentions(issues, "routes:")
    assert mentions(issues, "formato CIDR")


def test_malformed_target_networks_are_rejected() -> None:
    profile = Profile(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        connector="wireguard",
        launch=exe_spec(),
        tunnel_type=TunnelType.FULL,
        probe_ip="10.20.0.1",
        target_networks=("10.0.0.0/8", "la-central"),
    )

    issues = profile.validate()

    assert mentions(issues, "target_networks: 'la-central'")


def test_malformed_dns_is_rejected() -> None:
    profile = Profile(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        connector="wireguard",
        launch=exe_spec(),
        tunnel_type=TunnelType.FULL,
        probe_ip="10.20.0.1",
        dns=("10.0.0.53", "dns.interno.local"),
    )

    issues = profile.validate()

    assert mentions(issues, "dns: 'dns.interno.local'")
    assert not mentions(issues, "10.0.0.53")


def test_a_fully_populated_profile_validates() -> None:
    """El perfil realista completo, para que las reglas nuevas no se pasen de listas."""
    profile = Profile(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        connector="wireguard",
        launch=exe_spec(),
        tunnel_type=TunnelType.FULL,
        target_networks=("10.0.0.0/8", "fd00::/8"),
        probe_ip="10.20.0.1",
        dns=("10.0.0.53", "fd00::53"),
        routes=("10.0.0.0/8",),
        post_connect_apps=(exe_spec(r"C:\Windows\System32\mstsc.exe"),),
        expected_client_version="0.5.3",
        breaks_local_connectivity=True,
        disconnect_strategy=DisconnectStrategy.CLI,
        notes="tunel principal de la central",
    )

    assert profile.validate() == []


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


def test_success_result_carries_the_state_and_the_pid() -> None:
    result = Result.success(ConnectionState.LAUNCHING, "cliente abierto", pid=4242)

    assert result.ok is True
    assert result.state is ConnectionState.LAUNCHING
    assert result.pid == 4242


def test_success_result_without_a_pid() -> None:
    """Una app MSIX se lanza por el shell y no devuelve un pid utilizable."""
    result = Result.success(ConnectionState.LAUNCHING)

    assert result.ok is True
    assert result.pid is None
    assert result.message == ""


def test_failure_result_has_no_pid() -> None:
    assert Result.failure("no se pudo abrir").pid is None


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


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("10.20.0.1", True),
        ("fd00::53", True),
        ("0.0.0.0", True),
        ("10.20.0.1/32", False),
        ("10.20.0", False),
        ("", False),
        (" 10.20.0.1", False),
    ],
)
def test_ip_address_parser(value: str, valid: bool) -> None:
    assert is_ip_address(value) is valid


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("10.0.0.0/8", True),
        ("172.16.4.7", True),
        ("fd00::/8", True),
        ("10.0.0.5/8", False),
        ("10.0.0.0/33", False),
        ("", False),
    ],
)
def test_network_parser(value: str, valid: bool) -> None:
    assert is_network(value) is valid


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
