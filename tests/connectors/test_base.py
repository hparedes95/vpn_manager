"""Tests de `connectors.base`.

Lo que de verdad se prueba aqui no es que se arranque un proceso —el lanzador
es de mentira— sino lo contrario: que **no** se arranca nada cuando el perfil
no es valido, no es de este conector, o la operacion no esta declarada. Ese
es el filtro que protege a un servicio que corre en SYSTEM.
"""

from __future__ import annotations

import pytest

from vpnmanager.connectors.base import (
    Connector,
    ConnectorRegistry,
    LauncherConnector,
    LaunchOutcome,
)
from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    DisconnectStrategy,
    LaunchKind,
    LaunchSpec,
    Profile,
    Result,
    TunnelType,
)

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"


class FakeLauncher:
    """Lanzador de mentira: anota lo que se le pide y no arranca nada."""

    def __init__(self, outcome: LaunchOutcome | None = None) -> None:
        self.calls: list[LaunchSpec] = []
        self.outcome = LaunchOutcome(started=True, pid=4242) if outcome is None else outcome

    def start(self, spec: LaunchSpec) -> LaunchOutcome:
        self.calls.append(spec)
        return self.outcome


class LyingConnector(LauncherConnector):
    """Declara CONNECT y no lo implementa. El caso que hay que cazar."""

    capabilities = frozenset({Capability.LAUNCH, Capability.CONNECT})


class ObedientConnector(LauncherConnector):
    """Declara CONNECT y lo implementa, como haria un conector verificado."""

    capabilities = frozenset({Capability.LAUNCH, Capability.CONNECT})

    def _connect(self, profile: Profile) -> Result:
        return Result(
            ok=True,
            state=ConnectionState.WAITING_AUTH,
            message=f"orden aceptada para '{profile.id}'",
        )


def make_profile(
    *,
    profile_id: str = "wireguard-corp",
    connector: str = "wireguard",
    launch: LaunchSpec | None = None,
    probe_ip: str | None = "10.20.0.1",
    disconnect_strategy: DisconnectStrategy = DisconnectStrategy.NONE,
) -> Profile:
    return Profile(
        id=profile_id,
        display_name="WireGuard corporativa",
        connector=connector,
        launch=LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE) if launch is None else launch,
        tunnel_type=TunnelType.FULL,
        probe_ip=probe_ip,
        disconnect_strategy=disconnect_strategy,
    )


@pytest.fixture
def launcher() -> FakeLauncher:
    return FakeLauncher()


@pytest.fixture
def connector(launcher: FakeLauncher) -> LauncherConnector:
    return LauncherConnector(name="wireguard", launcher=launcher)


# --------------------------------------------------------------------------
# Lo que un conector declara
# --------------------------------------------------------------------------


def test_launcher_connector_only_declares_launch(connector: LauncherConnector) -> None:
    """El punto de partida de todo conector: abrir el cliente y nada mas."""
    assert connector.capabilities == frozenset({Capability.LAUNCH})
    assert connector.supports(Capability.LAUNCH)
    assert not connector.supports(Capability.CONNECT)
    assert not connector.supports(Capability.DISCONNECT)
    assert not connector.supports(Capability.STATUS)


def test_launcher_connector_declaration_is_valid(connector: LauncherConnector) -> None:
    assert connector.validate_declaration() == []


def test_connector_without_name_is_reported(launcher: FakeLauncher) -> None:
    issues = LauncherConnector(name="", launcher=launcher).validate_declaration()

    assert any("nombre de conector vacio" in issue for issue in issues)


def test_connector_without_launch_capability_is_reported(launcher: FakeLauncher) -> None:
    """Un conector que ni siquiera abre el cliente no sirve para nada."""

    class MuteConnector(LauncherConnector):
        capabilities = frozenset()

    issues = MuteConnector(name="mudo", launcher=launcher).validate_declaration()

    assert any("debe declarar LAUNCH" in issue for issue in issues)


def test_declared_but_unimplemented_capability_is_reported(launcher: FakeLauncher) -> None:
    """Prometer automatizacion que no existe es peor que no tenerla."""
    issues = LyingConnector(name="mentiroso", launcher=launcher).validate_declaration()

    assert issues == ["declara CONNECT pero no implementa _connect"]


def test_implemented_capability_is_accepted(launcher: FakeLauncher) -> None:
    assert ObedientConnector(name="obediente", launcher=launcher).validate_declaration() == []


# --------------------------------------------------------------------------
# launch()
# --------------------------------------------------------------------------


def test_launch_starts_exactly_the_spec_from_the_profile(
    connector: LauncherConnector, launcher: FakeLauncher
) -> None:
    """Lo que se ejecuta sale del catalogo firmado, sin retoques por el camino."""
    profile = make_profile()

    result = connector.launch(profile)

    assert result.ok
    assert launcher.calls == [profile.launch]


def test_launch_does_not_claim_the_profile_is_connected(connector: LauncherConnector) -> None:
    """Abrir el cliente no es conectar: el estado real lo dira la sonda."""
    result = connector.launch(make_profile())

    assert result.state is ConnectionState.LAUNCHING


def test_launch_hands_back_the_pid(connector: LauncherConnector) -> None:
    """Lo necesitara DisconnectStrategy.TERMINATE; si se pierde aqui, no hay otro."""
    result = connector.launch(make_profile())

    assert result.pid == 4242


def test_launch_without_a_pid_is_still_a_success(launcher: FakeLauncher) -> None:
    """Una app MSIX se lanza por el shell: arranca, pero no da un pid utilizable."""
    launcher.outcome = LaunchOutcome(started=True, pid=None)
    connector = LauncherConnector(name="wireguard", launcher=launcher)

    result = connector.launch(make_profile())

    assert result.ok
    assert result.pid is None


def test_launch_reports_the_launcher_failure(launcher: FakeLauncher) -> None:
    launcher.outcome = LaunchOutcome(started=False, detail="el ejecutable no existe")
    connector = LauncherConnector(name="wireguard", launcher=launcher)

    result = connector.launch(make_profile())

    assert not result.ok
    assert result.state is ConnectionState.ERROR
    assert "el ejecutable no existe" in result.message


def test_launch_failure_without_detail_is_still_readable(launcher: FakeLauncher) -> None:
    launcher.outcome = LaunchOutcome(started=False)
    connector = LauncherConnector(name="wireguard", launcher=launcher)

    result = connector.launch(make_profile())

    assert not result.ok
    assert not result.message.endswith(":")


# --------------------------------------------------------------------------
# Lo que se rechaza. Ningun caso de estos puede llegar a arrancar un proceso.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("capability", [Capability.CONNECT, Capability.DISCONNECT])
def test_undeclared_capability_is_refused_without_starting_anything(
    connector: LauncherConnector, launcher: FakeLauncher, capability: Capability
) -> None:
    operation = {Capability.CONNECT: connector.connect, Capability.DISCONNECT: connector.disconnect}

    result = operation[capability](make_profile())

    assert not result.ok
    assert capability.name in result.message
    assert launcher.calls == []


def test_undeclared_status_is_refused(connector: LauncherConnector) -> None:
    result = connector.status(make_profile())

    assert not result.ok
    assert "STATUS" in result.message


def test_profile_of_another_connector_is_refused(
    connector: LauncherConnector, launcher: FakeLauncher
) -> None:
    """Un fallo de encaminamiento no puede acabar ejecutando el binario de otro."""
    result = connector.launch(make_profile(connector="openvpn"))

    assert not result.ok
    assert "openvpn" in result.message
    assert launcher.calls == []


def test_invalid_profile_is_never_launched(
    connector: LauncherConnector, launcher: FakeLauncher
) -> None:
    """Un .bat en el catalogo es ejecucion arbitraria como SYSTEM: se para aqui."""
    profile = make_profile(launch=LaunchSpec(kind=LaunchKind.EXE, target=r"C:\temp\conectar.bat"))

    result = connector.launch(profile)

    assert not result.ok
    assert "debe apuntar a un .exe" in result.message
    assert launcher.calls == []


def test_refusal_lists_every_problem_with_the_profile(
    connector: LauncherConnector, launcher: FakeLauncher
) -> None:
    profile = make_profile(
        profile_id="",
        launch=LaunchSpec(kind=LaunchKind.EXE, target=""),
        probe_ip=None,
    )

    result = connector.launch(profile)

    assert "target vacio" in result.message
    assert "id vacio" in result.message
    assert "no se puede verificar el estado real" in result.message
    assert launcher.calls == []


def test_capability_is_checked_before_ownership(connector: LauncherConnector) -> None:
    """Con dos problemas a la vez se informa del primero: que no se puede."""
    result = connector.connect(make_profile(connector="openvpn"))

    assert "CONNECT" in result.message


# --------------------------------------------------------------------------
# Delegacion en el proveedor
# --------------------------------------------------------------------------


def test_declared_capability_reaches_the_provider(launcher: FakeLauncher) -> None:
    connector = ObedientConnector(name="wireguard", launcher=launcher)

    result = connector.connect(make_profile())

    assert result.ok
    assert result.state is ConnectionState.WAITING_AUTH
    assert "wireguard-corp" in result.message


def test_provider_never_sees_an_invalid_profile(launcher: FakeLauncher) -> None:
    """La comprobacion esta en la base: heredar no permite saltarsela."""
    connector = ObedientConnector(name="wireguard", launcher=launcher)

    result = connector.connect(make_profile(profile_id=""))

    assert not result.ok
    assert "id vacio" in result.message


def test_unimplemented_capability_fails_loudly(launcher: FakeLauncher) -> None:
    """Si el registro no lo hubiera parado, esto revienta en vez de mentir."""
    connector = LyingConnector(name="mentiroso", launcher=launcher)
    profile = make_profile(connector="mentiroso")

    with pytest.raises(NotImplementedError):
        connector.connect(profile)


# --------------------------------------------------------------------------
# ConnectorRegistry
# --------------------------------------------------------------------------


def test_registry_resolves_the_connector_of_a_profile(connector: LauncherConnector) -> None:
    registry = ConnectorRegistry()
    registry.register(connector)

    assert registry.for_profile(make_profile()) is connector
    assert registry.get("wireguard") is connector
    assert "wireguard" in registry
    assert len(registry) == 1


def test_registry_returns_none_for_a_connector_that_does_not_exist(
    connector: LauncherConnector,
) -> None:
    """El catalogo puede nombrar un conector que no existe; no se revienta por eso."""
    registry = ConnectorRegistry()
    registry.register(connector)

    assert registry.for_profile(make_profile(connector="forcepoint")) is None
    assert registry.get("forcepoint") is None


def test_registry_refuses_a_badly_declared_connector(launcher: FakeLauncher) -> None:
    """Mejor que el servicio no arranque a que arranque con un boton que miente."""
    registry = ConnectorRegistry()

    with pytest.raises(ValueError, match="mal declarado"):
        registry.register(LyingConnector(name="mentiroso", launcher=launcher))

    assert len(registry) == 0


def test_registry_refuses_a_duplicate_name(
    connector: LauncherConnector, launcher: FakeLauncher
) -> None:
    registry = ConnectorRegistry()
    registry.register(connector)

    with pytest.raises(ValueError, match="ya hay un conector"):
        registry.register(LauncherConnector(name="wireguard", launcher=launcher))


def test_registry_lists_its_connectors_in_a_stable_order(launcher: FakeLauncher) -> None:
    registry = ConnectorRegistry()
    for name in ("openvpn", "azure", "wireguard"):
        registry.register(LauncherConnector(name=name, launcher=launcher))

    assert registry.names() == ("azure", "openvpn", "wireguard")


def test_empty_registry_resolves_nothing() -> None:
    registry = ConnectorRegistry()

    assert len(registry) == 0
    assert registry.names() == ()
    assert registry.for_profile(make_profile()) is None


# --------------------------------------------------------------------------
# El catalogo frente a lo que los conectores pueden de verdad
# --------------------------------------------------------------------------


def test_catalog_validation_accepts_a_coherent_catalog(launcher: FakeLauncher) -> None:
    registry = ConnectorRegistry()
    registry.register(ObedientConnector(name="wireguard", launcher=launcher))

    assert registry.validate_catalog([make_profile()]) == []


def test_a_profile_governed_by_nobody_is_reported(connector: LauncherConnector) -> None:
    registry = ConnectorRegistry()
    registry.register(connector)

    issues = registry.validate_catalog([make_profile(connector="forcepoint")])

    assert any("forcepoint" in issue for issue in issues)


def test_a_profile_asking_for_a_disconnect_nobody_implements_is_reported(
    connector: LauncherConnector,
) -> None:
    """Pasa la validacion del perfil, pasa la del conector, y falla al desconectar."""
    registry = ConnectorRegistry()
    registry.register(connector)
    profile = make_profile(disconnect_strategy=DisconnectStrategy.CLI)

    issues = registry.validate_catalog([profile])

    assert any("no declara DISCONNECT" in issue for issue in issues)


@pytest.mark.parametrize("strategy", [DisconnectStrategy.NONE, DisconnectStrategy.TERMINATE])
def test_strategies_that_do_not_need_the_client_are_accepted(
    connector: LauncherConnector, strategy: DisconnectStrategy
) -> None:
    """NONE no desconecta nada y TERMINATE mata el proceso: ninguna pide permiso."""
    registry = ConnectorRegistry()
    registry.register(connector)

    assert registry.validate_catalog([make_profile(disconnect_strategy=strategy)]) == []


def test_catalog_validation_reports_every_profile(connector: LauncherConnector) -> None:
    registry = ConnectorRegistry()
    registry.register(connector)

    issues = registry.validate_catalog(
        [
            make_profile(profile_id="a", connector="forcepoint"),
            make_profile(profile_id="b", disconnect_strategy=DisconnectStrategy.CLI),
            make_profile(profile_id="c"),
        ]
    )

    assert len(issues) == 2


def test_connector_is_abstract() -> None:
    """`Connector` no se instancia: sin `_launch` no hay conector."""
    with pytest.raises(TypeError):
        Connector()  # type: ignore[abstract]
