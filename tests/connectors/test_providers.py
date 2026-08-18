"""Tests de la lista de conectores.

Poco codigo y mucha regla: lo que se protege aqui es que nadie prometa una
automatizacion que no se ha comprobado, que es la unica forma de que la
interfaz no acabe con botones que mienten.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.connectors.providers import (
    PROVIDERS,
    PROVIDERS_BY_NAME,
    Provider,
    build_registry,
    detect,
)
from vpnmanager.core.models import Capability, LaunchKind, LaunchSpec


class NullLauncher:
    def start(self, spec: LaunchSpec) -> LaunchOutcome:
        return LaunchOutcome(started=False, detail="lanzador de prueba")


@pytest.fixture
def registry() -> object:
    return build_registry(NullLauncher())


def test_the_eight_clients_of_the_project_are_there(registry: object) -> None:
    assert registry.names() == (  # type: ignore[attr-defined]
        "azure",
        "forcepoint",
        "forticlient",
        "globalprotect",
        "iap",
        "ivanti",
        "openvpn",
        "wireguard",
    )


def test_nobody_promises_automation_that_has_not_been_checked(registry: object) -> None:
    """La regla de entrada del proyecto, comprobada y no solo escrita.

    Si este test falla es porque alguien ha declarado CONNECT o DISCONNECT. Lo
    que hay que mirar entonces no es el test: es si esa orden se ha ejecutado
    de verdad en un puesto y si la version esta anotada en docs/CONECTORES.md.
    """
    for name in registry.names():  # type: ignore[attr-defined]
        connector = registry.get(name)  # type: ignore[attr-defined]

        assert connector.capabilities == frozenset({Capability.LAUNCH}), name


def test_every_registered_connector_can_do_what_it_declares(registry: object) -> None:
    for name in registry.names():  # type: ignore[attr-defined]
        assert registry.get(name).validate_declaration() == []  # type: ignore[attr-defined]


def test_every_provider_says_what_is_left_to_check() -> None:
    """Un pendiente sin explicar se convierte en un pendiente para siempre."""
    for provider in PROVIDERS:
        assert provider.pending, provider.name
        assert provider.display_name


def test_the_names_have_no_surprises() -> None:
    """Casan con `Profile.connector` del catalogo, asi que nada de mayusculas ni espacios."""
    for provider in PROVIDERS:
        assert provider.name == provider.name.lower()
        assert " " not in provider.name


def test_the_example_catalog_only_names_connectors_that_exist() -> None:
    """Un perfil que nombra un conector inexistente se queda sin botones."""
    example = Path(__file__).resolve().parents[2] / "docs" / "profiles.example.json"
    catalog = json.loads(example.read_text(encoding="utf-8"))
    known = {provider.name for provider in PROVIDERS}

    for profile in catalog["profiles"]:
        assert profile["connector"] in known, profile["id"]


def test_the_registry_can_be_built_twice_without_clashing() -> None:
    """Registrar dos veces el mismo nombre revienta, y eso esta bien: aqui no pasa."""
    build_registry(NullLauncher())
    build_registry(NullLauncher())


# --------------------------------------------------------------------------
# Donde esta instalado cada cliente
# --------------------------------------------------------------------------


def provider_named(name: str) -> Provider:
    return PROVIDERS_BY_NAME[name]


def test_detect_returns_the_candidate_that_exists() -> None:
    """La gracia es no tener que teclear la ruta a mano."""
    ivanti = provider_named("ivanti")
    installed = ivanti.candidates[2]

    assert detect(ivanti, exists=lambda path: path == installed) == installed


def test_detect_prefers_the_first_candidate_when_several_exist() -> None:
    """El orden de la lista es la preferencia: lo mas moderno primero."""
    openvpn = provider_named("openvpn")

    assert detect(openvpn, exists=lambda path: True) == openvpn.candidates[0]


def test_detect_returns_nothing_when_the_client_is_not_installed() -> None:
    """Sin nada instalado se devuelve None, no la primera candidata.

    Rellenar el formulario con una ruta que no existe seria peor que dejarlo
    vacio: el perfil se guardaria y fallaria al pulsarlo.
    """
    assert detect(provider_named("wireguard"), exists=lambda path: False) is None


def test_detect_returns_nothing_for_a_provider_without_candidates() -> None:
    """Forcepoint no tiene ninguna: nadie ha mirado donde se instala."""
    assert provider_named("forcepoint").candidates == ()
    assert detect(provider_named("forcepoint"), exists=lambda path: True) is None


def test_an_msix_is_offered_without_looking_at_the_disk() -> None:
    """Una app de Store no tiene ruta que comprobar."""
    azure = provider_named("azure")

    assert azure.launch_kind is LaunchKind.MSIX
    assert detect(azure, exists=lambda path: False) == azure.candidates[0]


def test_every_exe_candidate_would_pass_the_launch_validation() -> None:
    """Una candidata que el modelo rechazaria no serviria de nada.

    Rutas absolutas, sin recursos de red y terminadas en .exe: si alguna se
    escribe mal, el formulario la rellenaria y despues no dejaria guardar.
    """
    for provider in PROVIDERS:
        if provider.launch_kind is not LaunchKind.EXE:
            continue
        for candidate in provider.candidates:
            spec = LaunchSpec(kind=LaunchKind.EXE, target=candidate)
            assert spec.validate() == [], f"{provider.name}: {candidate}"


def test_every_msix_candidate_would_pass_the_launch_validation() -> None:
    for provider in PROVIDERS:
        if provider.launch_kind is not LaunchKind.MSIX:
            continue
        for candidate in provider.candidates:
            spec = LaunchSpec(kind=LaunchKind.MSIX, target=candidate)
            assert spec.validate() == [], f"{provider.name}: {candidate}"


def test_every_provider_is_reachable_by_name() -> None:
    """El desplegable de la interfaz se construye con esto."""
    assert set(PROVIDERS_BY_NAME) == {provider.name for provider in PROVIDERS}
    assert len(PROVIDERS_BY_NAME) == len(PROVIDERS)
