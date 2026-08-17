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
from vpnmanager.connectors.providers import PROVIDERS, build_registry
from vpnmanager.core.models import Capability, LaunchSpec


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
