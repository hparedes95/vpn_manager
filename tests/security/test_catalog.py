"""Tests de la carga del catalogo firmado.

El catalogo decide que binario ejecuta un servicio en SYSTEM, asi que aqui se
prueban sobre todo las negativas: firma que no valida, JSON retorcido, campos
que no existen, ids repetidos. Y una que importa mas que todas: que con la
firma mal, el contenido ni se mira.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vpnmanager.core.models import (
    DisconnectStrategy,
    LaunchKind,
    LaunchSpec,
    Profile,
    TunnelType,
)
from vpnmanager.security.catalog import (
    CATALOG_VERSION,
    CatalogLoad,
    RejectingVerifier,
    dump_catalog,
    load_catalog,
)

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
SIGNATURE = b"firma-de-mentira"


class AcceptingVerifier:
    """Da por buena cualquier firma y anota que le dieron a verificar."""

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytes]] = []

    def verify(self, payload: bytes, signature: bytes) -> bool:
        self.calls.append((payload, signature))
        return True


class RecordingRejector:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytes]] = []

    def verify(self, payload: bytes, signature: bytes) -> bool:
        self.calls.append((payload, signature))
        return False


@pytest.fixture
def verifier() -> AcceptingVerifier:
    return AcceptingVerifier()


def profile_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": "wireguard-corp",
        "display_name": "WireGuard corporativa",
        "connector": "wireguard",
        "launch": {"kind": "exe", "target": WIREGUARD_EXE},
        "tunnel_type": "full",
        "probe_ip": "10.20.0.1",
    }
    entry.update(overrides)
    return entry


def catalog_bytes(*entries: object, version: object = CATALOG_VERSION) -> bytes:
    return json.dumps({"version": version, "profiles": list(entries)}).encode("utf-8")


def load(*entries: object, version: object = CATALOG_VERSION) -> CatalogLoad:
    return load_catalog(catalog_bytes(*entries, version=version), SIGNATURE, AcceptingVerifier())


# --------------------------------------------------------------------------
# La firma manda
# --------------------------------------------------------------------------


def test_a_signature_that_does_not_validate_loads_nothing() -> None:
    result = load_catalog(catalog_bytes(profile_entry()), SIGNATURE, RecordingRejector())

    assert not result.ok
    assert result.profiles == ()
    assert "la firma del catalogo no valida" in result.issues[0]


def test_the_content_is_not_even_parsed_when_the_signature_fails() -> None:
    """El parser es el codigo mas delicado de aqui: no ve datos sin firmar."""
    result = load_catalog(b"{ esto no es JSON ni de lejos", SIGNATURE, RecordingRejector())

    assert len(result.issues) == 1
    assert "firma" in result.issues[0]
    assert "JSON" not in result.issues[0]


def test_the_verifier_gets_the_bytes_exactly_as_they_arrived() -> None:
    """Si se verificara algo reserializado, se estaria firmando otra cosa."""
    payload = catalog_bytes(profile_entry())
    verifier = AcceptingVerifier()

    load_catalog(payload, SIGNATURE, verifier)

    assert verifier.calls == [(payload, SIGNATURE)]


def test_without_a_verifier_nothing_loads() -> None:
    """Falla cerrado: olvidarse de configurarlo no carga un catalogo sin firmar."""
    result = load_catalog(catalog_bytes(profile_entry()), SIGNATURE)

    assert not result.ok
    assert result.profiles == ()


def test_the_default_verifier_rejects_everything() -> None:
    assert RejectingVerifier().verify(b"lo que sea", b"la firma que sea") is False


# --------------------------------------------------------------------------
# Un catalogo que si carga
# --------------------------------------------------------------------------


def test_a_minimal_catalog_loads() -> None:
    result = load(profile_entry())

    assert result.ok
    assert len(result.profiles) == 1
    assert result.profiles[0].id == "wireguard-corp"
    assert result.profiles[0].tunnel_type is TunnelType.FULL


def test_an_empty_catalog_is_valid() -> None:
    result = load()

    assert result.ok
    assert result.profiles == ()


def test_a_fully_populated_profile_loads() -> None:
    result = load(
        profile_entry(
            target_networks=["10.0.0.0/8"],
            dns=["10.0.0.53"],
            routes=["10.0.0.0/8"],
            post_connect_apps=[{"kind": "exe", "target": r"C:\Windows\System32\mstsc.exe"}],
            expected_client_version="0.5.3",
            breaks_local_connectivity=True,
            disconnect_strategy="cli",
            notes="tunel principal",
        )
    )

    assert result.ok
    profile = result.profiles[0]
    assert profile.routes == ("10.0.0.0/8",)
    assert profile.breaks_local_connectivity is True
    assert profile.disconnect_strategy is DisconnectStrategy.CLI
    assert profile.post_connect_apps[0].kind is LaunchKind.EXE
    assert profile.notes == "tunel principal"


def test_the_optional_fields_take_the_conservative_default() -> None:
    """Lo que no se dice en el catalogo no se da por concedido."""
    profile = load(profile_entry()).profiles[0]

    assert profile.breaks_local_connectivity is False
    assert profile.disconnect_strategy is DisconnectStrategy.NONE
    assert profile.expected_client_version is None
    assert profile.launch.args == ()
    assert profile.notes == ""


def test_launch_arguments_are_read_as_a_list() -> None:
    profile = load(
        profile_entry(launch={"kind": "exe", "target": WIREGUARD_EXE, "args": ["/installtunnel"]})
    ).profiles[0]

    assert profile.launch.args == ("/installtunnel",)


def test_the_catalog_can_be_indexed_by_id() -> None:
    """Es la forma en la que lo esperan el arbitro y el servidor del pipe."""
    result = load(profile_entry(), profile_entry(id="split-b", tunnel_type="split"))

    assert sorted(result.as_catalog()) == ["split-b", "wireguard-corp"]


# --------------------------------------------------------------------------
# JSON que no vale
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"no soy json", "no es JSON valido"),
        (b"[]", "debe ser un objeto JSON"),
        (b'"una cadena"', "debe ser un objeto JSON"),
        (b"\xff\xfe", "no es UTF-8"),
    ],
)
def test_a_malformed_catalog_is_rejected(payload: bytes, expected: str) -> None:
    result = load_catalog(payload, SIGNATURE, AcceptingVerifier())

    assert not result.ok
    assert expected in result.issues[0]


@pytest.mark.parametrize("version", [0, 2])
def test_another_catalog_version_is_rejected(version: int) -> None:
    result = load(profile_entry(), version=version)

    assert not result.ok
    assert "version de catalogo incompatible" in result.issues[0]


@pytest.mark.parametrize("version", ["1", None, True, 1.0])
def test_a_version_with_the_wrong_type_is_rejected(version: object) -> None:
    """`True == 1` y `1.0 == 1`: comparar sin mirar el tipo dejaria pasar los dos."""
    result = load(profile_entry(), version=version)

    assert not result.ok
    assert "tipo que no toca" in result.issues[0]


def test_an_unknown_top_level_field_is_rejected() -> None:
    payload = json.dumps(
        {"version": CATALOG_VERSION, "profiles": [], "firmado_por": "yo mismo"}
    ).encode("utf-8")

    result = load_catalog(payload, SIGNATURE, AcceptingVerifier())

    assert not result.ok
    assert "firmado_por" in result.issues[0]


def test_profiles_has_to_be_a_list() -> None:
    payload = json.dumps({"version": CATALOG_VERSION, "profiles": {}}).encode("utf-8")

    result = load_catalog(payload, SIGNATURE, AcceptingVerifier())

    assert not result.ok
    assert "lista 'profiles'" in result.issues[0]


# --------------------------------------------------------------------------
# Perfiles que no valen
# --------------------------------------------------------------------------


def test_a_profile_that_is_not_an_object_is_rejected() -> None:
    result = load("wireguard-corp")

    assert not result.ok
    assert "perfil[0]" in result.issues[0]


def test_an_unknown_profile_field_is_rejected() -> None:
    """Un campo de mas suele ser una errata, y una errata en el catalogo se paga."""
    result = load(profile_entry(run_as="SYSTEM"))

    assert not result.ok
    assert "run_as" in result.issues[0]


def test_a_missing_required_field_is_rejected() -> None:
    entry = profile_entry()
    del entry["connector"]

    result = load(entry)

    assert not result.ok
    assert "connector" in result.issues[0]


def test_a_missing_launch_is_rejected() -> None:
    entry = profile_entry()
    del entry["launch"]

    result = load(entry)

    assert not result.ok
    assert "launch" in result.issues[0]


def test_an_unknown_field_inside_launch_is_rejected() -> None:
    result = load(profile_entry(launch={"kind": "exe", "target": WIREGUARD_EXE, "shell": True}))

    assert not result.ok
    assert "shell" in result.issues[0]


def test_an_unknown_enum_value_lists_the_admitted_ones() -> None:
    """Quien edita el catalogo tiene que poder arreglarlo sin abrir el codigo."""
    result = load(profile_entry(tunnel_type="completo"))

    assert not result.ok
    assert "full" in result.issues[0]
    assert "split" in result.issues[0]
    assert "app" in result.issues[0]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 42),
        ("display_name", None),
        ("routes", "10.0.0.0/8"),
        ("dns", [10]),
        ("breaks_local_connectivity", "si"),
        ("expected_client_version", 3),
        ("post_connect_apps", {"kind": "exe"}),
    ],
)
def test_a_field_with_the_wrong_type_is_rejected(field: str, value: object) -> None:
    result = load(profile_entry(**{field: value}))

    assert not result.ok
    assert field in result.issues[0]


def test_the_semantic_validation_of_the_profile_also_applies() -> None:
    """La forma es correcta y aun asi el perfil no vale: mismo filtro de siempre."""
    result = load(profile_entry(launch={"kind": "exe", "target": "wireguard.exe"}))

    assert not result.ok
    assert "wireguard-corp" in result.issues[0]
    assert "ruta absoluta" in result.issues[0]


def test_every_semantic_problem_of_a_profile_is_reported_at_once() -> None:
    result = load(profile_entry(probe_ip="no-es-una-ip", routes=["la-central"]))

    assert len(result.issues) == 2


def test_a_repeated_id_is_rejected() -> None:
    """Uno taparia al otro en silencio, y nadie sabria cual gano."""
    result = load(profile_entry(), profile_entry(display_name="La otra"))

    assert not result.ok
    assert "esta repetido" in result.issues[0]


# --------------------------------------------------------------------------
# O todo o nada
# --------------------------------------------------------------------------


def test_one_bad_profile_rejects_the_whole_catalog() -> None:
    """Media carga silenciosa se diagnostica en una semana; un rechazo, en una tarde.

    Ademas deja al arbitro con sesiones vivas cuyo perfil ya no existe, que es
    el estado incoherente del que tiene que defenderse.
    """
    result = load(
        profile_entry(),
        profile_entry(id="split-b", tunnel_type="split", routes=["esto-no-es-una-red"]),
        profile_entry(id="app-iap", tunnel_type="app"),
    )

    assert not result.ok
    assert result.profiles == ()


def test_the_issues_name_the_profile_that_caused_them() -> None:
    result = load(
        profile_entry(),
        profile_entry(id="split-b", tunnel_type="split", routes=["esto-no-es-una-red"]),
    )

    assert len(result.issues) == 1
    assert result.issues[0].startswith("split-b:")


def test_a_load_without_issues_is_the_only_one_that_is_ok() -> None:
    assert CatalogLoad().ok is True
    assert CatalogLoad(issues=("algo",)).ok is False


def test_the_documented_example_catalog_loads() -> None:
    """Un ejemplo que no carga es peor que no tener ejemplo.

    Quien escriba el catalogo de verdad va a partir de este fichero, asi que
    tiene que seguir valiendo cuando el esquema cambie.
    """
    example = Path(__file__).resolve().parents[2] / "docs" / "profiles.example.json"

    result = load_catalog(example.read_bytes(), SIGNATURE, AcceptingVerifier())

    assert result.issues == ()
    assert sorted(result.as_catalog()) == [
        "azure-cliente-c",
        "iap-produccion",
        "ivanti-cliente-b",
        "wireguard-central",
    ]


# --------------------------------------------------------------------------
# Escribir el catalogo, para el editor con privilegios
# --------------------------------------------------------------------------


def test_what_is_written_can_be_read_back() -> None:
    """Ida y vuelta: es lo que hace fiable escribir el catalogo desde una interfaz."""
    original = load(
        profile_entry(
            routes=["10.0.0.0/8"],
            dns=["10.0.0.53"],
            breaks_local_connectivity=True,
            disconnect_strategy="cli",
            notes="la de la central",
        )
    )

    written = dump_catalog(original.profiles)
    again = load_catalog(written, SIGNATURE, AcceptingVerifier())

    assert again.issues == ()
    assert again.profiles == original.profiles


def test_an_invalid_profile_is_never_written() -> None:
    """Guardar sin mirar dejaria el equipo sin VPN hasta que alguien leyera el log."""
    broken = Profile(
        id="roto",
        display_name="Roto",
        connector="wireguard",
        launch=LaunchSpec(kind=LaunchKind.EXE, target="wireguard.exe"),
        tunnel_type=TunnelType.FULL,
        probe_ip="10.20.0.1",
    )

    with pytest.raises(ValueError, match="ruta absoluta"):
        dump_catalog([broken])


def test_a_repeated_id_is_never_written() -> None:
    original = load(profile_entry()).profiles

    with pytest.raises(ValueError, match="repetido"):
        dump_catalog([*original, *original])


def test_only_what_is_not_the_default_is_written() -> None:
    """El fichero se lee a mano: no se llena de valores por defecto."""
    written = dump_catalog(load(profile_entry()).profiles).decode("utf-8")

    assert "breaks_local_connectivity" not in written
    assert "post_connect_apps" not in written
    assert "notes" not in written


def test_it_is_written_to_be_read_by_a_person() -> None:
    written = dump_catalog(load(profile_entry()).profiles).decode("utf-8")

    assert "\n" in written  # con sangrado, no en una sola linea
    assert written.startswith("{")


def test_an_empty_catalog_can_be_written() -> None:
    assert load_catalog(dump_catalog([]), SIGNATURE, AcceptingVerifier()).ok


def test_the_name_of_the_connection_inside_the_client_survives_a_round_trip() -> None:
    """Es lo que distingue tres tuneles del mismo FortiClient."""
    original = load(profile_entry(client_profile_name="Cliente B"))

    again = load_catalog(dump_catalog(original.profiles), SIGNATURE, AcceptingVerifier())

    assert again.issues == ()
    assert again.profiles[0].client_profile_name == "Cliente B"


def test_a_profile_without_the_name_of_the_connection_is_valid() -> None:
    """La mayoria de clientes tienen una sola conexion: el campo sobra."""
    catalog = load(profile_entry())

    assert catalog.issues == ()
    assert catalog.profiles[0].client_profile_name == ""
    assert "client_profile_name" not in dump_catalog(catalog.profiles).decode("utf-8")


def test_a_profile_without_a_witness_ip_loads() -> None:
    """Recien dado de alta desde la interfaz: todavia no se sabe que sondear.

    El catalogo es todo o nada, asi que rechazarlo aqui dejaria el equipo sin
    ninguna VPN por un perfil al que le falta un dato opcional.
    """
    catalog = load(profile_entry(probe_ip=None))

    assert catalog.issues == ()
    assert catalog.profiles[0].probe_ip is None
    assert not catalog.profiles[0].can_verify_state
