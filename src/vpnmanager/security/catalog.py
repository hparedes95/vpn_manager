"""Carga y verificacion del catalogo firmado.

El catalogo define que binario ejecuta un servicio que corre en SYSTEM. Si un
usuario sin privilegios pudiera influir en su contenido, tendria ejecucion como
SYSTEM en su puesto. De ahi que el fichero viva en `%ProgramData%\\VpnManager`
con escritura solo para Administradores y SYSTEM, y de ahi la firma.

Tres decisiones:

**No se parsea nada sin verificar antes.** La firma se comprueba sobre los
bytes tal cual llegaron, y solo si valida se mira lo que hay dentro. Asi el
parser —que es el codigo mas complicado de este modulo— nunca ve datos que no
esten firmados.

**La firma es detached.** Va aparte, no dentro del JSON. Si fuera un campo mas
habria que decidir como se serializa el resto para firmarlo, y cualquier
diferencia de espacios o de orden de claves entre quien firma y quien verifica
se convierte en un fallo intermitente imposible de depurar.

**O carga todo o no carga nada.** Lo dice CLAUDE.md para la firma, y aqui se
aplica tambien a un perfil mal escrito. Un catalogo a medias deja al usuario
sin encontrar su VPN sin que nadie sepa por que, y deja al arbitro con
sesiones vivas cuyo perfil ya no existe, que es justo el estado incoherente
del que tiene que defenderse. Un rechazo entero es ruidoso y se arregla en una
tarde; media carga silenciosa se diagnostica en una semana.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol

from vpnmanager.core.models import (
    DisconnectStrategy,
    LaunchKind,
    LaunchSpec,
    Profile,
    TunnelType,
)

CATALOG_VERSION: Final = 1

_TOP_LEVEL_KEYS: Final = frozenset({"version", "profiles"})
_PROFILE_KEYS: Final = frozenset(
    {
        "id",
        "display_name",
        "connector",
        "launch",
        "tunnel_type",
        "target_networks",
        "probe_ip",
        "dns",
        "routes",
        "post_connect_apps",
        "expected_client_version",
        "breaks_local_connectivity",
        "disconnect_strategy",
        "notes",
    }
)
_LAUNCH_KEYS: Final = frozenset({"kind", "target", "args"})


class CatalogVerifier(Protocol):
    """Quien sabe decir si esos bytes los firmo quien tenia que firmarlos.

    Se inyecta porque el esquema todavia no esta decidido: firma detached con
    la clave del certificado de firma de codigo, Authenticode sobre el fichero,
    u otra cosa. Lo que no cambia es el contrato: bytes y firma entran, un si o
    un no sale. Nada de "valida a medias".
    """

    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class RejectingVerifier:
    """Verificador por defecto: no da por buena ninguna firma.

    Falla cerrado a proposito. Si el servicio arranca sin configurar un
    verificador de verdad, el resultado es que no se carga ningun perfil, no
    que se carguen todos sin comprobar.
    """

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return False


@dataclass(frozen=True)
class CatalogLoad:
    """Resultado de cargar el catalogo. Con incidencias, no hay perfiles."""

    profiles: tuple[Profile, ...] = ()
    issues: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.issues

    def as_catalog(self) -> dict[str, Profile]:
        """Los perfiles indexados por id, como los espera el arbitro."""
        return {profile.id: profile for profile in self.profiles}


class _FieldError(Exception):
    """Problema de forma en el JSON. Interno: sale como incidencia, no sube."""


def load_catalog(
    payload: bytes,
    signature: bytes,
    verifier: CatalogVerifier | None = None,
) -> CatalogLoad:
    """Verifica la firma y, solo entonces, lee el catalogo.

    Nunca lanza: devuelve las incidencias para que el servicio las registre y
    siga vivo sin ningun perfil. Un servicio caido no se puede diagnosticar en
    remoto; uno vivo que dice por que no tiene perfiles, si.
    """
    checker = RejectingVerifier() if verifier is None else verifier
    if not checker.verify(payload, signature):
        return CatalogLoad(issues=("la firma del catalogo no valida: no se carga ningun perfil",))

    try:
        data = _top_level(payload)
    except _FieldError as error:
        return CatalogLoad(issues=(str(error),))

    profiles: list[Profile] = []
    issues: list[str] = []
    for index, entry in enumerate(data):
        profile, entry_issues = _read_profile(entry, index)
        issues.extend(entry_issues)
        if profile is not None:
            profiles.append(profile)

    issues.extend(_duplicate_issues(profiles))
    if issues:
        # O todo o nada: ver la explicacion de arriba.
        return CatalogLoad(issues=tuple(issues))
    return CatalogLoad(profiles=tuple(profiles))


def _top_level(payload: bytes) -> list[object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _FieldError("el catalogo no es UTF-8 valido") from error

    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as error:
        raise _FieldError(f"el catalogo no es JSON valido: {error.msg}") from error

    if not isinstance(parsed, dict):
        raise _FieldError("el catalogo debe ser un objeto JSON")

    _check_keys(parsed, _TOP_LEVEL_KEYS, "el catalogo")
    version = parsed.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise _FieldError("falta la version del catalogo o tiene un tipo que no toca")
    if version != CATALOG_VERSION:
        raise _FieldError(f"version de catalogo incompatible: se esperaba {CATALOG_VERSION}")

    entries = parsed.get("profiles")
    if not isinstance(entries, list):
        raise _FieldError("el catalogo debe traer una lista 'profiles'")
    return list(entries)


def _read_profile(entry: object, index: int) -> tuple[Profile | None, list[str]]:
    """Un perfil del catalogo, o las razones por las que no lo es."""
    where = f"perfil[{index}]"
    try:
        data = _as_object(entry, where)
        _check_keys(data, _PROFILE_KEYS, where)
        profile = Profile(
            id=_string(data, "id", where),
            display_name=_string(data, "display_name", where),
            connector=_string(data, "connector", where),
            launch=_launch_spec(data.get("launch"), f"{where}.launch"),
            tunnel_type=_enum(data, "tunnel_type", TunnelType, where),
            target_networks=_strings(data, "target_networks", where),
            probe_ip=_optional_string(data, "probe_ip", where),
            dns=_strings(data, "dns", where),
            routes=_strings(data, "routes", where),
            post_connect_apps=tuple(
                _launch_spec(item, f"{where}.post_connect_apps[{position}]")
                for position, item in enumerate(_list(data, "post_connect_apps", where))
            ),
            expected_client_version=_optional_string(data, "expected_client_version", where),
            breaks_local_connectivity=_boolean(data, "breaks_local_connectivity", where),
            disconnect_strategy=_enum(
                data,
                "disconnect_strategy",
                DisconnectStrategy,
                where,
                default=DisconnectStrategy.NONE,
            ),
            notes=_string(data, "notes", where, default=""),
        )
    except _FieldError as error:
        return None, [str(error)]

    # La forma es correcta; ahora el contenido. Estas si salen todas juntas.
    name = profile.id or where
    return profile, [f"{name}: {issue}" for issue in profile.validate()]


def _duplicate_issues(profiles: list[Profile]) -> list[str]:
    """Dos perfiles con el mismo id harian que uno tapase al otro en silencio."""
    seen: set[str] = set()
    duplicated: list[str] = []
    for profile in profiles:
        if profile.id in seen and profile.id not in duplicated:
            duplicated.append(profile.id)
        seen.add(profile.id)
    return [f"el id '{profile_id}' esta repetido en el catalogo" for profile_id in duplicated]


# --------------------------------------------------------------------------
# Lectores. Cada uno dice donde estaba el problema, nunca que valor traia:
# el catalogo no deberia llevar secretos, pero el log tampoco es sitio para
# volcar lo que alguien haya metido en un campo.
# --------------------------------------------------------------------------


def _as_object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _FieldError(f"{where}: deberia ser un objeto JSON")
    return dict(value)


def _check_keys(data: Mapping[str, object], allowed: frozenset[str], where: str) -> None:
    unexpected = sorted(set(data) - allowed)
    if unexpected:
        raise _FieldError(f"{where}: campos que no existen: {', '.join(unexpected)}")


def _string(data: Mapping[str, object], key: str, where: str, default: str | None = None) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise _FieldError(f"{where}.{key}: falta o no es una cadena")
    return value


def _optional_string(data: Mapping[str, object], key: str, where: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _FieldError(f"{where}.{key}: deberia ser una cadena o estar ausente")
    return value


def _boolean(data: Mapping[str, object], key: str, where: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise _FieldError(f"{where}.{key}: deberia ser booleano")
    return value


def _list(data: Mapping[str, object], key: str, where: str) -> list[object]:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise _FieldError(f"{where}.{key}: deberia ser una lista")
    return list(value)


def _strings(data: Mapping[str, object], key: str, where: str) -> tuple[str, ...]:
    values = _list(data, key, where)
    if not all(isinstance(item, str) for item in values):
        raise _FieldError(f"{where}.{key}: deberia ser una lista de cadenas")
    return tuple(item for item in values if isinstance(item, str))


def _enum[T: Enum](
    data: Mapping[str, object],
    key: str,
    enum: type[T],
    where: str,
    default: T | None = None,
) -> T:
    value = data.get(key)
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise _FieldError(f"{where}.{key}: falta o no es una cadena")
    try:
        return enum(value)
    except ValueError as error:
        admitted = ", ".join(sorted(member.value for member in enum))
        raise _FieldError(f"{where}.{key}: valor no admitido. Admite: {admitted}") from error


def _launch_spec(value: object, where: str) -> LaunchSpec:
    data = _as_object(value, where)
    _check_keys(data, _LAUNCH_KEYS, where)
    return LaunchSpec(
        kind=_enum(data, "kind", LaunchKind, where),
        target=_string(data, "target", where),
        args=_strings(data, "args", where),
    )
