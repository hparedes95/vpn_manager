"""Reune el diagnostico del puesto. Lo que antes se pedia comando a comando.

La parte que decide como se cuenta esta en `core/diagnostics.py` y se prueba en
CI. Aqui esta la que va a buscar los datos, que si toca Windows: mirar si un
fichero existe, si el pipe esta ahi, que devuelven los scripts.

Todo entra por parametro (`Probe`), asi que el recorrido entero —incluido lo
que pasa cuando algo revienta a mitad— tambien se prueba sin un puesto delante.

**Ninguna comprobacion cambia nada.** Se mira y se cuenta: no se arranca
ningun cliente, no se toca la red y no se escribe el catalogo. Un diagnostico
que modifica lo que esta diagnosticando no sirve para nada.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from vpnmanager.core.diagnostics import Check, Report
from vpnmanager.core.models import LaunchKind, Profile


class Probe(Protocol):
    """Lo que hay que saber preguntarle a la maquina."""

    def exists(self, path: str) -> bool:
        """Si hay un fichero ahi."""

    def pipe_is_there(self) -> bool | None:
        """Si el servicio esta escuchando. `None` si no se pudo mirar."""

    def read_catalog(self) -> tuple[Sequence[Profile], Sequence[str]]:
        """Los perfiles y las incidencias del catalogo instalado."""

    def path_entries_removed(self) -> int | None:
        """Cuantas entradas del PATH se le quitan a un cliente al lanzarlo."""

    def detected_clients(self) -> Sequence[tuple[str, str]]:
        """Que clientes VPN hay instalados, como (nombre, ruta)."""


@dataclass(frozen=True)
class Layout:
    """Donde deberia estar cada cosa. Sale de como instala el .exe."""

    service_exe: str
    ui_exe: str
    scripts_dir: str


DEFAULT_LAYOUT = Layout(
    service_exe=r"C:\Program Files\VpnManager\svc\vpnmgr-svc.exe",
    ui_exe=r"C:\Program Files\VpnManager\ui\vpnmgr-ui.exe",
    scripts_dir=r"C:\Program Files\VpnManager\svc\_internal\vpnmanager\net\ps",
)

SCRIPTS = ("Get-NetState.ps1", "Restore-NetState.ps1", "Test-TunnelState.ps1")


def collect(
    version: str,
    probe: Probe,
    layout: Layout = DEFAULT_LAYOUT,
) -> Report:
    """Todas las comprobaciones, en el orden en que se descartan capas.

    Una que reviente no puede llevarse el informe por delante: sale como «no se
    pudo comprobar» y se sigue. Un diagnostico a medias vale mucho mas que una
    traza.
    """
    checks: list[Check] = []
    for name, run in _all_checks(probe, layout):
        checks.append(_safely(name, run))
    return Report(version=version, checks=tuple(checks), notes=_notes())


def _all_checks(
    probe: Probe, layout: Layout
) -> list[tuple[str, Callable[[], tuple[bool | None, str]]]]:
    return [
        ("Ejecutables instalados", lambda: _executables(probe, layout)),
        ("Scripts de red presentes", lambda: _scripts(probe, layout)),
        ("El servicio esta escuchando", lambda: _pipe(probe)),
        ("Catalogo de VPN", lambda: _catalog(probe)),
        ("Los clientes del catalogo estan instalados", lambda: _targets(probe)),
        ("Clientes VPN detectados en el equipo", lambda: _detected(probe)),
        ("El PATH que se le pasa a un cliente", lambda: _path(probe)),
    ]


def _safely(name: str, run: Callable[[], tuple[bool | None, str]]) -> Check:
    try:
        ok, detail = run()
    except Exception as error:
        return Check(name=name, ok=None, detail=f"no se pudo comprobar: {error!r}")
    return Check(name=name, ok=ok, detail=detail)


def _executables(probe: Probe, layout: Layout) -> tuple[bool | None, str]:
    missing = [path for path in (layout.service_exe, layout.ui_exe) if not probe.exists(path)]
    if missing:
        return False, "no estan: " + ", ".join(missing)
    return True, "servicio e interfaz en su sitio"


def _scripts(probe: Probe, layout: Layout) -> tuple[bool | None, str]:
    missing = [name for name in SCRIPTS if not probe.exists(f"{layout.scripts_dir}\\{name}")]
    if missing:
        return False, "faltan: " + ", ".join(missing)
    return True, f"{len(SCRIPTS)} scripts en {layout.scripts_dir}"


def _pipe(probe: Probe) -> tuple[bool | None, str]:
    there = probe.pipe_is_there()
    if there is None:
        return None, "no se pudo mirar la lista de pipes"
    if not there:
        # `Running` no significa escuchando: el Administrador de servicios da
        # por arrancado a un proceso que se registro a tiempo, y lo que pase
        # despues dentro no lo mira nadie.
        return False, "no existe \\\\.\\pipe\\vpnmgr: el servicio no esta atendiendo"
    return True, "\\\\.\\pipe\\vpnmgr existe"


def _catalog(probe: Probe) -> tuple[bool | None, str]:
    profiles, issues = probe.read_catalog()
    if issues:
        # El catalogo es todo o nada: una errata deja el equipo sin ninguna VPN.
        return False, f"{len(issues)} incidencia(s): " + "; ".join(issues)
    if not profiles:
        return False, "no hay ningun perfil"
    return True, f"{len(profiles)} perfil(es): " + ", ".join(p.id for p in profiles)


def _targets(probe: Probe) -> tuple[bool | None, str]:
    """Si el .exe de cada perfil esta donde dice el catalogo.

    Es el fallo mas probable y el mas confuso de todos: el servicio manda la
    orden, la interfaz intenta arrancar un binario que no esta, y sin esto lo
    unico que se ve es que no pasa nada.
    """
    profiles, _ = probe.read_catalog()
    missing = [
        f"{profile.id} → {profile.launch.target}"
        for profile in profiles
        # Una app de Store no tiene ruta que mirar: la resuelve el shell.
        if profile.launch.kind is LaunchKind.EXE and not probe.exists(profile.launch.target)
    ]
    if not profiles:
        return None, "sin perfiles que comprobar"
    if missing:
        return False, "no estan instalados donde dice el catalogo: " + "; ".join(missing)
    return True, "todos los ejecutables del catalogo existen"


def _detected(probe: Probe) -> tuple[bool | None, str]:
    """Que clientes hay en la maquina, para poder corregir una ruta mala.

    No decide nada: es informacion. Si el catalogo apunta a una ruta que no
    existe, esta linea dice donde esta el cliente de verdad, y con eso se
    corrige en el editor sin buscar nada a mano.
    """
    found = probe.detected_clients()
    if not found:
        return None, "no se ha encontrado ninguno en las rutas habituales"
    return True, "; ".join(f"{name} → {path}" for name, path in found)


def _path(probe: Probe) -> tuple[bool | None, str]:
    removed = probe.path_entries_removed()
    if removed is None:
        return None, "no se pudo calcular"
    if removed == 0:
        return True, "no habia nada nuestro que quitar"
    return True, (
        f"se le quitan {removed} entrada(s) que apuntan a VPN Manager. "
        f"Sin esto, un cliente puede cargar nuestras DLL en vez de las suyas"
    )


def _notes() -> tuple[str, ...]:
    return (
        "Ninguna comprobacion cambia nada: no arranca clientes ni toca la red.",
        "Si algo sale FALLA o ?, ese texto es lo unico que hace falta enviar.",
    )
