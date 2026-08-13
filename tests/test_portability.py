"""Los modulos puros tienen que poder testearse en CI sobre Linux.

Sin cliente VPN, sin Windows y sin red. Esa regla solo se sostiene si algo la
comprueba: un `import winreg` colado en `core/` no falla en Windows, falla el
dia que alguien lanza los tests en el runner, o peor, el dia que hay que
depurar el nucleo sin un puesto delante.

Se lee el AST de cada modulo y se miran sus imports. No se importan: importar
un modulo es ejecutarlo, y eso es justo lo que no queremos aqui.

Modulos vigilados:

- todo `core/`, que es logica pura por definicion.
- `connectors/base.py`, que define la interfaz y el conector minimo. Lo
  concreto de cada proveedor podra depender de Windows; el contrato no.
- `security/catalog.py`, que lee y valida el catalogo firmado. Leer el fichero
  de `%ProgramData%` con su ACL es del servicio; entender lo que pone, no, y
  ese parser es el que mas falta hace poder machacar a tests.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "vpnmanager"
CORE = SRC / "core"
CONNECTOR_BASE = SRC / "connectors" / "base.py"
CATALOG = SRC / "security" / "catalog.py"

# Modulos que atan un modulo puro a Windows, a la red o a un proceso externo.
FORBIDDEN_MODULES = frozenset(
    {
        "winreg",
        "msvcrt",
        "ctypes",
        "win32api",
        "win32com",
        "win32con",
        "win32event",
        "win32file",
        "win32service",
        "win32serviceutil",
        "pywintypes",
        "servicemanager",
        "wmi",
        "pythoncom",
        "subprocess",
        "socket",
        "ssl",
        "http",
        "urllib",
        "PySide6",
    }
)

# Capas de fuera. Las dependencias apuntan hacia el nucleo, nunca al reves,
# y ninguna capa puede depender de otra que este a su mismo nivel.
LAYERS = frozenset({"connectors", "net", "security", "service", "ui"})

PURE_MODULES = [*sorted(CORE.rglob("*.py")), CONNECTOR_BASE, CATALOG]


def module_id(path: Path) -> str:
    return str(path.relative_to(SRC))


def forbidden_layers_for(path: Path) -> frozenset[str]:
    """Todas las capas menos la suya: un modulo si puede mirar a sus vecinos."""
    return LAYERS - {path.relative_to(SRC).parts[0]}


def imported_roots(tree: ast.AST) -> set[str]:
    """Primer segmento de cada import: `os.path` -> `os`."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def internal_targets(tree: ast.AST) -> set[str]:
    """Capas del propio paquete a las que apunta cada import, absoluto o relativo."""
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "vpnmanager" and len(parts) > 1:
                    targets.add(parts[1])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                parts = node.module.split(".")
                if parts[0] == "vpnmanager" and len(parts) > 1:
                    targets.add(parts[1])
            elif node.level >= 2:
                # `from ..net import routes`: sale de la propia capa.
                targets.update(
                    node.module.split(".")[0] if node.module else alias.name for alias in node.names
                )
    return targets


def test_the_modules_under_watch_exist() -> None:
    """Si algo se mueve de sitio, los tests de abajo pasarian por vacios."""
    assert CORE.is_dir()
    assert CONNECTOR_BASE.is_file()
    assert CATALOG.is_file()
    assert len(PURE_MODULES) >= 3


# Los tres tests siguientes prueban al guardian, no al codigo: un guardian que
# no sabe detectar nada es un test que siempre pasa.


@pytest.mark.parametrize(
    "source",
    [
        "import winreg",
        "import os, subprocess",
        "import ctypes.wintypes",
        "from socket import gethostbyname",
        "from PySide6.QtWidgets import QApplication",
    ],
)
def test_guard_detects_platform_imports(source: str) -> None:
    assert imported_roots(ast.parse(source)) & FORBIDDEN_MODULES


@pytest.mark.parametrize(
    "source",
    [
        "import vpnmanager.net",
        "from vpnmanager.net import routes",
        "from vpnmanager.service.pipe import PipeServer",
        "from ..net import routes",
        "from .. import service",
    ],
)
def test_guard_detects_dependencies_on_other_layers(source: str) -> None:
    assert internal_targets(ast.parse(source)) & LAYERS


@pytest.mark.parametrize(
    "source",
    [
        "import dataclasses",
        "from enum import Enum, auto",
        "from __future__ import annotations",
        "from .models import Profile",  # relativo dentro de la propia capa
        "from vpnmanager.core.models import Profile",  # hacia el nucleo
        "import vpnmanager",
    ],
)
def test_guard_accepts_what_a_pure_module_may_import(source: str) -> None:
    tree = ast.parse(source)

    assert not imported_roots(tree) & FORBIDDEN_MODULES
    assert not internal_targets(tree) & (LAYERS - {"connectors"})


# Y estos, al codigo.


@pytest.mark.parametrize("module_path", PURE_MODULES, ids=module_id)
def test_pure_module_imports_nothing_platform_specific(module_path: Path) -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    offenders = imported_roots(tree) & FORBIDDEN_MODULES

    assert not offenders, (
        f"{module_id(module_path)} importa {sorted(offenders)}: tiene que poder "
        f"testearse en CI sobre Linux y sin tocar red"
    )


@pytest.mark.parametrize("module_path", PURE_MODULES, ids=module_id)
def test_pure_module_does_not_depend_on_other_layers(module_path: Path) -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    offenders = internal_targets(tree) & forbidden_layers_for(module_path)

    assert not offenders, (
        f"{module_id(module_path)} depende de {sorted(offenders)}: las capas de "
        f"fuera importan el nucleo, no al reves"
    )
