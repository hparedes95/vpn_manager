"""El nucleo tiene que poder testearse en CI sobre Linux, sin cliente VPN.

Esa regla de CLAUDE.md solo se sostiene si algo la comprueba: un `import
winreg` colado en `core/` no falla en Windows, falla el dia que alguien
lanza los tests en el runner. Aqui se lee el AST de cada modulo de `core/`
y se miran sus imports, sin importar los modulos (importarlos ya seria
ejecutarlos).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[2] / "src" / "vpnmanager" / "core"

# Modulos que atan el nucleo a Windows, a la red o a un proceso externo.
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

# Las dependencias apuntan hacia el nucleo, nunca al reves.
FORBIDDEN_SIBLINGS = frozenset({"connectors", "net", "security", "service", "ui"})

CORE_MODULES = sorted(CORE.rglob("*.py"))


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
    """Modulos del propio paquete a los que apunta cada import, absoluto o relativo."""
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
                # `from ..net import routes`: sale de core/ hacia una hermana.
                targets.update(
                    node.module.split(".")[0] if node.module else alias.name for alias in node.names
                )
    return targets


def test_core_package_exists() -> None:
    """Si `core/` se mueve, los tests de abajo pasarian por vacios."""
    assert CORE.is_dir()
    assert CORE_MODULES, f"no hay modulos que revisar en {CORE}"


# Los dos tests siguientes prueban al guardian, no al nucleo: un test que solo
# sabe decir que si no vigila nada.


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
        "from vpnmanager.connectors.base import Connector",
        "from ..net import routes",
        "from .. import service",
    ],
)
def test_guard_detects_dependencies_on_outer_layers(source: str) -> None:
    assert internal_targets(ast.parse(source)) & FORBIDDEN_SIBLINGS


@pytest.mark.parametrize(
    "source",
    [
        "import dataclasses",
        "from enum import Enum, auto",
        "from __future__ import annotations",
        "from .models import Profile",  # relativo dentro de core/: permitido
        "import vpnmanager",
    ],
)
def test_guard_accepts_what_the_core_may_import(source: str) -> None:
    tree = ast.parse(source)

    assert not imported_roots(tree) & FORBIDDEN_MODULES
    assert not internal_targets(tree) & FORBIDDEN_SIBLINGS


@pytest.mark.parametrize("module_path", CORE_MODULES, ids=lambda p: p.name)
def test_core_module_imports_nothing_platform_specific(module_path: Path) -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    offenders = imported_roots(tree) & FORBIDDEN_MODULES

    assert not offenders, (
        f"{module_path.name} importa {sorted(offenders)}: el nucleo debe poder "
        f"testearse en CI sobre Linux y sin tocar red"
    )


@pytest.mark.parametrize("module_path", CORE_MODULES, ids=lambda p: p.name)
def test_core_module_does_not_depend_on_outer_layers(module_path: Path) -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    offenders = internal_targets(tree) & FORBIDDEN_SIBLINGS

    assert not offenders, (
        f"{module_path.name} depende de {sorted(offenders)}: las capas de fuera "
        f"importan el nucleo, no al reves"
    )
