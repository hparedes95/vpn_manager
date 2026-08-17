"""El verificador de pruebas no puede colarse en un puesto de la empresa.

Con el puesto, el catalogo deja de estar protegido por una firma: quien pueda
escribir `profiles.json` elige que binario ejecuta un servicio que corre como
SYSTEM. En una VM de pruebas da igual; en el portatil de un compañero no.

Que se pida a mano y no por defecto es una promesa. Esto lo convierte en algo
que falla si alguien la rompe.
"""

from __future__ import annotations

import ast
from pathlib import Path

from vpnmanager.security.catalog import RejectingVerifier
from vpnmanager.security.unsafe_dev import UnsafeUnsignedCatalogVerifier
from vpnmanager.service.main import _verifier

SRC = Path(__file__).resolve().parents[2] / "src" / "vpnmanager"
UNSAFE_MODULE = "vpnmanager.security.unsafe_dev"

# El unico sitio del proyecto que puede nombrarlo: el arranque del servicio,
# y solo detras de la opcion explicita.
ALLOWED_TO_IMPORT_IT = {SRC / "service" / "main.py"}


def test_nothing_else_in_the_project_imports_it() -> None:
    offenders: list[str] = []
    for module in sorted(SRC.rglob("*.py")):
        if module in ALLOWED_TO_IMPORT_IT or module.name == "unsafe_dev.py":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.ImportFrom) and node.module == UNSAFE_MODULE) or (
                isinstance(node, ast.Import)
                and any(alias.name == UNSAFE_MODULE for alias in node.names)
            ):
                offenders.append(str(module.relative_to(SRC)))

    assert not offenders, f"el verificador de pruebas se ha colado en: {offenders}"


def test_by_default_nothing_unsigned_is_accepted() -> None:
    """Sin pedirlo a mano, el servicio no se fia de ningun catalogo."""
    assert isinstance(_verifier(allow_unsigned=False), RejectingVerifier)


def test_it_takes_asking_for_it_on_purpose() -> None:
    assert isinstance(_verifier(allow_unsigned=True), UnsafeUnsignedCatalogVerifier)


def test_its_own_name_says_what_it_is() -> None:
    """Quien lea un log o un `ps` tiene que ver que esa maquina no valida nada."""
    assert "Unsafe" in UnsafeUnsignedCatalogVerifier.__name__
