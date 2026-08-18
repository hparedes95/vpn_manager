"""Tests de la version que se esta ejecutando.

Existe por una razon practica: durante las pruebas se instalan builds una
detras de otra, y «¿esto lleva ya el arreglo?» tenia que contestarse mirando la
fecha del .exe. Lo que se protege aqui es que nunca se invente una version y
que nunca reviente por leerla.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vpnmanager.version import MAX_LENGTH, UNKNOWN, read_version, version_path


def test_it_reads_the_version_from_the_file(tmp_path: Path) -> None:
    target = tmp_path / "VERSION"
    target.write_text("0.1.0-dev+c3910c9", encoding="utf-8")

    assert read_version(target) == "0.1.0-dev+c3910c9"


def test_surrounding_whitespace_does_not_count(tmp_path: Path) -> None:
    """El empaquetado puede dejar un salto de linea al final."""
    target = tmp_path / "VERSION"
    target.write_text("  1.2.3\n", encoding="utf-8")

    assert read_version(target) == "1.2.3"


def test_only_the_first_line_is_used(tmp_path: Path) -> None:
    target = tmp_path / "VERSION"
    target.write_text("1.2.3\nlo que sea\n", encoding="utf-8")

    assert read_version(target) == "1.2.3"


def test_without_the_file_it_says_it_does_not_know(tmp_path: Path) -> None:
    """Ejecutando desde el repositorio no hay fichero, y no se inventa uno."""
    assert read_version(tmp_path / "no-existe") == UNKNOWN


@pytest.mark.parametrize("content", ["", "   ", "\n\n"])
def test_an_empty_file_says_it_does_not_know(tmp_path: Path, content: str) -> None:
    target = tmp_path / "VERSION"
    target.write_text(content, encoding="utf-8")

    assert read_version(target) == UNKNOWN


def test_something_that_is_not_a_version_is_not_used(tmp_path: Path) -> None:
    """Esto acaba en el titulo de una ventana: no puede ser cualquier cosa."""
    target = tmp_path / "VERSION"
    target.write_text("x" * (MAX_LENGTH + 1), encoding="utf-8")

    assert read_version(target) == UNKNOWN


def test_a_version_right_at_the_limit_is_used(tmp_path: Path) -> None:
    target = tmp_path / "VERSION"
    target.write_text("x" * MAX_LENGTH, encoding="utf-8")

    assert read_version(target) == "x" * MAX_LENGTH


def test_a_directory_where_the_file_should_be_does_not_raise(tmp_path: Path) -> None:
    """Leer la version no puede impedir que la aplicacion arranque."""
    target = tmp_path / "VERSION"
    target.mkdir()

    assert read_version(target) == UNKNOWN


def test_bytes_that_are_not_text_do_not_raise(tmp_path: Path) -> None:
    target = tmp_path / "VERSION"
    target.write_bytes(b"\xff\xfe\x00 no es utf-8")

    assert read_version(target) == UNKNOWN


def test_the_default_path_is_inside_the_package() -> None:
    """Sin empaquetar se busca junto al modulo."""
    assert version_path().name == "VERSION"
    assert version_path().parent.name == "vpnmanager"


def test_running_from_the_repository_reports_development() -> None:
    """Aqui no hay bundle, asi que no puede haber otra respuesta."""
    assert read_version() == UNKNOWN
