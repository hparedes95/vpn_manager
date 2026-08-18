"""Que version se esta ejecutando.

Existe por una razon muy concreta: durante las pruebas se instalan builds una
detras de otra, y cuando algo falla la primera pregunta —«¿esto lleva ya el
arreglo?»— no tenia respuesta. Se contestaba mirando la fecha del .exe, que es
adivinar.

El valor lo escribe el empaquetado en un fichero `VERSION` que viaja dentro del
bundle. En una build de CI lleva el hash corto del commit
(`0.1.0-dev+c3910c9`), asi que identifica exactamente que codigo hay instalado.

Ejecutando desde el repositorio no hay fichero y no se inventa uno: se dice
`desarrollo`, que es la verdad.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

UNKNOWN: Final = "desarrollo"

# Una version es corta. Si lo que hay en el fichero no lo es, no es una version:
# es otra cosa, y no va a acabar en el titulo de una ventana ni en el log.
MAX_LENGTH: Final = 64


def read_version(path: Path | None = None) -> str:
    """La version, o `desarrollo` si no se puede saber.

    Nunca falla ni lanza: esto se llama al pintar una ventana y al arrancar el
    servicio, y quedarse sin arrancar por no saber la version seria absurdo.
    """
    target = version_path() if path is None else path
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return UNKNOWN

    first = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    if not first or len(first) > MAX_LENGTH:
        return UNKNOWN
    return first


def version_path() -> Path:
    """Donde queda el fichero, empaquetado y sin empaquetar.

    Con PyInstaller el paquete vive dentro del archivo comprimido, asi que
    `__file__` no sirve para encontrar un fichero de datos: hay que ir al
    directorio que el propio bundle desempaqueta, que en `onedir` es
    `_internal`.
    """
    base = getattr(sys, "_MEIPASS", None)
    if base is not None:
        return Path(base) / "vpnmanager" / "VERSION"
    return Path(__file__).resolve().parent / "VERSION"
