"""La `Probe` de verdad: la que mira el puesto.

Implementa el puerto de `diagnose.py`. Vive en `ui/` porque es la interfaz
quien ofrece el boton de diagnostico, y porque corre en la sesion del usuario,
que es donde se lanzan los clientes y por tanto donde tiene sentido mirar el
PATH que van a heredar.

**No cambia nada.** Mira ficheros, lista pipes y lee el catalogo. Ni arranca
clientes ni toca la red.

Cada metodo se traga sus errores y devuelve el «no se sabe» que corresponda. Un
diagnostico que revienta a la mitad no diagnostica nada, y justo se pide cuando
algo ya va mal.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from pathlib import Path

from vpnmanager.connectors.process import bundle_directories, clean_environment
from vpnmanager.connectors.providers import PROVIDERS, detect
from vpnmanager.core.models import LaunchKind, Profile
from vpnmanager.security.catalog import load_catalog

log = logging.getLogger("vpnmgr.ui")

CATALOG_PATH = Path(r"C:\ProgramData\VpnManager\profiles.json")
PIPE_DIRECTORY = "\\\\.\\pipe\\"
PIPE_NAME = "vpnmgr"


class _OwnAuthority:
    """Lee el catalogo sin comprobar la firma.

    Aqui no se ejecuta nada de lo que ponga: solo se cuenta cuantos perfiles
    hay y si sus ejecutables existen. Quien decide si un catalogo sin firmar se
    puede usar de verdad es el servicio, y esa decision no pasa por aqui.
    """

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return True


class WindowsProbe:
    """Lo que se le puede preguntar a un puesto sin tocarle nada."""

    def exists(self, path: str) -> bool:
        try:
            return Path(path).is_file()
        except OSError:
            return False

    def pipe_is_there(self) -> bool | None:
        """Si el servicio esta atendiendo de verdad.

        Es la comprobacion buena, y no `Get-Service`: el Administrador de
        servicios da por RUNNING a un proceso que se registro a tiempo, aunque
        despues se le haya caido todo por dentro.
        """
        try:
            return any(PIPE_NAME in name for name in os.listdir(PIPE_DIRECTORY))
        except OSError:
            return None

    def read_catalog(self) -> tuple[Sequence[Profile], Sequence[str]]:
        try:
            payload = CATALOG_PATH.read_bytes()
        except OSError as error:
            return (), (f"no se pudo leer {CATALOG_PATH}: {error.strerror}",)

        load = load_catalog(payload, b"", _OwnAuthority())
        return load.profiles, load.issues

    def path_entries_removed(self) -> int | None:
        """Cuantas entradas del PATH se le quitan a un cliente al arrancarlo.

        Es lo que impedia abrir FortiClient: heredaba nuestro PATH y cargaba
        nuestras DLL. El numero dice si el saneado esta haciendo algo en esta
        maquina o no tiene nada que quitar.
        """
        try:
            before = os.environ.get("PATH", "")
            after = clean_environment().get("PATH", "")
            if not bundle_directories():
                return 0
            return len(_entries(before)) - len(_entries(after))
        except Exception:
            log.exception("no se pudo comparar el PATH")
            return None

    def detected_clients(self) -> Sequence[tuple[str, str]]:
        """Los clientes VPN que hay de verdad en este equipo.

        Si el catalogo apunta a una ruta que no existe, esto dice donde esta el
        cliente, y con eso se corrige en el editor sin ir a buscarlo a mano.
        """
        found: list[tuple[str, str]] = []
        for provider in PROVIDERS:
            if provider.launch_kind is not LaunchKind.EXE:
                continue
            path = detect(provider)
            if path:
                found.append((provider.display_name, path))
        return found


def _entries(path: str) -> list[str]:
    return [entry for entry in path.split(";") if entry]
