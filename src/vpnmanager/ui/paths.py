"""Donde escribe la interfaz. Un solo sitio, que lo lean los dos.

La bandeja y la ventana necesitan la misma carpeta —el log, el informe de
diagnostico— y la ventana la sacaba importando la bandeja. Eso es un ciclo: la
bandeja ya importa la ventana. Vive aqui, que no importa a nadie.

En `%LOCALAPPDATA%` y no junto al catalogo: la interfaz corre sin privilegios y
en `%ProgramData%\\VpnManager` solo escriben Administradores y SYSTEM, que es
justo la proteccion que hace que el catalogo sirva de algo.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

DATA_DIR: Final = Path(os.environ.get("LOCALAPPDATA", ".")) / "VpnManager"
LOG_PATH: Final = DATA_DIR / "vpnmgr-ui.log"
REPORT_PATH: Final = DATA_DIR / "diagnostico.txt"
