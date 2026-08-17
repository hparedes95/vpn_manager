"""Punto de entrada de `vpnmgr-ui.exe`.

PyInstaller necesita un fichero de script, no un modulo. Aqui no va logica: la
bandeja esta en `vpnmanager.ui.tray`.
"""

from __future__ import annotations

from vpnmanager.ui.tray import main

if __name__ == "__main__":
    raise SystemExit(main())
