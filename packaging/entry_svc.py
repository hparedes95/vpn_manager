"""Punto de entrada de `vpnmgr-svc.exe`.

PyInstaller necesita un fichero de script, no un modulo. Aqui no va logica: el
arranque de verdad esta en `vpnmanager.service.main`.
"""

from __future__ import annotations

from vpnmanager.service.main import main

if __name__ == "__main__":
    raise SystemExit(main())
