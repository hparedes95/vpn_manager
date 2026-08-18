# PyInstaller: dos bundles independientes en dist/.
#
# Sin MERGE. MERGE hace que un ejecutable dependa de ficheros que viven en el
# directorio del otro, y basta con que el instalador los reparta distinto para
# que uno de los dos no arranque y no diga por que. Se paga un runtime de
# Python duplicado a cambio de que cada .exe sea autonomo.
#
# `onedir` y no `onefile`: un onefile se descomprime en %TEMP% en cada
# arranque, y los .ps1 acabarian ejecutandose como SYSTEM desde un directorio
# donde escribe cualquiera. Con onedir viven junto al ejecutable.
#
# Se construye con:  pyinstaller packaging/vpnmgr.spec --noconfirm

import os
from pathlib import Path

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

# La version viaja dentro del bundle. Sin esto, saber que build hay
# instalada en un puesto es mirar la fecha del .exe, que es adivinar; y
# durante las pruebas eso significa depurar un arreglo que a lo mejor ni
# esta ahi. En CI el valor lleva el hash corto del commit.
VERSION = (os.environ.get("VPNMGR_VERSION") or "").strip() or "desarrollo"
VERSION_FILE = ROOT / "build" / "VERSION"
VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
VERSION_FILE.write_text(VERSION, encoding="utf-8")
VERSION_DATA = [(str(VERSION_FILE), "vpnmanager")]

# Los .ps1 son codigo: sin ellos el servicio no sabe leer ni restaurar la red.
PS_SCRIPTS = [
    (str(path), "vpnmanager/net/ps") for path in (SRC / "vpnmanager" / "net" / "ps").glob("*.ps1")
]

service_analysis = Analysis(
    [str(ROOT / "packaging" / "entry_svc.py")],
    pathex=[str(SRC)],
    datas=PS_SCRIPTS + VERSION_DATA,
    hiddenimports=[
        # pywin32 se importa dentro de las funciones para que el resto del
        # proyecto se pueda probar sin el; PyInstaller no lo ve solo.
        "win32file",
        "win32pipe",
        "win32security",
        "ntsecuritycon",
        "pywintypes",
        "win32api",
    ],
    excludes=["PySide6", "tkinter"],
)

service_exe = EXE(
    PYZ(service_analysis.pure),
    service_analysis.scripts,
    [],
    exclude_binaries=True,
    name="vpnmgr-svc",
    console=True,  # se arranca en consola para probar y depurar
    upx=False,
)

COLLECT(
    service_exe,
    service_analysis.binaries,
    service_analysis.datas,
    upx=False,
    name="vpnmgr-svc",
)

ui_analysis = Analysis(
    [str(ROOT / "packaging" / "entry_ui.py")],
    pathex=[str(SRC)],
    datas=VERSION_DATA,
    excludes=["tkinter"],
)

ui_exe = EXE(
    PYZ(ui_analysis.pure),
    ui_analysis.scripts,
    [],
    exclude_binaries=True,
    name="vpnmgr-ui",
    console=False,  # vive en la bandeja: una consola detras solo estorba
    upx=False,
)

COLLECT(
    ui_exe,
    ui_analysis.binaries,
    ui_analysis.datas,
    upx=False,
    name="vpnmgr-ui",
)
