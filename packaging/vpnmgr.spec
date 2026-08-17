# PyInstaller: construye los dos ejecutables en un solo directorio.
#
# `onedir` y no `onefile`, como dice CLAUDE.md. Un onefile se descomprime en
# %TEMP% en cada arranque: los .ps1 acabarian en un directorio temporal
# distinto cada vez, ejecutandose como SYSTEM desde un sitio donde escribe
# cualquiera. Con onedir viven junto al ejecutable, en Program Files.
#
# Se construye con:  pyinstaller packaging/vpnmgr.spec --noconfirm

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

# Los .ps1 son codigo: sin ellos el servicio no sabe leer ni restaurar la red.
PS_SCRIPTS = [
    (str(path), "vpnmanager/net/ps")
    for path in (SRC / "vpnmanager" / "net" / "ps").glob("*.ps1")
]

service = Analysis(
    [str(ROOT / "packaging" / "entry_svc.py")],
    pathex=[str(SRC)],
    datas=PS_SCRIPTS,
    hiddenimports=[
        # pywin32 se importa dentro de las funciones para que el resto del
        # proyecto se pueda probar sin el; PyInstaller no lo ve solo.
        "win32file",
        "win32pipe",
        "win32security",
        "ntsecuritycon",
        "pywintypes",
    ],
    excludes=["PySide6", "tkinter"],
    noarchive=False,
)

ui = Analysis(
    [str(ROOT / "packaging" / "entry_ui.py")],
    pathex=[str(SRC)],
    datas=collect_data_files("PySide6", includes=["plugins/platforms/*"]),
    excludes=["tkinter"],
    noarchive=False,
)

MERGE((service, "entry_svc", "vpnmgr-svc"), (ui, "entry_ui", "vpnmgr-ui"))

service_pyz = PYZ(service.pure)
ui_pyz = PYZ(ui.pure)

service_exe = EXE(
    service_pyz,
    service.scripts,
    [],
    exclude_binaries=True,
    name="vpnmgr-svc",
    console=True,  # se arranca en consola para probar y depurar
    debug=False,
    strip=False,
    upx=False,
)

ui_exe = EXE(
    ui_pyz,
    ui.scripts,
    [],
    exclude_binaries=True,
    name="vpnmgr-ui",
    console=False,  # vive en la bandeja: una consola detras solo estorba
    debug=False,
    strip=False,
    upx=False,
)

COLLECT(
    service_exe,
    service.binaries,
    service.datas,
    ui_exe,
    ui.binaries,
    ui.datas,
    strip=False,
    upx=False,
    name="VpnManager",
)
