"""Arranque de procesos: la unica parte del proyecto que crea procesos.

Implementa el puerto `ProcessLauncher` de `base.py`. Esta aparte a proposito:
que la creacion de procesos viva en un solo fichero pequeño es lo que hace que
se pueda auditar de un vistazo.

**Dos sitios donde puede correr un proceso, y no dan lo mismo.**

Un `LaunchSpec` con `LaunchContext.SERVICE` lo ejecuta este proceso, que corre
como SYSTEM. Es para lo que necesita privilegio y no habla con nadie, como
`wireguard.exe /installtunnelservice`.

Un `LaunchSpec` con `LaunchContext.USER_SESSION` —el caso normal— no lo puede
ejecutar el servicio: SYSTEM vive en la sesion 0, sin escritorio, y un cliente
VPN lanzado ahi seria invisible, no podria pedir MFA y no alcanzaria el
almacen de credenciales del usuario. Se delega en la interfaz, que corre en la
sesion del usuario, a traves del puerto `UserSessionLauncher`.

Esa delegacion no abre ningun agujero: el `LaunchSpec` sale del catalogo
firmado y viaja del proceso privilegiado al que no lo es. La interfaz acaba
arrancando un binario con los permisos que el usuario ya tiene, que es
exactamente lo que el usuario podria hacer solo.

**Nunca `shell=True`, nunca una cadena de comando.** `subprocess` siempre con
lista de argumentos, para que un espacio o una comilla en una ruta sea un
caracter mas y no un separador.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path, PureWindowsPath
from typing import Final, Protocol

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.core.models import LaunchContext, LaunchKind, LaunchSpec

# Una app MSIX no tiene ruta de ejecutable: se abre por el shell, con su
# Package Family Name. El explorador es quien sabe resolverlo.
_SHELL_HOST = r"C:\Windows\explorer.exe"
_APPS_FOLDER = "shell:AppsFolder\\"

# El de Windows, escrito a mano y no `os.pathsep`: esto corre en Windows pero
# se prueba en Linux, donde `os.pathsep` son dos puntos y partiria un PATH de
# Windows justo por la letra de unidad.
PATH_SEPARATOR: Final = ";"

# Variables que este proceso lleva por estar empaquetado, y que no significan
# nada para el cliente VPN que arranca. Heredarlas es peor que no pasarlas:
# apuntan a nuestras librerias, no a las suyas.
_BUNDLE_VARS: Final = frozenset(
    {
        # PyInstaller.
        "_MEIPASS2",
        "_PYI_APPLICATION_HOME_DIR",
        "_PYI_ARCHIVE_FILE",
        "_PYI_PARENT_PROCESS_LEVEL",
        "PYTHONHOME",
        "PYTHONPATH",
        # Qt, que PySide6 apunta a nuestros plugins.
        "QML2_IMPORT_PATH",
        "QML_IMPORT_PATH",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        # certifi: mandaria al cliente a nuestro almacen de certificados.
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
)


def _allow_the_client_to_come_to_the_front() -> None:
    """Deja que la ventana del cliente se ponga delante al abrirse.

    Windows no deja que un proceso le robe el primer plano a otro. Quien pulsa
    el boton lo hace en NUESTRA ventana, asi que el primer plano es nuestro y
    el cliente aparece detras: hay que ir a buscarlo a la barra de tareas, que
    es justo el paso que este programa deberia ahorrar.

    `AllowSetForegroundWindow` es la forma prevista de cederselo. Se cede a
    cualquiera (`ASFW_ANY`) porque todavia no hay pid al que cederselo: el
    proceso no existe hasta la linea siguiente.

    Si falla, no pasa nada y desde luego no se deja de arrancar el cliente:
    aparecer detras es un incordio, no arrancar es el fallo.
    """
    try:
        import ctypes

        ctypes.windll.user32.AllowSetForegroundWindow(-1)  # type: ignore[attr-defined]
    except Exception:
        pass


def bundle_directories() -> tuple[str, ...]:
    """Los directorios de este proceso empaquetado, si lo esta."""
    directories: list[str] = []
    unpacked = getattr(sys, "_MEIPASS", None)
    if unpacked:
        directories.append(str(unpacked))
    if getattr(sys, "frozen", False):
        directories.append(str(Path(sys.executable).resolve().parent))
    return tuple(directories)


def clean_environment(
    environ: Mapping[str, str] | None = None,
    bundle_dirs: tuple[str, ...] | None = None,
) -> dict[str, str]:
    """El entorno del usuario, sin lo que le haya anadido este proceso.

    **Esto es lo que impedia abrir FortiClient.** Su modulo nativo
    `guimessenger64.node` fallaba con el error 126 de Windows,
    `ERROR_MOD_NOT_FOUND`, que no significa que falte ese fichero: significa que
    falta una DLL de la que depende. Al fallar los dos modulos, el loader
    devolvia null y su `Logger` reventaba leyendo `TraceLog` de null.

    Windows resuelve esas dependencias por el directorio del ejecutable, los
    del sistema, el directorio actual y el `PATH`. Nosotros somos un bundle de
    PyInstaller con nuestro propio `VCRUNTIME140.dll`, `MSVCP140.dll` y las DLL
    de Qt; el cliente heredaba ese `PATH` y cargaba la nuestra en vez de la
    suya.

    Por eso arrancaba bien desde PowerShell y no desde aqui, con el mismo
    directorio de trabajo: la diferencia no era el directorio, era el entorno.

    Se quita solo lo que hemos puesto nosotros. El resto del entorno del
    usuario —su perfil, sus unidades de red, sus variables— viaja intacto,
    porque el cliente si lo necesita.
    """
    source = os.environ if environ is None else environ
    dirs = bundle_directories() if bundle_dirs is None else bundle_dirs

    env = {name: value for name, value in source.items() if name not in _BUNDLE_VARS}
    if dirs and env.get("PATH"):
        env["PATH"] = PATH_SEPARATOR.join(
            entry
            for entry in env["PATH"].split(PATH_SEPARATOR)
            if entry and not _inside_any(entry, dirs)
        )
    return env


def _inside_any(entry: str, directories: tuple[str, ...]) -> bool:
    """Si una entrada del PATH cae dentro de alguno de nuestros directorios.

    Con `PureWindowsPath` y no con `os.path`: esto solo se ejecuta en Windows,
    pero se prueba en Linux, y alli `os.path` no entiende ni el separador ni
    que las rutas no distingan mayusculas. Comparar con las reglas del sistema
    equivocado seria no comparar nada.

    Una entrada que ni se pueda interpretar se deja pasar: no tocar el PATH del
    usuario por si acaso es mejor que romperselo.
    """
    try:
        candidate = PureWindowsPath(entry)
    except (TypeError, ValueError):
        return False

    for directory in directories:
        try:
            target = PureWindowsPath(directory)
        except (TypeError, ValueError):
            continue
        # `PureWindowsPath` ya compara sin distinguir mayusculas.
        if candidate == target or candidate.is_relative_to(target):
            return True
    return False


class UserSessionLauncher(Protocol):
    """Puerto: quien puede arrancar algo en la sesion del usuario.

    Lo implementa el lado de la interfaz. El servicio le manda la orden por el
    pipe y la interfaz la ejecuta en su propia sesion.
    """

    def start_for_user(self, spec: LaunchSpec) -> LaunchOutcome: ...


class UnavailableUserSession:
    """Lo que hay cuando no hay ninguna interfaz conectada.

    No es un error del programa: pasa siempre entre que arranca el servicio y
    alguien inicia sesion. Se responde que no se pudo, con un motivo que se
    entiende, en vez de reventar.
    """

    def start_for_user(self, spec: LaunchSpec) -> LaunchOutcome:
        return LaunchOutcome(
            started=False,
            detail="no hay ninguna sesion de usuario con la interfaz abierta",
        )


class WindowsProcessLauncher:
    """El lanzador de verdad. Sin verificar en un puesto todavia."""

    def __init__(self, user_session: UserSessionLauncher | None = None) -> None:
        self._user_session = UnavailableUserSession() if user_session is None else user_session

    def start(self, spec: LaunchSpec) -> LaunchOutcome:
        if spec.context is LaunchContext.USER_SESSION:
            return self._user_session.start_for_user(spec)
        return self.start_here(spec)

    def start_here(self, spec: LaunchSpec) -> LaunchOutcome:
        """Arranca en **este** proceso. Como SYSTEM si esto es el servicio.

        La interfaz tambien la usa: para ella, "aqui" es la sesion del usuario,
        que es justo donde tiene que aparecer el cliente.
        """
        issues = spec.validate()
        if issues:
            # Ultima puerta antes de crear un proceso. El catalogo ya deberia
            # haberlo parado, pero esto no cuesta nada y cierra el camino.
            return LaunchOutcome(started=False, detail=f"launch invalido: {'; '.join(issues)}")

        _allow_the_client_to_come_to_the_front()
        try:
            process = subprocess.Popen(
                self._argv(spec),
                shell=False,
                # Desde su propia carpeta, como hace un acceso directo.
                cwd=self._working_directory(spec),
                # Y con el entorno del usuario, no con el nuestro: heredar el
                # PATH de un bundle de PyInstaller le hace cargar nuestras DLL.
                env=clean_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            # FileNotFoundError incluida: el cliente puede no estar instalado
            # en este puesto, y eso es informacion util, no una excepcion.
            return LaunchOutcome(started=False, detail=f"no se pudo arrancar: {error.strerror}")

        return LaunchOutcome(started=True, pid=self._pid_of(spec, process.pid))

    def _working_directory(self, spec: LaunchSpec) -> str | None:
        """La carpeta del propio cliente, como haria un acceso directo.

        Un acceso directo de Windows lleva su «Iniciar en», y el explorador lo
        pone a la carpeta del programa. `subprocess.Popen` no: hereda el
        directorio de quien lanza, que aqui es la carpeta de VPN Manager.

        Hay clientes que no lo soportan. FortiClient VPN, que es una app
        Electron, revienta al arrancar con
        `TypeError: Cannot read properties of null (reading 'TraceLog')` en su
        propio Logger: busca su configuracion por ruta relativa y no la
        encuentra. Visto en un puesto real.

        No es un apaño para un cliente concreto: arrancar un programa desde su
        carpeta es lo que hacen el explorador y el menu de inicio, y es lo que
        esos programas esperan. Lo raro era lo que haciamos antes.

        Con MSIX no aplica: quien arranca es el explorador y el shell resuelve
        la app por su Package Family Name, sin ninguna ruta de por medio.
        """
        if spec.kind is not LaunchKind.EXE:
            return None
        parent = PureWindowsPath(spec.target).parent
        # `validate()` ya exige ruta absoluta, asi que esto siempre tiene padre.
        # Si algun dia no lo tuviera, se hereda el de siempre en vez de fallar.
        return str(parent) if str(parent) not in ("", ".") else None

    def _argv(self, spec: LaunchSpec) -> list[str]:
        """La lista de argumentos. Nunca una cadena que alguien tenga que trocear."""
        if spec.kind is LaunchKind.MSIX:
            return [_SHELL_HOST, f"{_APPS_FOLDER}{spec.target}", *spec.args]
        return [spec.target, *spec.args]

    def _pid_of(self, spec: LaunchSpec, pid: int) -> int | None:
        """El pid del cliente, si es que se puede saber.

        Con MSIX no se puede: lo que arranca es el explorador, que le pasa el
        encargo al shell y se va. Devolver su pid seria peor que no devolver
        ninguno, porque `DisconnectStrategy.TERMINATE` mataria al explorador
        del usuario creyendo que mata el cliente VPN.
        """
        return None if spec.kind is LaunchKind.MSIX else pid
