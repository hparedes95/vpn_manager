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

import subprocess
from typing import Protocol

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.core.models import LaunchContext, LaunchKind, LaunchSpec

# Una app MSIX no tiene ruta de ejecutable: se abre por el shell, con su
# Package Family Name. El explorador es quien sabe resolverlo.
_SHELL_HOST = r"C:\Windows\explorer.exe"
_APPS_FOLDER = "shell:AppsFolder\\"


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

        try:
            process = subprocess.Popen(
                self._argv(spec),
                shell=False,
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
