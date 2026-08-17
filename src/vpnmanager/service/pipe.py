"""Servidor del named pipe. Transporte puro: no decide nada.

Todo lo que decide algo esta en `dispatcher.py`, que se prueba entero sin
Windows. Aqui solo se crea el pipe, se lee y se escribe. Si algun dia hay que
escribir aqui un `if` sobre el contenido de un mensaje, va en el otro sitio.

**La ACL es la mitad de la seguridad.** El protocolo decide *que* se puede
pedir; la ACL decide *quien* puede pedirlo. Sin la segunda, la primera protege
de bastante poco: cualquier proceso del equipo podria conectarse y pedir
conexiones. Por defecto se restringe a Administradores y SYSTEM; en produccion
va el grupo de AD.

Este modulo no se puede probar aqui —no hay Windows y no hay pywin32— asi que
se ha dejado lo mas corto posible.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

from vpnmanager.service.dispatcher import ConnectionHandler, DeferredUserSession
from vpnmanager.service.orchestrator import Orchestrator

if TYPE_CHECKING:  # pragma: no cover - solo para el tipado
    pass

log = logging.getLogger(__name__)

PIPE_NAME: Final = r"\\.\pipe\vpnmgr"
BUFFER_SIZE: Final = 64 * 1024

# Quien puede hablar con el servicio. Se sustituye por el grupo de AD cuando
# exista: hasta entonces, solo administradores del equipo.
DEFAULT_ALLOWED_GROUPS: Final = ("BUILTIN\\Administrators",)


def build_security_descriptor(allowed_groups: tuple[str, ...]):  # type: ignore[no-untyped-def]
    """Descriptor con acceso solo para SYSTEM y los grupos indicados.

    Se construye a mano y no se deja el descriptor por defecto: el de por
    defecto de un named pipe deja conectarse a cualquiera que haya iniciado
    sesion, que es justo lo que no queremos.
    """
    import ntsecuritycon
    import win32security

    descriptor = win32security.SECURITY_DESCRIPTOR()
    acl = win32security.ACL()

    system = win32security.ConvertStringSidToSid("S-1-5-18")
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system)

    for group in allowed_groups:
        sid, _, _ = win32security.LookupAccountName(None, group)
        acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE,
            sid,
        )

    # Sin herencia y con una DACL explicita: nadie mas entra.
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    return descriptor


class PipeServer:
    """Atiende conexiones del pipe, de una en una.

    De una en una a proposito. Solo hay una interfaz por sesion de usuario y
    las operaciones son cortas; atender en paralelo obligaria a serializar el
    acceso al orquestador, que hoy no lo esta, y esa es justo la clase de
    concurrencia que se cuela sin que nadie la vea.
    """

    def __init__(
        self,
        orchestrator: Orchestrator,
        user_session: DeferredUserSession,
        pipe_name: str = PIPE_NAME,
        allowed_groups: tuple[str, ...] = DEFAULT_ALLOWED_GROUPS,
    ) -> None:
        self._orchestrator = orchestrator
        self._user_session = user_session
        self._pipe_name = pipe_name
        self._allowed_groups = allowed_groups
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def serve_forever(self) -> None:
        while not self._stop:
            try:
                self._serve_one()
            except Exception:
                # Una conexion que revienta no puede llevarse el servicio por
                # delante: si el servicio muere, nadie deshace un tunel que
                # haya quedado a medias.
                log.exception("fallo atendiendo una conexion del pipe")

    def _serve_one(self) -> None:
        import pywintypes
        import win32file
        import win32pipe

        handle = win32pipe.CreateNamedPipe(
            self._pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            build_security_descriptor(self._allowed_groups),
        )
        try:
            win32pipe.ConnectNamedPipe(handle, None)
            self._converse(handle)
        except pywintypes.error:
            log.debug("la interfaz se desconecto del pipe")
        finally:
            win32file.CloseHandle(handle)

    def _converse(self, handle: object) -> None:
        """Lee, se lo da al manejador, escribe. Nada mas."""
        import win32file

        handler = ConnectionHandler(self._orchestrator, self._user_session)
        while not self._stop:
            _, chunk = win32file.ReadFile(handle, BUFFER_SIZE)
            if not chunk:
                return

            exchange = handler.feed(chunk)
            for reply in exchange.replies:
                win32file.WriteFile(handle, reply)
            if not exchange.keep_open:
                # El manejador ha decidido colgar. Aqui no se discute.
                return
