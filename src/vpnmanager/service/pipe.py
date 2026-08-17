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
import time
from typing import Final

from vpnmanager.service.dispatcher import ConnectionHandler, DeferredUserSession
from vpnmanager.service.orchestrator import Orchestrator

log = logging.getLogger(__name__)

PIPE_NAME: Final = r"\\.\pipe\vpnmgr"
BUFFER_SIZE: Final = 64 * 1024
RETRY_SECONDS: Final = 2.0

# Quien puede hablar con el servicio, por SID y no por nombre.
#
# Los grupos integrados de Windows estan traducidos: en un Windows en español
# el grupo no se llama "Administrators" sino "Administradores", y
# `LookupAccountName` falla con el error 1332. El SID es el mismo en todos los
# idiomas y en todas las instalaciones, asi que es lo unico que se puede
# escribir en el codigo sin dar por hecho el idioma de la maquina.
#
# S-1-5-32-544 = Administradores del equipo.
ADMINISTRATORS_SID: Final = "S-1-5-32-544"
LOCAL_SYSTEM_SID: Final = "S-1-5-18"

DEFAULT_ALLOWED_GROUPS: Final = (ADMINISTRATORS_SID,)


def build_security_attributes(allowed_groups: tuple[str, ...]):  # type: ignore[no-untyped-def]
    """SECURITY_ATTRIBUTES con acceso solo para SYSTEM y los grupos indicados.

    `CreateNamedPipe` espera un SECURITY_ATTRIBUTES, no un
    SECURITY_DESCRIPTOR: pasarle el segundo levanta un TypeError antes de
    crear nada, y el servidor no llega a escuchar jamas.

    Se construye a mano y no se deja el descriptor por defecto: el de por
    defecto de un named pipe deja conectarse a cualquiera que haya iniciado
    sesion, que es justo lo que no queremos.
    """
    import ntsecuritycon
    import win32security

    attributes = win32security.SECURITY_ATTRIBUTES()
    acl = win32security.ACL()

    system = win32security.ConvertStringSidToSid(LOCAL_SYSTEM_SID)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system)

    for group in allowed_groups:
        acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE,
            resolve_sid(group),
        )

    # Sin herencia y con una DACL explicita: nadie mas entra.
    attributes.SetSecurityDescriptorDacl(1, acl, 0)
    return attributes


def resolve_sid(group: str):  # type: ignore[no-untyped-def]
    """El SID de un grupo, venga como SID o como nombre.

    Un SID se usa tal cual. Un nombre —el grupo de AD, cuando exista— hay que
    resolverlo, y ahi si tiene sentido: los grupos de dominio no estan
    traducidos. Lo que no se resuelve nunca por nombre son los integrados de
    Windows, que si lo estan.
    """
    import win32security

    if group.upper().startswith("S-1-"):
        return win32security.ConvertStringSidToSid(group)

    sid, _, _ = win32security.LookupAccountName(None, group)
    return sid


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
                #
                # Con espera, y no reintentando a ciegas: si lo que falla es
                # crear el pipe —una ACL mal construida, un nombre ocupado— el
                # fallo se repite en cada vuelta, y sin pausa eso es un bucle
                # que llena el disco de log y no deja ver nada mas.
                log.exception("fallo atendiendo una conexion del pipe")
                time.sleep(RETRY_SECONDS)

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
            build_security_attributes(self._allowed_groups),
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
