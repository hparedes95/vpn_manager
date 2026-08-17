"""El pipe visto desde la interfaz.

El lado cliente de un named pipe no necesita ninguna libreria: en Windows se
abre como un fichero. Quien si necesita pywin32 es el servidor, porque crear
el pipe con su ACL no se puede hacer de otra forma razonable. Que la
dependencia se quede en el servicio y no llegue a la interfaz es una ventaja
que conviene no perder: la interfaz corre en el puesto de cada usuario.

Este modulo es transporte y no decide nada. Toda la conversacion —que se
pregunta, que se hace con la respuesta— esta en `client.py`, que se prueba sin
Windows.
"""

from __future__ import annotations

import contextlib
from typing import BinaryIO, Final

PIPE_NAME: Final = r"\\.\pipe\vpnmgr"

# Lo que se pide leer de una vez. El troceado real lo hace `MessageStream`.
READ_CHUNK: Final = 8192


class PipeUnavailable(Exception):
    """No se pudo hablar con el servicio.

    Pasa mas de lo que parece y casi nunca es grave: el servicio arrancando,
    el equipo recien encendido, o el usuario sin permiso en el grupo de AD. La
    bandeja lo enseña como "sin conexion con el servicio" y lo reintenta.
    """


class PipeTransport:
    """Cliente del named pipe. Sin verificar en un puesto todavia."""

    def __init__(self, pipe_name: str = PIPE_NAME) -> None:
        self._pipe_name = pipe_name
        self._handle: BinaryIO | None = None

    def send(self, payload: bytes) -> None:
        handle = self._open()
        try:
            handle.write(payload)
            handle.flush()
        except OSError as error:
            self.close()
            raise PipeUnavailable("se corto la conexion con el servicio") from error

    def receive(self) -> bytes:
        handle = self._open()
        try:
            chunk = handle.read(READ_CHUNK)
        except OSError as error:
            self.close()
            raise PipeUnavailable("se corto la conexion con el servicio") from error

        if not chunk:
            # El servicio colgo. Suele significar que lo que se le mando no le
            # gusto, y el propio servicio ya habra registrado por que.
            self.close()
            raise PipeUnavailable("el servicio cerro la conexion")
        return chunk

    def close(self) -> None:
        if self._handle is not None:
            # Cerrar algo que ya estaba roto no es un problema nuevo.
            with contextlib.suppress(OSError):
                self._handle.close()
            self._handle = None

    def _open(self) -> BinaryIO:
        if self._handle is not None:
            return self._handle
        try:
            # Sin buffering: un pipe en modo mensaje no se lleva bien con que
            # Python decida por su cuenta cuando escribir.
            self._handle = open(self._pipe_name, "r+b", buffering=0)  # noqa: SIM115
        except OSError as error:
            raise PipeUnavailable("no se pudo conectar con el servicio de VPN Manager") from error
        return self._handle

    def __enter__(self) -> PipeTransport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
