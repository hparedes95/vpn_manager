"""El manejador de una conexion: bytes que entran, bytes que salen.

Aqui vive toda la logica del servidor del pipe. Lo que queda fuera —abrir el
pipe con su ACL, leer y escribir— es transporte, es Windows puro y no decide
nada. Partirlo asi permite probar en CI el camino completo desde los bytes que
llegan hasta los bytes que se devuelven, incluido lo que pasa cuando lo que
llega es basura.

**Un `ProtocolError` cierra la conexion.** No se contesta y se sigue: quien
manda algo que no se entiende esta hablando otro protocolo o probando suerte,
y en los dos casos lo sano es colgar. Se responde una vez, con un motivo
generico, y se cierra.
"""

from __future__ import annotations

from dataclasses import dataclass

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.core.models import LaunchSpec
from vpnmanager.core.protocol import (
    MAX_REQUEST_BYTES,
    LaunchOrder,
    MessageStream,
    ProtocolError,
    Request,
    Response,
)
from vpnmanager.service.orchestrator import Orchestrator


class DeferredUserSession:
    """Recoge lo que hay que arrancar en la sesion del usuario, sin arrancarlo.

    El servicio no puede lanzar un cliente con ventana, y el pipe es sincrono:
    no hay forma de empujarle un mensaje a la interfaz en mitad de nada. Asi
    que se anota la orden y viaja de vuelta en la respuesta a la peticion que
    la provoco.

    Devuelve `started=True` a proposito. Desde el punto de vista del servicio
    el arranque esta en marcha —la orden sale en la respuesta— y el estado que
    corresponde es `LAUNCHING`. Si de verdad arranco o no lo dira la sonda,
    que es lo unico que cuenta como estado real.
    """

    def __init__(self) -> None:
        self._pending: LaunchSpec | None = None

    def start_for_user(self, spec: LaunchSpec) -> LaunchOutcome:
        self._pending = spec
        return LaunchOutcome(
            started=True,
            detail="la interfaz lo arrancara en la sesion del usuario",
        )

    def take(self) -> LaunchOrder | None:
        """Devuelve la orden pendiente y la olvida. Se entrega una sola vez."""
        spec, self._pending = self._pending, None
        return None if spec is None else LaunchOrder.from_spec(spec)


@dataclass(frozen=True)
class Exchange:
    """Lo que hay que escribir de vuelta y si la conexion sigue viva."""

    replies: tuple[bytes, ...] = ()
    keep_open: bool = True


class ConnectionHandler:
    """Atiende una conexion del pipe. Una instancia por conexion."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        user_session: DeferredUserSession,
        max_request_bytes: int = MAX_REQUEST_BYTES,
    ) -> None:
        self._orchestrator = orchestrator
        self._user_session = user_session
        self._stream = MessageStream(max_request_bytes)

    def feed(self, chunk: bytes) -> Exchange:
        """Procesa lo leido del pipe y devuelve lo que hay que escribir."""
        try:
            messages = self._stream.feed(chunk)
        except ProtocolError as error:
            return Exchange(replies=(Response.failure(str(error)).encode(),), keep_open=False)

        replies: list[bytes] = []
        for message in messages:
            try:
                request = Request.decode(message)
            except ProtocolError as error:
                # El mensaje de `ProtocolError` describe la clase de fallo y
                # nunca repite lo recibido, asi que se puede devolver tal cual.
                replies.append(Response.failure(str(error)).encode())
                return Exchange(replies=tuple(replies), keep_open=False)

            replies.append(self._answer(request).encode())

        return Exchange(replies=tuple(replies))

    def _answer(self, request: Request) -> Response:
        response = self._orchestrator.handle(request)
        order = self._user_session.take()
        if order is None:
            return response
        # La orden se adjunta a la respuesta que la provoco. Si el orquestador
        # ya traia una, manda la suya: no se pisan.
        return response if response.launch is not None else _with_launch(response, order)


def _with_launch(response: Response, order: LaunchOrder) -> Response:
    return Response(
        ok=response.ok,
        message=response.message,
        state=response.state,
        profiles=response.profiles,
        manual_disconnect_first=response.manual_disconnect_first,
        warnings=response.warnings,
        launch=order,
    )
