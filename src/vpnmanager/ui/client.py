"""El lado de la interfaz: hablar con el servicio y arrancar los clientes.

Esto es lo que hay debajo de la bandeja. No dibuja nada: manda peticiones,
interpreta respuestas y arranca en la sesion del usuario lo que el servicio le
pida. Los widgets van encima y son finos a proposito, porque lo que se puede
probar es esto.

**Confirmar no es lo mismo que lanzar, y el orden importa.** El watchdog
existe porque un tunel completo puede cortar la sesion RDP del usuario, que es
justo donde vive este proceso. Si eso pasa, esta interfaz se queda muerta y no
confirma, y por eso la conexion se deshace sola. Confirmar nada mas lanzar
desarmaria el seguro antes de que el tunel llegue a montarse: seria como
firmar el acuse antes de abrir el paquete.

Por eso se confirma **cuando el servicio dice que el perfil esta conectado**,
no cuando se le manda conectar.
"""

from __future__ import annotations

from typing import Protocol

from vpnmanager.connectors.base import LaunchOutcome
from vpnmanager.core.models import Capability, ConnectionState, LaunchSpec
from vpnmanager.core.protocol import (
    MAX_RESPONSE_BYTES,
    Command,
    LaunchOrder,
    MessageStream,
    ProfileSummary,
    ProtocolError,
    Request,
    Response,
)


class Transport(Protocol):
    """Puerto: el pipe, visto desde la interfaz.

    Se inyecta para que todo lo de este modulo se pueda probar sin Windows y
    sin servicio, que es donde estan los errores que importan.
    """

    def send(self, payload: bytes) -> None: ...

    def receive(self) -> bytes: ...


class LocalLauncher(Protocol):
    """Puerto: arrancar algo aqui, en la sesion del usuario."""

    def start_here(self, spec: LaunchSpec) -> LaunchOutcome: ...


class ServiceClient:
    """Cliente del servicio. Una instancia por sesion de interfaz."""

    def __init__(self, transport: Transport, launcher: LocalLauncher) -> None:
        self._transport = transport
        self._launcher = launcher
        self._stream = MessageStream(MAX_RESPONSE_BYTES)
        # Ojo: si la conexion se cae, el transporte reabre por su cuenta pero
        # en el buffer pueden quedar bytes de una respuesta a medias. Sumados
        # a la siguiente, todas las respuestas quedan corridas para siempre.
        # Por eso el flujo se tira y se rehace en cada reconexion.
        self.last_launch: LaunchOutcome | None = None

    # -- Lo que la bandeja necesita ---------------------------------------

    def list_profiles(self) -> tuple[ProfileSummary, ...]:
        return self._ask(Request(command=Command.LIST)).profiles

    def launch(self, profile_id: str) -> Response:
        return self._ask(Request(command=Command.LAUNCH, profile_id=profile_id))

    def connect(self, profile_id: str, *, user_confirmed: bool = False) -> Response:
        return self._ask(
            Request(
                command=Command.CONNECT,
                profile_id=profile_id,
                user_confirmed=user_confirmed,
            )
        )

    def disconnect(self, profile_id: str) -> Response:
        return self._ask(Request(command=Command.DISCONNECT, profile_id=profile_id))

    def status(self, profile_id: str) -> Response:
        return self._ask(Request(command=Command.STATUS, profile_id=profile_id))

    def confirm_if_connected(self, profile_id: str) -> Response:
        """Confirma solo si el servicio ya da el perfil por conectado.

        Es lo que la bandeja llama cada pocos segundos mientras hay una
        conexion en marcha. Si esta interfaz ha dejado de responder —porque el
        tunel se llevo por delante la sesion RDP— esto no llega a ejecutarse,
        el servicio no recibe la confirmacion y deshace la conexion. Ese
        silencio es el mecanismo, no un fallo.
        """
        current = self.status(profile_id)
        if current.state is not ConnectionState.CONNECTED:
            return current
        return self._ask(Request(command=Command.CONFIRM, profile_id=profile_id))

    # -- Interno -----------------------------------------------------------

    def _ask(self, request: Request) -> Response:
        """Manda una peticion y devuelve la respuesta, ya con su orden atendida.

        El flujo se rehace en cada peticion. El servicio cuelga la conexion en
        cuanto algo no le cuadra, y el transporte reabre por su cuenta: si se
        conservara el flujo, los bytes de la respuesta a medias se sumarian a
        la siguiente y **todas** las respuestas quedarian corridas a partir de
        ahi. Y una sola pasada del limite lo dejaria roto para siempre, con la
        bandeja inservible hasta reiniciarla.
        """
        self._stream = MessageStream(MAX_RESPONSE_BYTES)
        self._transport.send(request.encode())
        response = self._read()
        if response.launch is not None:
            # El servicio no puede arrancar un cliente con ventana. Se hace
            # aqui, con los permisos de este usuario y en su escritorio.
            self.last_launch = self._run(response.launch)
        return response

    def _read(self) -> Response:
        """Lee del transporte hasta tener una respuesta entera."""
        while True:
            messages = self._stream.feed(self._transport.receive())
            if messages:
                return Response.decode(messages[0])

    def _run(self, order: LaunchOrder) -> LaunchOutcome:
        return self._launcher.start_here(
            LaunchSpec(kind=order.kind, target=order.target, args=order.args)
        )


def action_label(summary: ProfileSummary) -> str:
    """Lo que dice el boton de un perfil.

    Se decide con lo que el conector declara, no con lo que nos gustaria que
    hiciera. Prometer automatizacion que no existe es peor que no tenerla.
    """
    if summary.state is ConnectionState.CONNECTED:
        return "Desconectar" if Capability.DISCONNECT in summary.capabilities else "Conectado"
    if Capability.CONNECT in summary.capabilities:
        return "Conectar"
    return "Abrir cliente"


def needs_asking_first(summary: ProfileSummary) -> bool:
    """Si hay que preguntarle al usuario antes de conectar (HU-03).

    La interfaz pregunta, y el servicio ademas lo exige: aunque alguien
    escribiera otra interfaz que no preguntase, la conexion no saldria.
    """
    return summary.needs_confirmation and summary.state is not ConnectionState.CONNECTED


__all__ = [
    "LocalLauncher",
    "ProtocolError",
    "ServiceClient",
    "Transport",
    "action_label",
    "needs_asking_first",
]
