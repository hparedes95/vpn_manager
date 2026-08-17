"""Protocolo del pipe: lo unico que la interfaz puede decirle al servicio.

Al otro lado de este contrato hay un proceso corriendo en SYSTEM y a este
lado un usuario sin privilegios. Todo lo que sigue existe para que esa
frontera sea estrecha y aburrida.

**La gramatica no permite expresar una ruta.** No es que el servicio ignore un
campo `path`: es que no hay ningun campo donde quepa. Una peticion es un
comando de un conjunto cerrado y, como mucho, el id de un perfil del catalogo
firmado. Si algun dia alguien anade aqui un campo de texto libre que el
servicio use para construir una linea de comandos o una operacion de red, eso
es una escalada de privilegios local en cada puesto de la empresa.

**El decodificador es estricto por definicion.** Clave desconocida, tipo que no
toca, version distinta, tamano excesivo: todo se rechaza. Nada se ignora en
silencio, porque lo que llega y no se entiende es un error de programacion o
un intento de colar algo, y ninguno de los dos merece que se siga adelante.

**Los mensajes de error no repiten lo recibido.** Describen la clase de fallo,
nunca el contenido. Un mensaje hostil no puede acabar escrito en el log solo
por estar mal formado.

Formato: un objeto JSON por mensaje, UTF-8, terminado en salto de linea. El
salto de linea es el unico separador, asi que el JSON va compacto y sin saltos
dentro.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Final

from vpnmanager.core.models import (
    Capability,
    ConnectionState,
    LaunchKind,
    LaunchSpec,
    TunnelType,
    is_valid_profile_id,
)

PROTOCOL_VERSION: Final = 1

# Un cliente sin privilegios no puede obligar al servicio a reservar memoria
# sin limite. Con 4 KiB sobra: la peticion mas larga es un comando y un id de
# 64 caracteres.
MAX_REQUEST_BYTES: Final = 4096

# Las respuestas van en el otro sentido y son mucho mayores: un LIST lleva el
# catalogo entero. El limite aqui no protege de un atacante —al otro lado esta
# el servicio— sino de un flujo que se descuadre y crezca sin fin.
MAX_RESPONSE_BYTES: Final = 256 * 1024


class ProtocolError(Exception):
    """Mensaje que no se entiende o que no cumple el contrato.

    El servidor la captura y responde con un error generico. El texto describe
    la clase de fallo y nunca incluye lo que llego por el pipe.
    """


class Command(Enum):
    """Todo lo que se puede pedir. El conjunto es cerrado a proposito."""

    LIST = "list"  # que perfiles hay y como estan
    LAUNCH = "launch"  # abrir el cliente oficial
    CONNECT = "connect"  # conectar un perfil del catalogo
    DISCONNECT = "disconnect"  # desconectar un perfil del catalogo
    STATUS = "status"  # estado de un perfil
    CONFIRM = "confirm"  # la conexion funciona: desarma el watchdog


# LIST es el unico comando que no habla de un perfil concreto.
COMMANDS_WITHOUT_PROFILE: Final = frozenset({Command.LIST})


@dataclass(frozen=True)
class Request:
    """Lo que la interfaz manda al servicio.

    No hay identificador de peticion: el pipe es sincrono, una peticion y una
    respuesta. Cada campo que no existe es un campo que no hay que validar.
    """

    command: Command
    profile_id: str | None = None
    # Solo en CONNECT: el usuario ha aceptado explicitamente perder la
    # conectividad local (HU-03). El servicio no puede darlo por hecho, porque
    # quien pulsa suele estar dentro de la sesion RDP que se va a cortar.
    user_confirmed: bool = False

    def encode(self) -> bytes:
        payload: dict[str, object] = {
            "version": PROTOCOL_VERSION,
            "command": self.command.value,
        }
        if self.profile_id is not None:
            payload["profile_id"] = self.profile_id
        if self.command is Command.CONNECT:
            payload["user_confirmed"] = self.user_confirmed
        return _encode(payload)

    @staticmethod
    def decode(raw: bytes) -> Request:
        """Convierte bytes del pipe en una peticion, o falla.

        Este es el punto por el que pasa todo lo que viene de fuera. Lo que
        salga de aqui ya puede tratarse como valido; lo que no salga, no
        existe.
        """
        if len(raw) > MAX_REQUEST_BYTES:
            raise ProtocolError(
                f"peticion demasiado larga: el limite son {MAX_REQUEST_BYTES} bytes"
            )

        data = _decode_object(raw)
        # La version primero: si algun dia hay una v2, quien la hable debe
        # enterarse de eso y no de que sus campos nuevos "no existen".
        _check_version(data)
        command = _read_command(data)
        _check_keys(data, allowed=_allowed_keys(command))

        profile_id = _read_profile_id(data, command)
        user_confirmed = _read_user_confirmed(data, command)
        return Request(command=command, profile_id=profile_id, user_confirmed=user_confirmed)


@dataclass(frozen=True)
class ProfileSummary:
    """Lo que la interfaz necesita saber de un perfil para dibujarse.

    No lleva la especificacion de arranque ni las rutas: la interfaz no las
    necesita, y lo que no viaja no se puede filtrar ni manipular.
    """

    id: str
    display_name: str
    tunnel_type: TunnelType
    state: ConnectionState
    capabilities: tuple[Capability, ...] = ()
    needs_confirmation: bool = False

    def as_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "tunnel_type": self.tunnel_type.value,
            "state": self.state.value,
            # Por nombre, no por valor: `Capability` usa auto() y sus numeros
            # cambiarian con solo reordenar el enum.
            "capabilities": [capability.name for capability in self.capabilities],
            "needs_confirmation": self.needs_confirmation,
        }

    @staticmethod
    def from_payload(data: dict[str, object]) -> ProfileSummary:
        _check_keys(
            data,
            allowed=frozenset(
                {
                    "id",
                    "display_name",
                    "tunnel_type",
                    "state",
                    "capabilities",
                    "needs_confirmation",
                }
            ),
        )
        capabilities = _read_list_of_strings(data, "capabilities")
        return ProfileSummary(
            id=_read_string(data, "id"),
            display_name=_read_string(data, "display_name"),
            tunnel_type=_read_enum(data, "tunnel_type", TunnelType),
            state=_read_enum(data, "state", ConnectionState),
            capabilities=tuple(_capability_by_name(name) for name in capabilities),
            needs_confirmation=_read_bool(data, "needs_confirmation", default=False),
        )


@dataclass(frozen=True)
class LaunchOrder:
    """Lo que el servicio le pide a la interfaz que arranque en su sesion.

    Un cliente VPN con ventana tiene que aparecer en la sesion del usuario, y
    el servicio vive en la sesion 0. Como el pipe es sincrono y el servicio no
    puede empujar mensajes, la orden viaja en la respuesta: "arranca esto y
    luego confirmame".

    Que aqui si haya una ruta no contradice la regla del protocolo. La regla
    es que el servicio no **acepta** rutas; esta sale del catalogo firmado y
    va del proceso privilegiado al que no lo es. La interfaz acaba arrancando
    un binario con los permisos que el usuario ya tiene. No hay ningun campo
    en `Request` por el que esto pueda volver.
    """

    kind: LaunchKind
    target: str
    args: tuple[str, ...] = ()

    @staticmethod
    def from_spec(spec: LaunchSpec) -> LaunchOrder:
        return LaunchOrder(kind=spec.kind, target=spec.target, args=spec.args)

    def as_payload(self) -> dict[str, object]:
        return {"kind": self.kind.value, "target": self.target, "args": list(self.args)}

    @staticmethod
    def from_payload(data: dict[str, object]) -> LaunchOrder:
        _check_keys(data, allowed=frozenset({"kind", "target", "args"}))
        return LaunchOrder(
            kind=_read_enum(data, "kind", LaunchKind),
            target=_read_string(data, "target"),
            args=tuple(_read_list_of_strings(data, "args")),
        )


@dataclass(frozen=True)
class Response:
    """Lo que el servicio contesta.

    `manual_disconnect_first` y `warnings` vienen del arbitro: la interfaz los
    pinta tal cual, sin tener que interpretar el texto de `message`.
    """

    ok: bool
    message: str = ""
    state: ConnectionState | None = None
    profiles: tuple[ProfileSummary, ...] = ()
    manual_disconnect_first: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    launch: LaunchOrder | None = None

    @staticmethod
    def failure(message: str) -> Response:
        return Response(ok=False, message=message)

    def encode(self) -> bytes:
        payload: dict[str, object] = {
            "version": PROTOCOL_VERSION,
            "ok": self.ok,
            "message": self.message,
            "state": None if self.state is None else self.state.value,
            "profiles": [profile.as_payload() for profile in self.profiles],
            "manual_disconnect_first": list(self.manual_disconnect_first),
            "warnings": list(self.warnings),
            "launch": None if self.launch is None else self.launch.as_payload(),
        }
        return _encode(payload)

    @staticmethod
    def decode(raw: bytes) -> Response:
        data = _decode_object(raw)
        _check_keys(
            data,
            allowed=frozenset(
                {
                    "version",
                    "ok",
                    "message",
                    "state",
                    "profiles",
                    "manual_disconnect_first",
                    "warnings",
                    "launch",
                }
            ),
        )
        _check_version(data)

        state_value = data.get("state")
        launch_value = data.get("launch")
        if launch_value is not None and not isinstance(launch_value, dict):
            raise ProtocolError("el campo 'launch' debe ser un objeto o estar ausente")
        return Response(
            ok=_read_bool(data, "ok"),
            message=_read_string(data, "message", default=""),
            state=None if state_value is None else _read_enum(data, "state", ConnectionState),
            profiles=tuple(
                ProfileSummary.from_payload(item)
                for item in _read_list_of_objects(data, "profiles")
            ),
            manual_disconnect_first=tuple(_read_list_of_strings(data, "manual_disconnect_first")),
            warnings=tuple(_read_list_of_strings(data, "warnings")),
            launch=None if launch_value is None else LaunchOrder.from_payload(dict(launch_value)),
        )


class MessageStream:
    """Trocea en mensajes lo que va llegando por el pipe.

    Un pipe es un flujo de bytes: lo que se lee no coincide con lo que se
    escribio. Un mensaje puede llegar partido en tres trozos y tres mensajes
    pueden llegar juntos.

    Lo importante es **donde** se aplica el limite de tamano. Si se leyera sin
    tope hasta encontrar un salto de linea, un cliente sin privilegios podria
    mandar bytes para siempre sin mandar ninguno, y el limite de
    `Request.decode` no llegaria a comprobarse nunca porque nunca habria un
    mensaje que comprobar. Por eso el tope se mira mientras se acumula.

    Pasado el limite, el flujo queda roto y no se recupera: reengancharse
    despues de la basura permitiria colar un mensaje detras de ella. Quien lo
    use tiene que cerrar la conexion.
    """

    def __init__(self, max_message_bytes: int = MAX_REQUEST_BYTES) -> None:
        self._max = max_message_bytes
        self._buffer = bytearray()
        self._broken = False

    @property
    def pending_bytes(self) -> int:
        """Lo que hay acumulado sin terminar en un mensaje."""
        return len(self._buffer)

    def feed(self, chunk: bytes) -> list[bytes]:
        """Anade lo leido y devuelve los mensajes completos, sin el salto final."""
        if self._broken:
            raise ProtocolError("el flujo venia roto: hay que cerrar la conexion")

        self._buffer.extend(chunk)
        messages: list[bytes] = []
        while (index := self._buffer.find(b"\n")) != -1:
            message = bytes(self._buffer[:index])
            del self._buffer[: index + 1]
            if len(message) > self._max:
                # Se descartan tambien los mensajes ya troceados en esta misma
                # llamada: la conexion se va a cerrar de todas formas.
                self._break(f"mensaje de mas de {self._max} bytes")
            messages.append(message)

        if len(self._buffer) > self._max:
            self._break(f"mensaje sin terminar de mas de {self._max} bytes")
        return messages

    def _break(self, reason: str) -> None:
        self._broken = True
        self._buffer.clear()
        raise ProtocolError(reason)


# --------------------------------------------------------------------------
# Lectura estricta. Ninguna de estas funciones repite en el error lo que leyo.
# --------------------------------------------------------------------------


def _encode(payload: dict[str, object]) -> bytes:
    # Compacto y sin saltos: el salto de linea es el separador de mensajes.
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def _decode_object(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("el mensaje no es UTF-8 valido") from error

    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as error:
        raise ProtocolError("el mensaje no es JSON valido") from error

    if not isinstance(parsed, dict):
        raise ProtocolError("el mensaje debe ser un objeto JSON")
    # Las claves de un objeto JSON siempre son cadenas.
    return dict(parsed)


def _allowed_keys(command: Command) -> frozenset[str]:
    keys = {"version", "command"}
    if command not in COMMANDS_WITHOUT_PROFILE:
        keys.add("profile_id")
    if command is Command.CONNECT:
        keys.add("user_confirmed")
    return frozenset(keys)


def _check_keys(data: dict[str, object], allowed: frozenset[str]) -> None:
    """Nada se ignora en silencio.

    Aceptar una clave que no se entiende es aceptar que alguien esta hablando
    otro protocolo, y no saber cual.
    """
    unexpected = sorted(set(data) - allowed)
    if unexpected:
        raise ProtocolError(f"el mensaje trae campos que no existen: {', '.join(unexpected)}")


def _check_version(data: dict[str, object]) -> None:
    version = data.get("version")
    # `isinstance(True, int)` es cierto y `1.0 == 1` tambien, asi que comparar
    # a secas dejaria pasar `true` y `1.0` como si fueran la version 1. Aqui
    # da igual, pero la costumbre de comparar sin mirar el tipo no da igual en
    # ningun otro sitio de este fichero.
    if not isinstance(version, int) or isinstance(version, bool):
        raise ProtocolError("version de protocolo ausente o con un tipo que no toca")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"version de protocolo incompatible: se esperaba {PROTOCOL_VERSION}")


def _read_command(data: dict[str, object]) -> Command:
    value = data.get("command")
    if not isinstance(value, str):
        raise ProtocolError("falta el comando o no es una cadena")
    try:
        return Command(value)
    except ValueError as error:
        raise ProtocolError("comando desconocido") from error


def _read_profile_id(data: dict[str, object], command: Command) -> str | None:
    value = data.get("profile_id")
    if command in COMMANDS_WITHOUT_PROFILE:
        # La clave ya se rechazo en _check_keys; esto solo lo deja explicito.
        return None
    if not isinstance(value, str):
        raise ProtocolError(f"el comando '{command.value}' necesita un profile_id")
    if not is_valid_profile_id(value):
        raise ProtocolError("el profile_id tiene caracteres o una longitud que no se admiten")
    return value


def _read_user_confirmed(data: dict[str, object], command: Command) -> bool:
    if command is not Command.CONNECT:
        return False
    return _read_bool(data, "user_confirmed", default=False)


def _read_bool(data: dict[str, object], key: str, default: bool | None = None) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ProtocolError(f"el campo '{key}' debe ser booleano")
    return value


def _read_string(data: dict[str, object], key: str, default: str | None = None) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ProtocolError(f"el campo '{key}' debe ser una cadena")
    return value


def _read_enum[T: Enum](data: dict[str, object], key: str, enum: type[T]) -> T:
    value = _read_string(data, key)
    try:
        return enum(value)
    except ValueError as error:
        raise ProtocolError(f"el campo '{key}' no admite ese valor") from error


def _capability_by_name(name: str) -> Capability:
    try:
        return Capability[name]
    except KeyError as error:
        raise ProtocolError("capacidad desconocida") from error


def _read_list_of_strings(data: dict[str, object], key: str) -> list[str]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ProtocolError(f"el campo '{key}' debe ser una lista de cadenas")
    return [item for item in values if isinstance(item, str)]


def _read_list_of_objects(data: dict[str, object], key: str) -> list[dict[str, object]]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        raise ProtocolError(f"el campo '{key}' debe ser una lista de objetos")
    return [dict(item) for item in values if isinstance(item, dict)]
