"""Tests del protocolo del pipe.

Aqui no basta con probar que un mensaje bien formado se entiende. Lo que hay
al otro lado corre en SYSTEM, asi que la mayoria de estos tests mandan basura
a proposito: campos que no existen, tipos cambiados, ids con separadores de
ruta, mensajes enormes. Lo que tiene que quedar demostrado es que nada de eso
llega a convertirse en una peticion valida.
"""

from __future__ import annotations

import json

import pytest

from vpnmanager.core.models import Capability, ConnectionState, TunnelType
from vpnmanager.core.protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    Command,
    MessageStream,
    ProfileSummary,
    ProtocolError,
    Request,
    Response,
)


def raw(**payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8")


# --------------------------------------------------------------------------
# Ida y vuelta de lo que si es valido
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        Request(command=Command.LIST),
        Request(command=Command.LAUNCH, profile_id="azure-cliente-c"),
        Request(command=Command.CONNECT, profile_id="wireguard-corp"),
        Request(command=Command.CONNECT, profile_id="full-rdp", user_confirmed=True),
        Request(command=Command.DISCONNECT, profile_id="wireguard-corp"),
        Request(command=Command.STATUS, profile_id="wireguard-corp"),
        Request(command=Command.CONFIRM, profile_id="wireguard-corp"),
    ],
)
def test_a_request_survives_the_round_trip(request_: Request) -> None:
    assert Request.decode(request_.encode()) == request_


def test_an_encoded_message_ends_in_a_newline_and_has_none_inside() -> None:
    """El salto de linea es el separador de mensajes en el pipe."""
    encoded = Request(command=Command.CONNECT, profile_id="wireguard-corp").encode()

    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1


def test_list_does_not_carry_a_profile() -> None:
    encoded = Request(command=Command.LIST).encode()

    assert b"profile_id" not in encoded


def test_only_connect_carries_the_user_confirmation() -> None:
    """Lo que no significa nada en un comando, no viaja en ese comando."""
    encoded = Request(command=Command.STATUS, profile_id="wireguard-corp").encode()

    assert b"user_confirmed" not in encoded


# --------------------------------------------------------------------------
# Lo que no se acepta
# --------------------------------------------------------------------------


def test_a_message_bigger_than_the_limit_is_rejected_before_parsing() -> None:
    """Un cliente sin privilegios no reserva memoria sin limite en SYSTEM."""
    huge = b'{"version":1,"command":"list","x":"' + b"a" * MAX_REQUEST_BYTES + b'"}'

    with pytest.raises(ProtocolError, match="demasiado larga"):
        Request.decode(huge)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"no soy json",
        b"[1, 2, 3]",  # JSON valido, pero no un objeto
        b'"una cadena"',
        b"null",
        b"42",
    ],
)
def test_something_that_is_not_a_json_object_is_rejected(payload: bytes) -> None:
    with pytest.raises(ProtocolError):
        Request.decode(payload)


def test_a_message_that_is_not_utf8_is_rejected() -> None:
    with pytest.raises(ProtocolError, match="UTF-8"):
        Request.decode(b'{"version":1,"command":"\xff\xfe"}')


@pytest.mark.parametrize("version", [0, 2, "1", None, 1.0, True, [1]])
def test_another_protocol_version_is_rejected(version: object) -> None:
    """`1.0 == 1` y `True == 1` en Python: comparar sin mirar el tipo no vale."""
    with pytest.raises(ProtocolError, match="version de protocolo"):
        Request.decode(raw(version=version, command="list"))


def test_a_missing_version_is_rejected() -> None:
    with pytest.raises(ProtocolError, match="version de protocolo"):
        Request.decode(raw(command="list"))


@pytest.mark.parametrize("command", ["", "conectar", "CONNECT", "exec", None, 3])
def test_an_unknown_command_is_rejected(command: object) -> None:
    """El conjunto de comandos es cerrado: lo que no esta, no se hace."""
    with pytest.raises(ProtocolError):
        Request.decode(raw(version=PROTOCOL_VERSION, command=command))


@pytest.mark.parametrize(
    "extra",
    [
        {"launch": r"C:\temp\mio.exe"},
        {"args": ["--config", r"C:\temp\mio.ovpn"]},
        {"target": r"\\servidor\share\x.exe"},
        {"routes": ["0.0.0.0/0"]},
        {"user_confirmed": True},  # valido en CONNECT, no aqui
    ],
)
def test_any_field_that_is_not_in_the_grammar_is_rejected(extra: dict[str, object]) -> None:
    """El nucleo del contrato: no hay hueco donde meter una ruta ni un argumento.

    No se ignora el campo de mas: se rechaza el mensaje entero. Ignorarlo seria
    aceptar que alguien habla otro protocolo y no saber cual.
    """
    with pytest.raises(ProtocolError, match="campos que no existen"):
        Request.decode(
            raw(version=PROTOCOL_VERSION, command="status", profile_id="wireguard-corp", **extra)
        )


def test_list_does_not_accept_a_profile_id() -> None:
    with pytest.raises(ProtocolError, match="campos que no existen"):
        Request.decode(raw(version=PROTOCOL_VERSION, command="list", profile_id="wireguard-corp"))


@pytest.mark.parametrize("command", ["launch", "connect", "disconnect", "status", "confirm"])
def test_a_command_about_a_profile_needs_one(command: str) -> None:
    with pytest.raises(ProtocolError, match="necesita un profile_id"):
        Request.decode(raw(version=PROTOCOL_VERSION, command=command))


@pytest.mark.parametrize(
    "profile_id",
    [
        r"..\..\Windows\System32\cmd.exe",
        "/etc/passwd",
        r"C:\temp\mio.exe",
        "wireguard corp",  # espacio
        "wireguard\ncorp",  # salto de linea: romperia el troceado de mensajes
        "wireguard;corp",
        "perfil'; DROP",
        "perfil\x00nulo",
        "",
        "x" * 65,
        123,
        None,
        ["wireguard-corp"],
    ],
)
def test_a_profile_id_outside_the_allowed_charset_is_rejected(profile_id: object) -> None:
    """El id se restringe aunque solo se use como clave de un diccionario.

    Defensa en profundidad: el dia que alguien lo use para otra cosa, ya viene
    limpio de fabrica.
    """
    with pytest.raises(ProtocolError):
        Request.decode(raw(version=PROTOCOL_VERSION, command="connect", profile_id=profile_id))


@pytest.mark.parametrize("value", ["si", 1, 0, "true", None, []])
def test_a_user_confirmation_that_is_not_a_boolean_is_rejected(value: object) -> None:
    """Nada de veracidad: `1` no es `True` cuando lo que se acepta es cortar el RDP."""
    with pytest.raises(ProtocolError, match="booleano"):
        Request.decode(
            raw(
                version=PROTOCOL_VERSION,
                command="connect",
                profile_id="wireguard-corp",
                user_confirmed=value,
            )
        )


def test_an_error_never_repeats_what_it_received() -> None:
    """Un mensaje hostil no acaba escrito en el log solo por venir mal formado."""
    secreto = "token-secretisimo-que-no-debe-salir"

    with pytest.raises(ProtocolError) as error:
        Request.decode(
            raw(version=PROTOCOL_VERSION, command="status", profile_id=f"C:\\temp\\{secreto}.exe")
        )

    assert secreto not in str(error.value)


def test_a_malformed_command_error_does_not_repeat_it_either() -> None:
    with pytest.raises(ProtocolError) as error:
        Request.decode(raw(version=PROTOCOL_VERSION, command="rm -rf /"))

    assert "rm -rf" not in str(error.value)


# --------------------------------------------------------------------------
# Respuestas
# --------------------------------------------------------------------------


def test_a_response_survives_the_round_trip() -> None:
    response = Response(
        ok=True,
        message="conectado",
        state=ConnectionState.CONNECTED,
        profiles=(
            ProfileSummary(
                id="wireguard-corp",
                display_name="WireGuard corporativa",
                tunnel_type=TunnelType.FULL,
                state=ConnectionState.CONNECTED,
                capabilities=(Capability.LAUNCH, Capability.CONNECT),
                needs_confirmation=True,
            ),
        ),
        manual_disconnect_first=("forti-cliente-a",),
        warnings=("un aviso",),
    )

    assert Response.decode(response.encode()) == response


def test_an_empty_response_survives_the_round_trip() -> None:
    response = Response(ok=False, message="no esta en el catalogo firmado")

    decoded = Response.decode(response.encode())

    assert decoded == response
    assert decoded.state is None
    assert decoded.profiles == ()


def test_capabilities_travel_by_name() -> None:
    """`Capability` usa auto(): sus numeros cambian con solo reordenar el enum."""
    encoded = Response(
        ok=True,
        profiles=(
            ProfileSummary(
                id="azure-cliente-c",
                display_name="Azure cliente C",
                tunnel_type=TunnelType.FULL,
                state=ConnectionState.DISCONNECTED,
                capabilities=(Capability.LAUNCH,),
            ),
        ),
    ).encode()

    assert b'"LAUNCH"' in encoded


def test_a_summary_carries_nothing_the_interface_does_not_need() -> None:
    """Ni ruta del binario, ni argumentos, ni rutas de red: no viajan."""
    encoded = Response(
        ok=True,
        profiles=(
            ProfileSummary(
                id="wireguard-corp",
                display_name="WireGuard corporativa",
                tunnel_type=TunnelType.FULL,
                state=ConnectionState.CONNECTED,
            ),
        ),
    ).encode()

    for forbidden in (b"launch", b"target", b"args", b"routes", b"dns", b"probe_ip"):
        assert forbidden not in encoded


def test_failure_response() -> None:
    response = Response.failure("el conector no declara CONNECT")

    assert response.ok is False
    assert response.state is None


@pytest.mark.parametrize(
    "payload",
    [
        {"ok": "si"},
        {"ok": True, "state": "inventado"},
        {"ok": True, "profiles": "no soy una lista"},
        {"ok": True, "profiles": [{"id": "x"}]},
        {"ok": True, "warnings": [1, 2]},
        {"ok": True, "campo_de_mas": 1},
    ],
)
def test_a_malformed_response_is_rejected(payload: dict[str, object]) -> None:
    """La interfaz confia en el servicio, pero no se traga cualquier cosa."""
    with pytest.raises(ProtocolError):
        Response.decode(raw(version=PROTOCOL_VERSION, **payload))


def test_a_response_of_another_version_is_rejected() -> None:
    with pytest.raises(ProtocolError, match="version de protocolo"):
        Response.decode(raw(version=99, ok=True))


def test_an_unknown_capability_is_rejected() -> None:
    with pytest.raises(ProtocolError, match="capacidad desconocida"):
        Response.decode(
            raw(
                version=PROTOCOL_VERSION,
                ok=True,
                profiles=[
                    {
                        "id": "x",
                        "display_name": "X",
                        "tunnel_type": "full",
                        "state": "conectado",
                        "capabilities": ["ROOT"],
                        "needs_confirmation": False,
                    }
                ],
            )
        )


# --------------------------------------------------------------------------
# Forma del contrato
# --------------------------------------------------------------------------


def test_the_command_set_is_the_expected_one() -> None:
    """Anadir un comando es ampliar lo que un usuario sin privilegios puede pedir."""
    assert {c.value for c in Command} == {
        "list",
        "launch",
        "connect",
        "disconnect",
        "status",
        "confirm",
    }


# --------------------------------------------------------------------------
# Troceado del flujo
# --------------------------------------------------------------------------


def test_a_whole_message_arrives_in_one_piece() -> None:
    stream = MessageStream()
    encoded = Request(command=Command.LIST).encode()

    assert stream.feed(encoded) == [encoded.removesuffix(b"\n")]


def test_several_messages_in_the_same_read() -> None:
    """Un pipe es un flujo: lo que se lee no coincide con lo que se escribio."""
    stream = MessageStream()
    first = Request(command=Command.LIST).encode()
    second = Request(command=Command.STATUS, profile_id="wireguard-corp").encode()

    messages = stream.feed(first + second)

    assert [Request.decode(m) for m in messages] == [
        Request(command=Command.LIST),
        Request(command=Command.STATUS, profile_id="wireguard-corp"),
    ]


def test_a_message_split_across_reads() -> None:
    stream = MessageStream()
    encoded = Request(command=Command.CONNECT, profile_id="wireguard-corp").encode()

    assert stream.feed(encoded[:5]) == []
    assert stream.feed(encoded[5:20]) == []
    messages = stream.feed(encoded[20:])

    assert [Request.decode(m) for m in messages] == [
        Request(command=Command.CONNECT, profile_id="wireguard-corp")
    ]


def test_an_empty_read_yields_nothing() -> None:
    assert MessageStream().feed(b"") == []


def test_an_empty_line_is_handed_over_and_rejected_by_the_decoder() -> None:
    """No se descarta en silencio: se pasa, y el decodificador dice que no."""
    messages = MessageStream().feed(b"\n")

    assert messages == [b""]
    with pytest.raises(ProtocolError):
        Request.decode(messages[0])


def test_a_client_that_never_sends_a_newline_is_cut_off() -> None:
    """Aqui esta el motivo de que el limite se mire mientras se acumula.

    Si se leyera sin tope hasta encontrar el salto de linea, el limite de
    `Request.decode` no llegaria a comprobarse nunca, porque nunca habria un
    mensaje que comprobar.
    """
    stream = MessageStream()

    with pytest.raises(ProtocolError, match="sin terminar"):
        stream.feed(b"a" * (MAX_REQUEST_BYTES + 1))


def test_the_buffer_does_not_keep_growing_after_being_cut_off() -> None:
    stream = MessageStream()

    with pytest.raises(ProtocolError):
        stream.feed(b"a" * (MAX_REQUEST_BYTES + 1))

    assert stream.pending_bytes == 0


def test_a_complete_message_over_the_limit_is_rejected() -> None:
    stream = MessageStream()

    with pytest.raises(ProtocolError, match="mas de"):
        stream.feed(b"a" * (MAX_REQUEST_BYTES + 1) + b"\n")


def test_a_message_exactly_at_the_limit_still_passes() -> None:
    stream = MessageStream()

    assert stream.feed(b"a" * MAX_REQUEST_BYTES + b"\n") == [b"a" * MAX_REQUEST_BYTES]


def test_a_broken_stream_does_not_resync() -> None:
    """Reengancharse tras la basura permitiria colar un mensaje detras de ella."""
    stream = MessageStream()
    with pytest.raises(ProtocolError):
        stream.feed(b"a" * (MAX_REQUEST_BYTES + 1))

    with pytest.raises(ProtocolError, match="venia roto"):
        stream.feed(Request(command=Command.LIST).encode())


def test_responses_need_their_own_limit() -> None:
    """Un LIST con el catalogo entero pasa de largo el limite de una peticion."""
    catalog = Response(
        ok=True,
        profiles=tuple(
            ProfileSummary(
                id=f"perfil-{index:03d}",
                display_name=f"Perfil numero {index}",
                tunnel_type=TunnelType.SPLIT,
                state=ConnectionState.DISCONNECTED,
                capabilities=(Capability.LAUNCH,),
            )
            for index in range(40)
        ),
    ).encode()

    assert len(catalog) > MAX_REQUEST_BYTES
    assert MessageStream(MAX_RESPONSE_BYTES).feed(catalog) == [catalog.removesuffix(b"\n")]


def test_no_command_carries_free_text() -> None:
    """Ni un solo campo del que se pueda sacar una ruta o un argumento.

    Si este test empieza a estorbar, la pregunta no es como arreglarlo: es que
    campo se acaba de anadir y quien lo va a usar en el proceso privilegiado.
    """
    fields = set(Request.__dataclass_fields__)

    assert fields == {"command", "profile_id", "user_confirmed"}
