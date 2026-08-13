"""Arbitro de tunel: decide que estorba antes de conectar un perfil.

Un solo perfil `FULL` activo a la vez, porque dos tuneles que capturan todo
el trafico se pelean por la tabla de rutas y el resultado no es determinista.
Los `SPLIT` conviven entre ellos y con un `FULL`. Los `APP` —IAP Desktop—
reenvian TCP por aplicacion, no tocan rutas ni DNS, y **nunca entran en el
arbitro**: ni molestan ni se les molesta.

Este modulo no ejecuta nada. Devuelve un `ConnectionPlan`, que es una hoja de
instrucciones para el servicio: a quien hay que echar primero, si hace falta
que el usuario confirme, y si hay que armar el watchdog antes de tocar la red.
Separar la decision de la ejecucion es lo que permite probar el arbitro entero
en CI, sin Windows y sin un cliente VPN delante.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from vpnmanager.core.models import ConnectionState, Profile, Session, TunnelType


# Un perfil ocupa la maquina mientras no este limpiamente desconectado. Un
# tunel en ERROR o caido cuenta: pudo dejar rutas puestas, y montar otro FULL
# encima de esos restos es la forma corta de dejar el equipo inalcanzable.
def is_occupying(session: Session) -> bool:
    return session.state is not ConnectionState.DISCONNECTED


# Volver a pedir la conexion de algo que ya esta conectado, o conectandose, no
# es un error del usuario: es una segunda pulsacion. Se responde que no hay
# nada que hacer, en vez de rehacer el proceso entero.
REENTRY_REFUSALS = {
    ConnectionState.CONNECTED: "ya esta conectado",
    ConnectionState.DEGRADED: "ya esta conectado, con avisos",
    ConnectionState.LAUNCHING: "ya se esta conectando",
    ConnectionState.WAITING_AUTH: "ya se esta conectando: falta que el usuario se autentique",
}


@dataclass(frozen=True)
class ConnectionPlan:
    """Lo que hay que hacer para conectar un perfil, sin hacerlo todavia."""

    profile_id: str
    disconnect_first: tuple[str, ...] = ()
    needs_confirmation: bool = False
    confirmation_reason: str = ""
    needs_watchdog: bool = False
    refusal: str = ""

    @property
    def allowed(self) -> bool:
        return not self.refusal

    @staticmethod
    def refused(profile_id: str, reason: str) -> ConnectionPlan:
        return ConnectionPlan(profile_id=profile_id, refusal=reason)


class TunnelArbiter:
    """Guarda el invariante: como mucho un tunel completo a la vez.

    Se construye con el catalogo firmado ya cargado. Solo conoce ids del
    catalogo; cualquier otro se rechaza, que es la misma regla que aplica el
    servidor del pipe.
    """

    def __init__(self, catalog: Mapping[str, Profile]) -> None:
        self._catalog = dict(catalog)

    def plan_connection(self, profile_id: str, sessions: Iterable[Session]) -> ConnectionPlan:
        target = self._catalog.get(profile_id)
        if target is None:
            return ConnectionPlan.refused(
                profile_id, "no esta en el catalogo firmado: no se conecta nada"
            )

        issues = target.validate()
        if issues:
            return ConnectionPlan.refused(profile_id, f"perfil invalido: {'; '.join(issues)}")

        live = list(sessions)

        reentry = self._reentry_refusal(target, live)
        if reentry is not None:
            return reentry

        if target.tunnel_type is TunnelType.FULL:
            conflict = self._unknown_occupant(live)
            if conflict is not None:
                return ConnectionPlan.refused(
                    profile_id,
                    f"hay una sesion activa de '{conflict}', que no esta en el catalogo: "
                    f"no se puede saber si es un tunel completo",
                )

        return ConnectionPlan(
            profile_id=profile_id,
            disconnect_first=self._conflicting_tunnels(target, live),
            needs_confirmation=target.breaks_local_connectivity,
            confirmation_reason=self._confirmation_reason(target),
            needs_watchdog=target.tunnel_type is TunnelType.FULL,
        )

    # -- Interno -----------------------------------------------------------

    def _reentry_refusal(self, target: Profile, sessions: list[Session]) -> ConnectionPlan | None:
        """Rechaza reconectar algo que ya esta en marcha.

        ERROR y DOWN no entran aqui a proposito: reintentar un perfil que
        fallo o que se ha caido es justo lo que el usuario querra hacer.
        """
        for session in sessions:
            if session.profile_id != target.id:
                continue
            reason = REENTRY_REFUSALS.get(session.state)
            if reason is not None:
                return ConnectionPlan.refused(target.id, reason)
        return None

    def _unknown_occupant(self, sessions: list[Session]) -> str | None:
        """Primera sesion viva cuyo perfil no esta en el catalogo, si la hay.

        Pasa si el catalogo se recarga mientras algo esta conectado. No se
        puede saber si eso que sigue vivo es un FULL, asi que tampoco se puede
        garantizar el invariante: mejor no conectar que conectar a ciegas.
        """
        for session in sessions:
            if is_occupying(session) and session.profile_id not in self._catalog:
                return session.profile_id
        return None

    def _conflicting_tunnels(self, target: Profile, sessions: list[Session]) -> tuple[str, ...]:
        """Los que hay que echar antes de conectar `target`.

        Solo un FULL echa a alguien, y solo a otros FULL. Un SPLIT convive con
        todo y un APP no entra siquiera en esta conversacion.
        """
        if target.tunnel_type is not TunnelType.FULL:
            return ()

        conflicting = [
            session.profile_id
            for session in sessions
            if session.profile_id != target.id
            and is_occupying(session)
            and self._is_full(session.profile_id)
        ]
        # Puede haber dos sesiones del mismo perfil si el estado se ha
        # descuadrado; se desconecta una vez, en el orden en que llegaron.
        return tuple(dict.fromkeys(conflicting))

    def _is_full(self, profile_id: str) -> bool:
        profile = self._catalog.get(profile_id)
        return profile is not None and profile.tunnel_type is TunnelType.FULL

    def _confirmation_reason(self, target: Profile) -> str:
        if not target.breaks_local_connectivity:
            return ""
        return (
            f"conectar '{target.display_name}' corta la conectividad local: "
            f"si estas trabajando por escritorio remoto contra este equipo, "
            f"perderas la sesion"
        )
