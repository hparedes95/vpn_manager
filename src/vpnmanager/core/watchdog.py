"""Watchdog de reversion: el seguro contra quedarse fuera del equipo.

El PC de oficina es el destino de sesiones RDP. Conectar un tunel completo
corta esa sesion, asi que si algo sale mal justo despues de conectar, quien lo
pulso ya no puede entrar a arreglarlo: hay que ir andando hasta la maquina.

De ahi el trato: antes de conectar un `FULL`, el servicio guarda como estaba
la red, arma este temporizador y conecta. Si la interfaz confirma dentro de la
ventana, se desarma. Si no confirma —porque la interfaz murio, o porque el
tunel dejo el equipo incomunicado— la conexion se deshace sola y la red vuelve
a como estaba.

Aqui no hay hilos ni esperas. Este modulo solo sabe decir si una ventana ha
vencido, que es una resta; el temporizador de verdad y la restauracion de la
red son del servicio. Asi la ventana de 90 segundos se prueba en microsegundos
y sin Windows delante.

El reloj es `time.monotonic` a proposito: un ajuste de hora por NTP o un
cambio de horario no puede hacer que una ventana de 90 segundos venza de
golpe, ni que no venza nunca.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

DEFAULT_WINDOW_SECONDS: Final = 90.0


@dataclass(frozen=True)
class NetworkSnapshot:
    """Como estaba la red antes de tocarla.

    Lo rellena `net/`, que es quien sabe leerla. Aqui solo se guarda para
    poder devolverla intacta cuando haya que deshacer.

    `routes` y `dns` son un resumen legible, para el log y para la interfaz.
    `payload` es lo que `net/` necesita de verdad para restaurar, en su propio
    formato, y el nucleo no lo interpreta: si lo interpretara, tendria que
    saber de tablas de rutas de Windows, y entonces dejaria de ser portable.
    """

    routes: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    payload: str = ""

    @property
    def usable(self) -> bool:
        """Si con esta foto se puede restaurar algo.

        Una foto vacia no es una foto de una red vacia: es que no se pudo
        sacar. Armar el watchdog con ella seria confiar en un seguro que no
        tiene nada dentro.
        """
        return bool(self.payload)


@dataclass(frozen=True)
class Reversion:
    """Orden de deshacer: desconectar el perfil y restaurar la red."""

    profile_id: str
    snapshot: NetworkSnapshot
    reason: str


@dataclass(frozen=True)
class _Armed:
    profile_id: str
    snapshot: NetworkSnapshot
    armed_at: float


@dataclass
class Watchdog:
    """Ventanas de confirmacion abiertas, y cuales han vencido.

    No arranca nada ni restaura nada: responde preguntas. El servicio lo
    consulta en su propio ciclo y ejecuta lo que salga de `collect_expired`.
    """

    window_seconds: float = DEFAULT_WINDOW_SECONDS
    clock: Callable[[], float] = time.monotonic
    _armed: dict[str, _Armed] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            # Una ventana de cero revierte antes de que a nadie le de tiempo a
            # confirmar; una negativa no vence nunca. Las dos convierten el
            # seguro en un estorbo o en un adorno.
            raise ValueError("la ventana del watchdog tiene que ser mayor que cero")

    def arm(self, profile_id: str, snapshot: NetworkSnapshot) -> None:
        """Abre la ventana de confirmacion de un perfil.

        Rearmar el mismo perfil reinicia su ventana en vez de duplicarla: un
        reintento no debe arrastrar el reloj del intento anterior.
        """
        self._armed[profile_id] = _Armed(
            profile_id=profile_id,
            snapshot=snapshot,
            armed_at=self.clock(),
        )

    def confirm(self, profile_id: str) -> bool:
        """La interfaz dice que la conexion funciona. Devuelve si se desarmo.

        Una confirmacion que llega con la ventana ya vencida **no vale**. Es
        deliberado: si valiera, que el equipo revierta o no dependeria de por
        donde ande el ciclo del servicio en ese instante, y un seguro que a
        veces salta y a veces no es peor que no tenerlo. Revertir de mas
        cuesta una reconexion; revertir de menos cuesta ir hasta el equipo.
        """
        armed = self._armed.get(profile_id)
        if armed is None or self._has_expired(armed):
            return False
        del self._armed[profile_id]
        return True

    def cancel(self, profile_id: str) -> bool:
        """Desarma sin revertir. Devuelve si habia algo que desarmar.

        Para cuando la conexion fallo y el servicio ya limpio lo suyo: la
        ventana ya no protege nada y dejarla abierta solo produciria una
        reversion sobre algo que no esta conectado.
        """
        return self._armed.pop(profile_id, None) is not None

    def collect_expired(self) -> tuple[Reversion, ...]:
        """Las reversiones pendientes, y las descuenta.

        Se entregan una sola vez. Si se devolvieran en cada consulta, un
        servicio que llame dos veces revertiria dos veces sobre una red que ya
        habia vuelto a su sitio.
        """
        expired = [armed for armed in self._armed.values() if self._has_expired(armed)]
        for armed in expired:
            del self._armed[armed.profile_id]
        return tuple(
            Reversion(
                profile_id=armed.profile_id,
                snapshot=armed.snapshot,
                reason=(
                    f"la interfaz no confirmo la conexion en "
                    f"{self.window_seconds:g} s: se deshace y se restaura la red"
                ),
            )
            for armed in expired
        )

    def revert_all(self, reason: str) -> tuple[Reversion, ...]:
        """Todo lo armado, haya vencido o no, y lo descuenta.

        Para cuando el servicio se para: una ventana abierta protege porque
        alguien la vigila, y al irse ya no hay nadie. Dejar un tunel completo
        arriba sin vigilante es exactamente lo que este modulo existe para
        impedir.
        """
        armed = list(self._armed.values())
        self._armed.clear()
        return tuple(
            Reversion(profile_id=entry.profile_id, snapshot=entry.snapshot, reason=reason)
            for entry in armed
        )

    def is_armed(self, profile_id: str) -> bool:
        return profile_id in self._armed

    def armed_profiles(self) -> tuple[str, ...]:
        return tuple(self._armed)

    def seconds_left(self, profile_id: str) -> float | None:
        """Lo que queda de ventana, para que la interfaz pueda enseñarlo.

        None si ese perfil no esta armado. Se acota por los dos lados: una
        ventana vencida es cero, y nunca queda mas de lo que dura la ventana
        entera aunque el reloj retroceda.
        """
        armed = self._armed.get(profile_id)
        if armed is None:
            return None
        remaining = self.window_seconds - self._elapsed(armed)
        return min(self.window_seconds, max(0.0, remaining))

    def _elapsed(self, armed: _Armed) -> float:
        return self.clock() - armed.armed_at

    def _has_expired(self, armed: _Armed) -> bool:
        # Con `>=`, a los 90 segundos exactos la ventana ya esta cerrada.
        return self._elapsed(armed) >= self.window_seconds
