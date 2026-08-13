"""Tests del watchdog de reversion.

El reloj se inyecta, asi que la ventana de 90 segundos se prueba entera sin
esperar 90 segundos. Lo que se comprueba aqui es cuando revierte y cuando no,
que es lo unico que separa "el usuario se reconecta" de "hay que ir andando
hasta el equipo".
"""

from __future__ import annotations

import pytest

from vpnmanager.core.watchdog import (
    DEFAULT_WINDOW_SECONDS,
    NetworkSnapshot,
    Watchdog,
)

SNAPSHOT = NetworkSnapshot(routes=("0.0.0.0/0 via 192.168.1.1",), dns=("192.168.1.1",))


class FakeClock:
    """Reloj de mentira: solo avanza cuando se le dice."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def watchdog(clock: FakeClock) -> Watchdog:
    return Watchdog(window_seconds=90.0, clock=clock)


# --------------------------------------------------------------------------
# La ventana
# --------------------------------------------------------------------------


def test_the_default_window_is_ninety_seconds() -> None:
    assert DEFAULT_WINDOW_SECONDS == 90.0


def test_nothing_expires_while_the_window_is_open(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)

    clock.advance(89.9)

    assert watchdog.collect_expired() == ()
    assert watchdog.is_armed("full-rdp")


def test_the_window_is_over_at_exactly_the_limit(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)

    clock.advance(90.0)

    assert len(watchdog.collect_expired()) == 1


def test_an_expired_window_orders_the_reversion(watchdog: Watchdog, clock: FakeClock) -> None:
    """Sin esto, un fallo deja el equipo inalcanzable hasta ir fisicamente."""
    watchdog.arm("full-rdp", SNAPSHOT)

    clock.advance(120.0)
    reversions = watchdog.collect_expired()

    assert len(reversions) == 1
    assert reversions[0].profile_id == "full-rdp"
    assert reversions[0].snapshot == SNAPSHOT
    assert "90" in reversions[0].reason


def test_the_snapshot_comes_back_untouched(watchdog: Watchdog, clock: FakeClock) -> None:
    """Es lo que se le devuelve a la red: no puede llegar alterado."""
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(120.0)

    assert watchdog.collect_expired()[0].snapshot is SNAPSHOT


@pytest.mark.parametrize("window", [0.0, -1.0])
def test_a_window_that_protects_nothing_is_rejected(window: float) -> None:
    """Cero revierte antes de que de tiempo a confirmar; negativa no vence nunca."""
    with pytest.raises(ValueError, match="mayor que cero"):
        Watchdog(window_seconds=window)


# --------------------------------------------------------------------------
# Confirmar y cancelar
# --------------------------------------------------------------------------


def test_confirming_inside_the_window_disarms(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(30.0)

    assert watchdog.confirm("full-rdp") is True

    clock.advance(120.0)
    assert watchdog.collect_expired() == ()
    assert not watchdog.is_armed("full-rdp")


def test_confirming_after_the_window_does_not_stop_the_reversion(
    watchdog: Watchdog, clock: FakeClock
) -> None:
    """Deliberado: un seguro que a veces salta y a veces no es peor que ninguno.

    Si valiera una confirmacion tardia, que el equipo revierta o no dependeria
    de por donde ande el ciclo del servicio en ese instante.
    """
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(91.0)

    assert watchdog.confirm("full-rdp") is False
    assert len(watchdog.collect_expired()) == 1


def test_confirming_something_that_was_never_armed(watchdog: Watchdog) -> None:
    assert watchdog.confirm("full-rdp") is False


def test_cancelling_disarms_without_reverting(watchdog: Watchdog, clock: FakeClock) -> None:
    """La conexion fallo y el servicio ya limpio: no hay nada que deshacer."""
    watchdog.arm("full-rdp", SNAPSHOT)

    assert watchdog.cancel("full-rdp") is True

    clock.advance(120.0)
    assert watchdog.collect_expired() == ()


def test_cancelling_something_that_was_never_armed(watchdog: Watchdog) -> None:
    assert watchdog.cancel("full-rdp") is False


def test_cancelling_after_the_window_also_avoids_the_reversion(
    watchdog: Watchdog, clock: FakeClock
) -> None:
    """A diferencia de confirmar: cancelar lo pide el propio servicio, no la interfaz."""
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(120.0)

    assert watchdog.cancel("full-rdp") is True
    assert watchdog.collect_expired() == ()


# --------------------------------------------------------------------------
# Entregar una reversion una sola vez
# --------------------------------------------------------------------------


def test_a_reversion_is_handed_over_only_once(watchdog: Watchdog, clock: FakeClock) -> None:
    """Devolverla en cada consulta revertiria dos veces sobre una red ya restaurada."""
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(120.0)

    assert len(watchdog.collect_expired()) == 1
    assert watchdog.collect_expired() == ()
    assert not watchdog.is_armed("full-rdp")


def test_collecting_with_nothing_armed(watchdog: Watchdog) -> None:
    assert watchdog.collect_expired() == ()


# --------------------------------------------------------------------------
# Varios perfiles a la vez
# --------------------------------------------------------------------------


def test_only_the_expired_one_is_reverted(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(60.0)
    watchdog.arm("split-b", NetworkSnapshot())

    clock.advance(40.0)  # el primero lleva 100 s, el segundo 40
    reversions = watchdog.collect_expired()

    assert [r.profile_id for r in reversions] == ["full-rdp"]
    assert watchdog.is_armed("split-b")


def test_rearming_restarts_the_window(watchdog: Watchdog, clock: FakeClock) -> None:
    """Un reintento no arrastra el reloj del intento anterior."""
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(80.0)
    watchdog.arm("full-rdp", SNAPSHOT)

    clock.advance(20.0)  # 100 s desde el primer armado, 20 desde el segundo

    assert watchdog.collect_expired() == ()
    assert watchdog.armed_profiles() == ("full-rdp",)


def test_rearming_does_not_duplicate_the_reversion(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(120.0)

    assert len(watchdog.collect_expired()) == 1


# --------------------------------------------------------------------------
# Lo que la interfaz puede enseñar
# --------------------------------------------------------------------------


def test_seconds_left_counts_down(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)

    assert watchdog.seconds_left("full-rdp") == 90.0
    clock.advance(30.0)
    assert watchdog.seconds_left("full-rdp") == 60.0


def test_seconds_left_never_goes_negative(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.arm("full-rdp", SNAPSHOT)
    clock.advance(200.0)

    assert watchdog.seconds_left("full-rdp") == 0.0


def test_seconds_left_of_something_not_armed(watchdog: Watchdog) -> None:
    assert watchdog.seconds_left("full-rdp") is None


def test_a_clock_that_goes_backwards_does_not_revert_early(
    watchdog: Watchdog, clock: FakeClock
) -> None:
    """Por eso el reloj por defecto es monotonic y no la hora del sistema.

    Un ajuste por NTP no puede hacer que una ventana de 90 s venza de golpe.
    """
    watchdog.arm("full-rdp", SNAPSHOT)

    clock.advance(-3600.0)

    assert watchdog.collect_expired() == ()
    assert watchdog.seconds_left("full-rdp") == 90.0


def test_a_watchdog_uses_a_monotonic_clock_by_default() -> None:
    import time

    assert Watchdog().clock is time.monotonic
