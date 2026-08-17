"""Tests de la capa de red.

No hay Windows ni PowerShell, asi que lo que se prueba es **que se le pediria
al sistema** y como se interpreta lo que conteste. Que `Get-NetRoute` devuelva
lo esperado se prueba en un puesto; que aqui no se pueda ejecutar otra cosa
que los tres scripts del paquete, se prueba ahora.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from vpnmanager.core.models import (
    LaunchKind,
    LaunchSpec,
    Profile,
    TunnelType,
)
from vpnmanager.core.watchdog import NetworkSnapshot
from vpnmanager.net.powershell import (
    MAX_OUTPUT_BYTES,
    PowerShellRunner,
    Script,
)
from vpnmanager.net.probe import PowerShellProbe
from vpnmanager.net.state import PowerShellNetworkController


class FakeRun:
    """Sustituye a subprocess.run y anota como se le llamo."""

    def __init__(self, stdout: bytes = b'{"ok":true}', returncode: int = 0) -> None:
        self.argv: list[str] | None = None
        self.kwargs: dict[str, Any] = {}
        self.stdout = stdout
        self.returncode = returncode
        self.error: Exception | None = None

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeRun:
        if self.error is not None:
            raise self.error
        self.argv = argv
        self.kwargs = kwargs
        return self


class StubRunner:
    """Un ejecutor que devuelve lo que se le diga, sin tocar el sistema."""

    def __init__(self, ok: bool = True, data: dict[str, object] | None = None) -> None:
        from vpnmanager.net.powershell import ScriptResult

        self.result = ScriptResult(ok=ok, data={} if data is None else data)
        self.calls: list[tuple[Script, dict[str, str]]] = []

    def run(self, script: Script, **parameters: str) -> Any:
        self.calls.append((script, parameters))
        return self.result


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    fake = FakeRun()
    monkeypatch.setattr("vpnmanager.net.powershell.subprocess.run", fake)
    return fake


def make_profile(
    tunnel_type: TunnelType = TunnelType.FULL,
    probe_ip: str | None = "10.20.0.1",
    target_networks: tuple[str, ...] = ("10.0.0.0/8",),
) -> Profile:
    return Profile(
        id="wireguard-corp",
        display_name="WireGuard corporativa",
        connector="wireguard",
        launch=LaunchSpec(kind=LaunchKind.EXE, target=r"C:\Program Files\WireGuard\wireguard.exe"),
        tunnel_type=tunnel_type,
        probe_ip=probe_ip,
        target_networks=target_networks,
    )


# --------------------------------------------------------------------------
# Que scripts existen
# --------------------------------------------------------------------------


def test_the_script_set_is_closed_and_the_files_are_there() -> None:
    """Si no esta en el enum, no existe. Y si esta, tiene que estar el fichero."""
    assert {s.value for s in Script} == {
        "Get-NetState.ps1",
        "Restore-NetState.ps1",
        "Test-TunnelState.ps1",
    }
    for script in Script:
        assert script.path.is_file(), f"falta {script.value} en el paquete"


def test_every_script_always_answers_in_json() -> None:
    """El contrato de la capa: nada de texto para parsear, ni al fallar."""
    for script in Script:
        source = script.path.read_text(encoding="utf-8")
        assert "ConvertTo-Json" in source
        assert "$ErrorActionPreference = 'Stop'" in source


# --------------------------------------------------------------------------
# Que se le pide a PowerShell
# --------------------------------------------------------------------------


def test_a_script_is_invoked_by_file_and_never_by_command(run: FakeRun) -> None:
    """`-Command` con la orden en una cadena es una inyeccion esperando."""
    PowerShellRunner().run(Script.GET_NET_STATE)

    assert run.argv is not None
    assert "-File" in run.argv
    assert "-Command" not in run.argv
    assert run.argv[-1] == str(Script.GET_NET_STATE.path)


def test_the_interpreter_is_an_absolute_path(run: FakeRun) -> None:
    """Buscarlo en el PATH seria dejar que el PATH elija que corre como SYSTEM."""
    PowerShellRunner().run(Script.GET_NET_STATE)

    assert run.argv is not None
    assert run.argv[0].startswith("C:\\Windows\\")


def test_the_shell_is_never_used(run: FakeRun) -> None:
    PowerShellRunner().run(Script.GET_NET_STATE)

    assert run.kwargs["shell"] is False


def test_parameters_travel_as_separate_list_items(run: FakeRun) -> None:
    """Un valor con espacios es un elemento mas, no un trozo de la orden."""
    PowerShellRunner().run(Script.TEST_TUNNEL, ProbeIp="10.20.0.1", TargetNetworks="10.0.0.0/8")

    assert run.argv is not None
    assert run.argv[-4:] == ["-ProbeIp", "10.20.0.1", "-TargetNetworks", "10.0.0.0/8"]


def test_there_is_always_a_timeout(run: FakeRun) -> None:
    """Un PowerShell colgado no puede colgar al servicio."""
    PowerShellRunner(timeout_seconds=12.0).run(Script.GET_NET_STATE)

    assert run.kwargs["timeout"] == 12.0


# --------------------------------------------------------------------------
# Que se hace con lo que conteste
# --------------------------------------------------------------------------


def test_a_successful_script_returns_its_data(run: FakeRun) -> None:
    run.stdout = b'{"ok":true,"routes":[{"destination":"0.0.0.0/0"}]}'

    result = PowerShellRunner().run(Script.GET_NET_STATE)

    assert result.ok
    assert result.data["routes"] == [{"destination": "0.0.0.0/0"}]


def test_a_script_that_hangs_is_an_error_not_an_exception(run: FakeRun) -> None:
    run.error = subprocess.TimeoutExpired(cmd="powershell", timeout=30)

    result = PowerShellRunner().run(Script.GET_NET_STATE)

    assert not result.ok
    assert "no respondio" in result.error


@pytest.mark.parametrize(
    "stdout",
    [b"", b"   ", b"no soy json", b"[1,2,3]", b'"una cadena"', b"\xff\xfe"],
)
def test_anything_that_is_not_a_json_object_is_an_error(run: FakeRun, stdout: bytes) -> None:
    run.stdout = stdout

    assert not PowerShellRunner().run(Script.GET_NET_STATE).ok


def test_a_script_that_says_it_failed_is_believed(run: FakeRun) -> None:
    run.stdout = b'{"ok":false,"error":"no se pudo leer el estado de red"}'

    result = PowerShellRunner().run(Script.GET_NET_STATE)

    assert not result.ok
    assert result.error == "no se pudo leer el estado de red"


@pytest.mark.parametrize("value", [1, "true", None, "ok"])
def test_only_a_real_true_counts_as_success(run: FakeRun, value: object) -> None:
    """Nada de veracidad: `1` no es `True` cuando lo que se decide es la red."""
    run.stdout = json.dumps({"ok": value}).encode("utf-8")

    assert not PowerShellRunner().run(Script.GET_NET_STATE).ok


def test_an_enormous_output_is_rejected(run: FakeRun) -> None:
    run.stdout = b"a" * (MAX_OUTPUT_BYTES + 1)

    result = PowerShellRunner().run(Script.GET_NET_STATE)

    assert not result.ok
    assert "enorme" in result.error


def test_a_missing_script_is_reported_not_raised(run: FakeRun, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "vpnmanager.net.powershell.SCRIPT_DIR", Script.GET_NET_STATE.path.parent / "no-existe"
    )

    result = PowerShellRunner().run(Script.GET_NET_STATE)

    assert not result.ok
    assert "falta el script" in result.error
    assert run.argv is None


# --------------------------------------------------------------------------
# La sonda
# --------------------------------------------------------------------------


def test_the_probe_reports_the_three_checks_separately() -> None:
    runner = StubRunner(ok=True, data={"adapterUp": True, "routed": True, "probeAnswers": False})

    result = PowerShellProbe(runner).check(make_profile())  # type: ignore[arg-type]

    assert result.adapter_up is True
    assert result.routed is True
    assert result.probe_answers is False
    assert result.connected is False


def test_the_probe_passes_the_networks_from_the_profile() -> None:
    runner = StubRunner()

    PowerShellProbe(runner).check(make_profile(target_networks=("10.0.0.0/8", "172.16.0.0/12")))  # type: ignore[arg-type]

    assert runner.calls[0][1] == {
        "ProbeIp": "10.20.0.1",
        "TargetNetworks": "10.0.0.0/8,172.16.0.0/12",
    }


def test_an_app_tunnel_is_not_probed() -> None:
    """IAP Desktop no monta adaptador ni rutas: decir que esta caido seria mentir."""
    runner = StubRunner()

    result = PowerShellProbe(runner).check(make_profile(TunnelType.APP, probe_ip=None))  # type: ignore[arg-type]

    assert result.checked is False
    assert runner.calls == []


def test_a_probe_that_could_not_run_says_so_instead_of_saying_down() -> None:
    """Confundirlas haria que un fallo del script se viera como un tunel roto."""
    result = PowerShellProbe(StubRunner(ok=False)).check(make_profile())  # type: ignore[arg-type]

    assert result.checked is False


@pytest.mark.parametrize("value", [1, "true", None])
def test_only_a_real_true_counts_in_the_probe(value: object) -> None:
    runner = StubRunner(ok=True, data={"adapterUp": value, "routed": value, "probeAnswers": value})

    result = PowerShellProbe(runner).check(make_profile())  # type: ignore[arg-type]

    assert result.connected is False


# --------------------------------------------------------------------------
# Foto y restauracion
# --------------------------------------------------------------------------


def test_the_snapshot_keeps_what_is_needed_to_restore() -> None:
    runner = StubRunner(
        ok=True,
        data={
            "ok": True,
            "routes": [
                {"destination": "0.0.0.0/0", "next_hop": "192.168.1.1", "interfaceIndex": 5}
            ],
            "dns": [{"interfaceAlias": "Ethernet", "servers": ["192.168.1.1"]}],
        },
    )

    snapshot = PowerShellNetworkController(runner).snapshot()  # type: ignore[arg-type]

    assert snapshot.usable
    assert "0.0.0.0/0" in snapshot.routes[0]
    assert "Ethernet" in snapshot.dns[0]
    assert json.loads(snapshot.payload)["routes"][0]["next_hop"] == "192.168.1.1"


def test_a_snapshot_that_could_not_be_taken_is_not_usable() -> None:
    """Y por eso el orquestador se niega a conectar un tunel completo con ella."""
    snapshot = PowerShellNetworkController(StubRunner(ok=False)).snapshot()  # type: ignore[arg-type]

    assert not snapshot.usable


def test_restoring_sends_back_the_payload_untouched() -> None:
    runner = StubRunner(ok=True)
    snapshot = NetworkSnapshot(payload='{"ok":true,"routes":[]}')

    assert PowerShellNetworkController(runner).restore(snapshot) is True  # type: ignore[arg-type]
    assert runner.calls[0][0] is Script.RESTORE_NET_STATE
    assert runner.calls[0][1] == {"State": '{"ok":true,"routes":[]}'}


def test_restoring_an_empty_snapshot_does_nothing_and_says_it_failed() -> None:
    """Devolver exito seria peor: nadie se enteraria de que no se deshizo nada."""
    runner = StubRunner(ok=True)

    assert PowerShellNetworkController(runner).restore(NetworkSnapshot()) is False  # type: ignore[arg-type]
    assert runner.calls == []


def test_a_restore_that_fails_is_reported() -> None:
    runner = StubRunner(ok=False)

    assert PowerShellNetworkController(runner).restore(NetworkSnapshot(payload="{}")) is False  # type: ignore[arg-type]
