"""Tests del diagnostico.

Existe para que nadie tenga que ir ejecutando comandos de PowerShell dictados
uno a uno cuando algo falla. Lo que se protege aqui es que el informe no mienta:
que "no se pudo comprobar" no se confunda con "esta bien", que una comprobacion
que revienta no se lleve el informe por delante, y que el resumen diga la verdad.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from vpnmanager.core.diagnostics import MAX_DETAIL, Check, Report
from vpnmanager.core.models import LaunchKind, LaunchSpec, Profile, TunnelType
from vpnmanager.diagnose import DEFAULT_LAYOUT, SCRIPTS, collect

FORTICLIENT = r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"


def profile(profile_id: str = "forti", target: str = FORTICLIENT) -> Profile:
    return Profile(
        id=profile_id,
        display_name=f"Perfil {profile_id}",
        connector="forticlient",
        launch=LaunchSpec(kind=LaunchKind.EXE, target=target),
        tunnel_type=TunnelType.SPLIT,
        probe_ip="10.20.0.1",
    )


class FakeProbe:
    """Un puesto de mentira, con todo bien salvo lo que cada test rompa."""

    def __init__(
        self,
        *,
        missing: frozenset[str] = frozenset(),
        pipe: bool | None = True,
        profiles: Sequence[Profile] | None = None,
        issues: Sequence[str] = (),
        removed: int | None = 0,
        clients: Sequence[tuple[str, str]] = (("FortiClient VPN", FORTICLIENT),),
    ) -> None:
        self._missing = missing
        self._pipe = pipe
        self._profiles = (profile(),) if profiles is None else profiles
        self._issues = issues
        self._removed = removed
        self._clients = clients

    def exists(self, path: str) -> bool:
        return path not in self._missing

    def pipe_is_there(self) -> bool | None:
        return self._pipe

    def read_catalog(self) -> tuple[Sequence[Profile], Sequence[str]]:
        return self._profiles, self._issues

    def path_entries_removed(self) -> int | None:
        return self._removed

    def detected_clients(self) -> Sequence[tuple[str, str]]:
        return self._clients


def check_named(report: Report, fragment: str) -> Check:
    return next(check for check in report.checks if fragment in check.name)


# --------------------------------------------------------------------------
# El informe
# --------------------------------------------------------------------------


def test_a_healthy_workstation_reports_everything_ok() -> None:
    report = collect("0.1.0-dev+abc1234", FakeProbe())

    assert report.all_ok
    assert "Todo correcto" in report.render()


def test_the_version_is_in_the_report() -> None:
    """Sin ella no se sabe si el fallo que se mira ya estaba arreglado."""
    assert "0.1.0-dev+abc1234" in collect("0.1.0-dev+abc1234", FakeProbe()).render()


def test_what_could_not_be_checked_does_not_count_as_ok() -> None:
    """Un informe que dice "todo bien" porque no miro es peor que ninguno."""
    report = collect("v", FakeProbe(pipe=None))

    assert not report.all_ok
    assert len(report.unknown) == 1
    assert "sin comprobar" in report.render()


def test_a_failing_check_names_itself_in_the_summary() -> None:
    """Quien lo lea tiene que saber que esta roto sin recorrerse la lista."""
    report = collect("v", FakeProbe(pipe=False))

    summary = report.render().splitlines()[3]
    assert "El servicio esta escuchando" in summary


def test_a_check_that_blows_up_does_not_take_the_report_down() -> None:
    """Se pide un diagnostico justo cuando algo ya va mal."""

    class Exploding(FakeProbe):
        def pipe_is_there(self) -> bool | None:
            raise RuntimeError("boom")

    report = collect("v", Exploding())

    assert len(report.checks) == len(collect("v", FakeProbe()).checks)
    assert check_named(report, "escuchando").ok is None
    assert "boom" in check_named(report, "escuchando").detail


# --------------------------------------------------------------------------
# Lo que se comprueba
# --------------------------------------------------------------------------


def test_a_missing_executable_is_reported() -> None:
    report = collect("v", FakeProbe(missing=frozenset({DEFAULT_LAYOUT.ui_exe})))

    check = check_named(report, "Ejecutables")
    assert check.ok is False
    assert DEFAULT_LAYOUT.ui_exe in check.detail


def test_a_missing_script_is_reported_by_name() -> None:
    missing = f"{DEFAULT_LAYOUT.scripts_dir}\\{SCRIPTS[1]}"
    report = collect("v", FakeProbe(missing=frozenset({missing})))

    check = check_named(report, "Scripts")
    assert check.ok is False
    assert SCRIPTS[1] in check.detail


def test_a_service_that_is_not_listening_is_reported() -> None:
    """`Running` no significa escuchando, y esa es la comprobacion buena."""
    check = check_named(collect("v", FakeProbe(pipe=False)), "escuchando")

    assert check.ok is False
    assert "no esta atendiendo" in check.detail


def test_a_broken_catalog_lists_its_issues() -> None:
    """El catalogo es todo o nada: una errata deja el equipo sin ninguna VPN."""
    report = collect("v", FakeProbe(profiles=(), issues=("perfil[0]: id vacio",)))

    check = check_named(report, "Catalogo")
    assert check.ok is False
    assert "id vacio" in check.detail


def test_an_empty_catalog_is_a_failure() -> None:
    check = check_named(collect("v", FakeProbe(profiles=())), "Catalogo")

    assert check.ok is False


def test_a_client_that_is_not_where_the_catalog_says_is_the_headline() -> None:
    """El fallo mas probable y el mas confuso: no pasa nada y no se ve por que."""
    report = collect("v", FakeProbe(missing=frozenset({FORTICLIENT})))

    check = check_named(report, "clientes del catalogo")
    assert check.ok is False
    assert "forti" in check.detail
    assert FORTICLIENT in check.detail


def test_an_msix_profile_is_not_looked_for_on_disk() -> None:
    """Una app de Store no tiene ruta que comprobar: la resuelve el shell."""
    azure = Profile(
        id="azure",
        display_name="Azure",
        connector="azure",
        launch=LaunchSpec(kind=LaunchKind.MSIX, target="Microsoft.AzureVpn_8wekyb3d8bbwe!App"),
        tunnel_type=TunnelType.SPLIT,
        probe_ip="10.90.0.4",
    )
    # `missing` lo tiene todo: si mirara el disco, fallaria.
    probe = FakeProbe(profiles=(azure,), missing=frozenset({azure.launch.target}))

    assert check_named(collect("v", probe), "clientes del catalogo").ok is True


def test_the_path_check_says_when_it_is_doing_something() -> None:
    """El numero dice si el saneado del PATH aplica en esta maquina."""
    check = check_named(collect("v", FakeProbe(removed=3)), "PATH")

    assert check.ok is True
    assert "3 entrada" in check.detail


def test_the_path_check_survives_not_knowing() -> None:
    assert check_named(collect("v", FakeProbe(removed=None)), "PATH").ok is None


def test_nothing_in_the_report_suggests_it_changed_something() -> None:
    """Un diagnostico que modifica lo que diagnostica no sirve de nada."""
    assert "cambia nada" in collect("v", FakeProbe()).render().lower()


# --------------------------------------------------------------------------
# Como se escribe
# --------------------------------------------------------------------------


def test_a_long_detail_is_cut() -> None:
    """Un informe se pega en un mensaje: un PATH entero ahi estorba."""
    rendered = Check(name="x", ok=False, detail="y" * (MAX_DETAIL * 3)).render()

    assert len(rendered) < MAX_DETAIL * 2
    assert rendered.endswith("…")


def test_a_detail_with_newlines_stays_on_one_line() -> None:
    """Los saltos romperian la lista."""
    rendered = Check(name="x", ok=False, detail="una\ncosa\n\ny otra").render()

    assert rendered.count("\n") == 1
    assert "una cosa y otra" in rendered


@pytest.mark.parametrize(
    ("ok", "expected"),
    [(True, "OK"), (False, "FALLA"), (None, "?")],
)
def test_each_outcome_has_its_own_mark(ok: bool | None, expected: str) -> None:
    assert Check(name="x", ok=ok).mark == expected


def test_an_empty_report_is_not_ok() -> None:
    """Sin comprobaciones no se ha comprobado nada, y eso no es "todo bien"."""
    report = Report(version="v")

    assert not report.all_ok
    assert "No se pudo comprobar nada" in report.render()
