"""Tests del lanzador de procesos.

Aqui no se arranca ningun cliente VPN: no hay Windows y no hay clientes. Lo
que si se puede comprobar, y es lo que importa, es **que se le pediria al
sistema operativo**: la lista de argumentos exacta, que nunca hay `shell=True`,
y que un `LaunchSpec` invalido no llega a crear un proceso.

Que `wireguard.exe` obedezca ya es otra historia, y esa se prueba en un puesto.
"""

from __future__ import annotations

from typing import Any

import pytest

from vpnmanager.connectors.process import (
    UnavailableUserSession,
    WindowsProcessLauncher,
    clean_environment,
)
from vpnmanager.core.models import LaunchContext, LaunchKind, LaunchSpec

WIREGUARD_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
AZURE_PFN = "Microsoft.AzureVpn_8wekyb3d8bbwe!App"


class FakePopen:
    """Sustituye a subprocess.Popen y anota como se le llamo."""

    def __init__(self) -> None:
        self.argv: list[str] | None = None
        self.kwargs: dict[str, Any] = {}
        self.error: OSError | None = None
        self.pid = 4242

    def __call__(self, argv: list[str], **kwargs: Any) -> FakePopen:
        if self.error is not None:
            raise self.error
        self.argv = argv
        self.kwargs = kwargs
        return self


class RecordingUserSession:
    def __init__(self) -> None:
        self.specs: list[LaunchSpec] = []

    def start_for_user(self, spec: LaunchSpec) -> Any:
        from vpnmanager.connectors.base import LaunchOutcome

        self.specs.append(spec)
        return LaunchOutcome(started=True, pid=99)


@pytest.fixture
def popen(monkeypatch: pytest.MonkeyPatch) -> FakePopen:
    fake = FakePopen()
    monkeypatch.setattr("vpnmanager.connectors.process.subprocess.Popen", fake)
    return fake


def service_spec(target: str = WIREGUARD_EXE, args: tuple[str, ...] = ()) -> LaunchSpec:
    return LaunchSpec(
        kind=LaunchKind.EXE,
        target=target,
        args=args,
        context=LaunchContext.SERVICE,
    )


# --------------------------------------------------------------------------
# Que se le pide al sistema
# --------------------------------------------------------------------------


def test_an_exe_is_launched_with_its_arguments_as_a_list(popen: FakePopen) -> None:
    """Nunca una cadena: un espacio en 'Program Files' no puede ser un separador."""
    launcher = WindowsProcessLauncher()

    outcome = launcher.start(service_spec(args=("/installtunnelservice", "corp.conf")))

    assert outcome.started
    assert popen.argv == [WIREGUARD_EXE, "/installtunnelservice", "corp.conf"]


def test_the_shell_is_never_used(popen: FakePopen) -> None:
    """La regla que no se negocia en todo el repositorio."""
    WindowsProcessLauncher().start(service_spec())

    assert popen.kwargs["shell"] is False


def test_the_child_gets_no_standard_streams(popen: FakePopen) -> None:
    """Un cliente VPN no tiene nada que decirle por consola a un servicio."""
    WindowsProcessLauncher().start(service_spec())

    assert popen.kwargs["stdin"] is not None
    assert popen.kwargs["close_fds"] is True


def test_an_msix_is_opened_through_the_shell_folder(popen: FakePopen) -> None:
    """Una app de Store no tiene ruta: se abre por su Package Family Name."""
    spec = LaunchSpec(kind=LaunchKind.MSIX, target=AZURE_PFN)

    WindowsProcessLauncher().start_here(spec)

    assert popen.argv == [r"C:\Windows\explorer.exe", f"shell:AppsFolder\\{AZURE_PFN}"]


def test_an_msix_reports_no_pid(popen: FakePopen) -> None:
    """El pid seria el del explorador, y TERMINATE mataria el escritorio."""
    spec = LaunchSpec(kind=LaunchKind.MSIX, target=AZURE_PFN)

    outcome = WindowsProcessLauncher().start_here(spec)

    assert outcome.started
    assert outcome.pid is None


def test_an_exe_reports_its_pid(popen: FakePopen) -> None:
    outcome = WindowsProcessLauncher().start(service_spec())

    assert outcome.pid == 4242


# --------------------------------------------------------------------------
# Lo que no se llega a arrancar
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        r"C:\temp\conectar.bat",
        "wireguard.exe",
        r"\\servidor\share\wireguard.exe",
        "",
    ],
)
def test_an_invalid_spec_never_creates_a_process(popen: FakePopen, target: str) -> None:
    """Ultima puerta antes de crear un proceso como SYSTEM."""
    outcome = WindowsProcessLauncher().start(service_spec(target))

    assert not outcome.started
    assert "launch invalido" in outcome.detail
    assert popen.argv is None


def test_a_client_that_is_not_installed_is_reported_not_raised(popen: FakePopen) -> None:
    """Que falte un cliente en un puesto es informacion, no una excepcion."""
    popen.error = FileNotFoundError(2, "El sistema no puede encontrar el archivo")

    outcome = WindowsProcessLauncher().start(service_spec())

    assert not outcome.started
    assert "encontrar el archivo" in outcome.detail


def test_a_permission_error_is_reported_too(popen: FakePopen) -> None:
    popen.error = PermissionError(13, "Acceso denegado")

    outcome = WindowsProcessLauncher().start(service_spec())

    assert not outcome.started
    assert "Acceso denegado" in outcome.detail


# --------------------------------------------------------------------------
# Sesion 0: quien arranca que
# --------------------------------------------------------------------------


def test_a_user_session_spec_is_not_launched_by_the_service(popen: FakePopen) -> None:
    """Un cliente con interfaz lanzado desde SYSTEM seria invisible."""
    session = RecordingUserSession()
    launcher = WindowsProcessLauncher(user_session=session)
    spec = LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE)

    outcome = launcher.start(spec)

    assert outcome.started
    assert session.specs == [spec]
    assert popen.argv is None


def test_a_service_spec_is_launched_here(popen: FakePopen) -> None:
    """`/installtunnelservice` necesita privilegio y no habla con nadie."""
    session = RecordingUserSession()

    WindowsProcessLauncher(user_session=session).start(service_spec())

    assert session.specs == []
    assert popen.argv is not None


def test_the_user_session_is_the_default_context() -> None:
    """Correr como SYSTEM hay que pedirlo a proposito, no cae por comodidad."""
    assert LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE).context is (
        LaunchContext.USER_SESSION
    )


def test_without_an_interface_connected_it_says_so(popen: FakePopen) -> None:
    """Pasa siempre entre que arranca el servicio y alguien inicia sesion."""
    outcome = WindowsProcessLauncher().start(LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE))

    assert not outcome.started
    assert "sesion de usuario" in outcome.detail
    assert popen.argv is None


def test_the_unavailable_session_never_starts_anything() -> None:
    outcome = UnavailableUserSession().start_for_user(
        LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE)
    )

    assert not outcome.started
    assert outcome.pid is None


# --------------------------------------------------------------------------
# Desde que carpeta se arranca
# --------------------------------------------------------------------------


def test_a_client_starts_from_its_own_folder(popen: FakePopen) -> None:
    """Como haria un acceso directo, que lleva su «Iniciar en».

    `subprocess.Popen` hereda el directorio de quien lanza —la carpeta de VPN
    Manager— y hay clientes que no lo soportan: FortiClient VPN revienta en su
    propio Logger buscando configuracion por ruta relativa.
    """
    WindowsProcessLauncher().start_here(LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE))

    assert popen.kwargs["cwd"] == r"C:\Program Files\WireGuard"


def test_the_folder_is_the_one_of_the_target_not_of_vpn_manager(popen: FakePopen) -> None:
    forticlient = r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"

    WindowsProcessLauncher().start_here(LaunchSpec(kind=LaunchKind.EXE, target=forticlient))

    assert popen.kwargs["cwd"] == r"C:\Program Files\Fortinet\FortiClient"


def test_an_msix_inherits_the_folder(popen: FakePopen) -> None:
    """Quien arranca es el explorador y no hay ninguna ruta de por medio."""
    WindowsProcessLauncher().start_here(LaunchSpec(kind=LaunchKind.MSIX, target=AZURE_PFN))

    assert popen.kwargs["cwd"] is None


def test_the_folder_does_not_change_the_arguments(popen: FakePopen) -> None:
    """El .exe se sigue invocando por su ruta completa, no por su nombre."""
    WindowsProcessLauncher().start_here(
        LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE, args=("/installtunnelservice",))
    )

    assert popen.argv == [WIREGUARD_EXE, "/installtunnelservice"]
    assert popen.kwargs["shell"] is False


# --------------------------------------------------------------------------
# Con que entorno se arranca
# --------------------------------------------------------------------------

BUNDLE = r"C:\Program Files\VpnManager\ui\_internal"
BUNDLE_DIRS = (BUNDLE,)


def test_the_bundle_is_taken_out_of_the_path() -> None:
    """Era lo que impedia abrir FortiClient.

    Su modulo nativo fallaba con el error 126 de Windows —falta una DLL de la
    que depende, no el modulo— porque heredaba nuestro PATH y cargaba nuestro
    VCRUNTIME en vez del suyo.
    """
    environ = {"PATH": rf"{BUNDLE};C:\Windows\system32;C:\Windows"}

    env = clean_environment(environ, BUNDLE_DIRS)

    assert env["PATH"] == r"C:\Windows\system32;C:\Windows"


def test_subdirectories_of_the_bundle_also_go() -> None:
    environ = {"PATH": rf"{BUNDLE}\PySide6;C:\Windows\system32"}

    env = clean_environment(environ, BUNDLE_DIRS)

    assert env["PATH"] == r"C:\Windows\system32"


def test_the_rest_of_the_environment_survives() -> None:
    """El cliente necesita el entorno del usuario: solo se quita lo nuestro."""
    environ = {
        "PATH": r"C:\Windows\system32",
        "USERPROFILE": r"C:\Users\test",
        "APPDATA": r"C:\Users\test\AppData\Roaming",
        "HOMEDRIVE": "H:",
    }

    env = clean_environment(environ, BUNDLE_DIRS)

    assert env["USERPROFILE"] == r"C:\Users\test"
    assert env["APPDATA"] == r"C:\Users\test\AppData\Roaming"
    assert env["HOMEDRIVE"] == "H:"


@pytest.mark.parametrize(
    "name",
    [
        "_MEIPASS2",
        "PYTHONHOME",
        "PYTHONPATH",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "SSL_CERT_FILE",
    ],
)
def test_what_the_bundle_added_is_removed(name: str) -> None:
    """Apuntan a nuestras librerias y a nuestros certificados, no a los suyos."""
    env = clean_environment({name: "lo que sea", "PATH": ""}, BUNDLE_DIRS)

    assert name not in env


def test_a_path_comparison_ignores_case_and_separators() -> None:
    """Windows no distingue mayusculas en las rutas."""
    environ = {"PATH": r"c:\program files\vpnmanager\ui\_internal\;C:\Windows"}

    env = clean_environment(environ, BUNDLE_DIRS)

    assert env["PATH"] == r"C:\Windows"


def test_without_a_bundle_the_path_is_left_alone() -> None:
    """Ejecutando desde el repositorio no hay nada nuestro que quitar."""
    environ = {"PATH": r"C:\Windows\system32;C:\Windows"}

    assert clean_environment(environ, ()).get("PATH") == r"C:\Windows\system32;C:\Windows"


def test_an_environment_without_path_does_not_break() -> None:
    assert clean_environment({"USERPROFILE": "x"}, BUNDLE_DIRS) == {"USERPROFILE": "x"}


def test_the_launch_uses_the_clean_environment(popen: FakePopen) -> None:
    """Que exista la funcion no sirve de nada si no se usa al arrancar."""
    WindowsProcessLauncher().start_here(LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE))

    assert "env" in popen.kwargs
    assert popen.kwargs["env"] is not None


def test_the_clean_environment_is_never_empty(popen: FakePopen) -> None:
    """Pasar un entorno vacio dejaria al cliente sin USERPROFILE ni APPDATA.

    Ahi es donde los clientes VPN guardan su configuracion, que es justo lo
    que este programa no quiere tocar.
    """
    WindowsProcessLauncher().start_here(LaunchSpec(kind=LaunchKind.EXE, target=WIREGUARD_EXE))

    assert len(popen.kwargs["env"]) > 0
