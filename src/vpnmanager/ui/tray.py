"""La bandeja: lo unico que el usuario ve.

Es fina a proposito. Todo lo que decide algo esta en `client.py` y se prueba
sin escritorio; aqui solo hay widgets y el hilo que los une. Si alguna vez hay
que escribir un `if` complicado en este fichero, es que le corresponde a
`client.py`.

**Este modulo no tiene tests y no puede tenerlos aqui:** PySide6 necesita un
escritorio, y en CI no hay ninguno. Lo que hay debajo si esta probado. Lo que
falta por comprobar en un puesto son cosas de mirar con los ojos: que el icono
aparezca, que el menu se lea, y que el aviso de HU-03 se entienda antes de
pulsar y no despues.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon

from vpnmanager.connectors.process import WindowsProcessLauncher
from vpnmanager.core.models import Capability, ConnectionState
from vpnmanager.core.protocol import ProfileSummary, Response
from vpnmanager.ui.client import ServiceClient, action_label, needs_asking_first
from vpnmanager.ui.transport import PipeTransport, PipeUnavailable

# Cada cuanto se refresca el menu y se confirman las conexiones en marcha. La
# ventana del watchdog son 90 s, asi que 10 deja margen de sobra para varios
# intentos antes de que venza.
REFRESH_MS = 10_000

_STATE_MARK = {
    ConnectionState.CONNECTED: "●",
    ConnectionState.DEGRADED: "◐",
    ConnectionState.DOWN: "○",
    ConnectionState.ERROR: "✕",
    ConnectionState.LAUNCHING: "…",
    ConnectionState.WAITING_AUTH: "…",
    ConnectionState.DISCONNECTED: "○",
}


class TrayApp:
    """Icono de bandeja con un menu por perfil."""

    def __init__(self, client: ServiceClient) -> None:
        self._client = client
        self._icon = QSystemTrayIcon(QIcon.fromTheme("network-vpn"))
        self._menu = QMenu()
        self._icon.setContextMenu(self._menu)
        self._watching: set[str] = set()

        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(REFRESH_MS)

    def start(self) -> None:
        self._icon.show()
        self._tick()

    # -- Ciclo -------------------------------------------------------------

    def _tick(self) -> None:
        """Refresca el menu y confirma lo que ya este conectado.

        Que esto deje de ejecutarse es justo lo que el servicio interpreta
        como "esta interfaz ya no esta": si el tunel se llevo por delante la
        sesion, nadie confirma y la conexion se deshace sola.
        """
        for profile_id in sorted(self._watching):
            try:
                self._client.confirm_if_connected(profile_id)
            except PipeUnavailable:
                return

        try:
            profiles = self._client.list_profiles()
        except PipeUnavailable as error:
            self._icon.setToolTip(f"VPN Manager: {error}")
            return

        self._icon.setToolTip("VPN Manager")
        self._rebuild(profiles)

    def _rebuild(self, profiles: tuple[ProfileSummary, ...]) -> None:
        self._menu.clear()
        for summary in profiles:
            mark = _STATE_MARK.get(summary.state, "○")
            action = QAction(
                f"{mark}  {summary.display_name} — {action_label(summary)}", self._menu
            )
            action.triggered.connect(lambda _checked=False, s=summary: self._act_on(s))
            self._menu.addAction(action)

        self._menu.addSeparator()
        quit_action = QAction("Salir", self._menu)
        quit_action.triggered.connect(QApplication.quit)
        self._menu.addAction(quit_action)

    # -- Acciones ----------------------------------------------------------

    def _act_on(self, summary: ProfileSummary) -> None:
        try:
            self._run_action(summary)
        except PipeUnavailable as error:
            self._warn("Sin conexion con el servicio", str(error))

    def _run_action(self, summary: ProfileSummary) -> None:
        if summary.state is ConnectionState.CONNECTED:
            if Capability.DISCONNECT in summary.capabilities:
                self._report(self._client.disconnect(summary.id))
                self._watching.discard(summary.id)
            return

        if needs_asking_first(summary) and not self._ask_about_losing_the_network(summary):
            return

        if Capability.CONNECT in summary.capabilities:
            response = self._client.connect(summary.id, user_confirmed=summary.needs_confirmation)
        else:
            response = self._client.launch(summary.id)

        if response.ok:
            # A partir de aqui hay que confirmar hasta que el tunel este
            # arriba, o el servicio lo deshara.
            self._watching.add(summary.id)
        self._report(response)

    def _ask_about_losing_the_network(self, summary: ProfileSummary) -> bool:
        """HU-03. La pregunta se hace **antes**, no despues de cortar la red.

        Quien pulsa esto suele estar trabajando por escritorio remoto contra
        este mismo equipo, y va a perder la sesion.
        """
        answer = QMessageBox.warning(
            None,
            "Vas a perder la conexion local",
            f"Conectar «{summary.display_name}» corta la conectividad local de este "
            f"equipo.\n\nSi estas trabajando por escritorio remoto contra el, perderas "
            f"la sesion en cuanto se conecte.\n\n¿Seguro que quieres continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Yes

    # -- Avisos ------------------------------------------------------------

    def _report(self, response: Response) -> None:
        if response.manual_disconnect_first:
            pending = ", ".join(response.manual_disconnect_first)
            self._warn(
                "Hay que desconectar algo a mano",
                f"{response.message}\n\nPerfiles: {pending}",
            )
            return

        if not response.ok:
            self._warn("No se pudo", response.message)
            return

        for warning in response.warnings:
            self._icon.showMessage("VPN Manager", warning, QSystemTrayIcon.MessageIcon.Warning)

    def _warn(self, title: str, detail: str) -> None:
        QMessageBox.warning(None, title, detail)


def main() -> int:
    """Punto de entrada de `vpnmgr-ui`."""
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(
            None,
            "VPN Manager",
            "Este escritorio no tiene area de notificacion, asi que no hay donde poner el icono.",
        )
        return 1

    client = ServiceClient(PipeTransport(), WindowsProcessLauncher())
    TrayApp(client).start()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
