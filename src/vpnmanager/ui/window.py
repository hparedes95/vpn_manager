"""La ventana de gestion: la lista de VPN y lo que se puede hacer con cada una.

La bandeja sola no basta para gestionar varias VPN: no deja ver de un vistazo
que hay conectado, ni por que algo fallo. Esto es lo que se abre al pulsar el
icono.

Sigue sin haber logica aqui. Que dice cada boton lo decide `client.py` a
partir de las capacidades que declara el conector, y que se puede conectar lo
decide el servicio. Esta ventana pinta y pregunta.

Cerrarla no cierra la aplicacion: se queda en la bandeja. Es deliberado,
porque mientras la interfaz vive es quien confirma las conexiones, y cerrarla
del todo haria que el servicio deshiciera los tuneles a los 90 segundos.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from vpnmanager.core.models import ConnectionState
from vpnmanager.core.protocol import ProfileSummary, Response
from vpnmanager.ui.client import (
    ServiceClient,
    action_label,
    can_act,
    is_open,
    needs_asking_first,
)
from vpnmanager.version import read_version

log = logging.getLogger("vpnmgr.ui")

_TUNNEL_LABEL = {"full": "Completo", "split": "Parcial", "app": "Por aplicacion"}

_STATE_COLOR = {
    ConnectionState.CONNECTED: "#1a7f37",
    ConnectionState.DEGRADED: "#9a6700",
    ConnectionState.DOWN: "#cf222e",
    ConnectionState.ERROR: "#cf222e",
    ConnectionState.LAUNCHING: "#0969da",
    ConnectionState.WAITING_AUTH: "#0969da",
    # Ni verde ni rojo: no se sabe. Se pinta como un aviso porque lo es,
    # pero no como un fallo, porque puede estar perfectamente conectada.
    ConnectionState.UNVERIFIED: "#9a6700",
    ConnectionState.DISCONNECTED: "#57606a",
}


class MainWindow(QWidget):
    """Lista de perfiles con su estado y un boton por perfil."""

    def __init__(self, client: ServiceClient, watching: set[str]) -> None:
        super().__init__()
        self._client = client
        # Compartido con la bandeja: lo que hay que seguir confirmando.
        self._watching = watching

        # Con la version: durante las pruebas se instalan builds seguidas y
        # "esto lleva ya el arreglo?" tiene que poder contestarse mirando.
        self.setWindowTitle(f"VPN Manager {read_version()}")
        self.resize(760, 420)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["VPN", "Tipo", "Estado", "", ""])
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        self._status = QLabel("Conectando con el servicio…")

        # Lo que ha ido pasando. Sin esto, un fallo se ve un segundo en un
        # cuadro de dialogo y ya no hay forma de releerlo.
        self._journal = QTextEdit()
        self._journal.setReadOnly(True)
        self._journal.setMaximumHeight(120)
        self._journal.setFont(QFont("Consolas", 9))

        manage = QPushButton("Gestionar VPN…")
        manage.setToolTip(
            "Anadir o quitar VPN del catalogo. Pide permisos de administrador: ese "
            "fichero decide que ejecuta el servicio como SYSTEM."
        )
        manage.clicked.connect(self._open_editor)

        refresh = QPushButton("Actualizar")
        refresh.clicked.connect(self.refresh_now)

        top = QHBoxLayout()
        top.addWidget(self._status, 1)
        top.addWidget(manage)
        top.addWidget(refresh)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._table, 1)
        layout.addWidget(QLabel("Actividad:"))
        layout.addWidget(self._journal)

    # -- Pintado -----------------------------------------------------------

    def show_profiles(self, profiles: tuple[ProfileSummary, ...]) -> None:
        self._status.setText(f"{len(profiles)} VPN en el catalogo")
        self._table.setRowCount(len(profiles))
        for row, summary in enumerate(profiles):
            self._table.setItem(row, 0, QTableWidgetItem(summary.display_name))
            self._table.setItem(row, 1, _tunnel_item(summary))
            self._table.setItem(row, 2, _state_item(summary))
            self._table.setCellWidget(row, 3, self._configure_button_for(summary))
            self._table.setCellWidget(row, 4, self._button_for(summary))

    def show_problem(self, detail: str) -> None:
        self._status.setText(f"Sin conexion con el servicio: {detail}")
        self._table.setRowCount(0)

    def note(self, text: str) -> None:
        self._journal.append(text)

    def _configure_button_for(self, summary: ProfileSummary) -> QPushButton:
        """Abrir el cliente oficial, para configurarlo alli.

        Separado de conectar a proposito. La configuracion de una VPN —SSO,
        IPSec, certificados, gateways— se hace una vez en el cliente del
        fabricante, que es el unico que la entiende, y este programa no la
        reimplementa. Sin este boton habia que ir a buscar el cliente al menu
        de inicio, que es justo el paso que este programa deberia ahorrar.
        """
        button = QPushButton("Abrir cliente…")
        button.setToolTip(
            "Abre el cliente oficial para configurar la VPN alli: usuario, "
            "gateway, certificados, SSO. No conecta nada."
        )
        button.clicked.connect(lambda _checked=False, s=summary: self.configure(s))
        return button

    def _button_for(self, summary: ProfileSummary) -> QPushButton:
        """El texto lo decide `client.py`, no esta ventana.

        Lo deducia por su cuenta y acababa diciendo "Desconectar en su cliente"
        donde la bandeja decia otra cosa para la misma fila. Un solo sitio
        decide, y las dos superficies lo leen.
        """
        button = QPushButton(action_label(summary))
        button.setEnabled(can_act(summary))
        if not can_act(summary):
            button.setToolTip("Este cliente no admite que se le pida desconectar: cierralo en el")
        button.clicked.connect(lambda _checked=False, s=summary: self.act_on(s))
        return button

    # -- Acciones ----------------------------------------------------------

    def _open_editor(self) -> None:
        """Abre el editor, elevado y en otro proceso.

        Esta ventana corre sin privilegios a proposito y no puede escribir el
        catalogo: si pudiera, cualquier usuario del puesto elegiria que ejecuta
        el servicio como SYSTEM.
        """
        from vpnmanager.ui.editor import relaunch_elevated

        if relaunch_elevated():
            self.note("· editor del catalogo abierto (como administrador)")
        else:
            self.note("✕ hace falta ser administrador para cambiar el catalogo")
            QMessageBox.information(
                self,
                "Hacen falta permisos de administrador",
                "El catalogo decide que binario ejecuta el servicio como SYSTEM, asi "
                "que solo lo puede cambiar un administrador.\n\nEs la misma "
                "proteccion que impide editarlo con el Bloc de notas.",
            )

    def refresh_now(self) -> None:
        """Lo rellena la bandeja en su ciclo; esto solo lo adelanta."""
        self.requested_refresh()

    def requested_refresh(self) -> None:  # se sustituye desde la bandeja
        pass

    def configure(self, summary: ProfileSummary) -> None:
        """Abre el cliente oficial y no toca nada mas."""
        if summary.needs_confirmation and not self._confirm_opening(summary):
            self.note(f"· {summary.display_name}: cancelado por el usuario")
            return

        response = self._client.launch(summary.id, user_confirmed=summary.needs_confirmation)
        self._report(summary, response)
        if response.ok:
            self.note(
                "  → configura la VPN en su cliente y guardala alli; "
                "aqui solo se gestiona la conexion"
            )
        self.requested_refresh()

    def _confirm_opening(self, summary: ProfileSummary) -> bool:
        """Abrir no es conectar, salvo que el cliente conecte solo al abrirse.

        Aqui no hay forma de saberlo, y la diferencia entre las dos cosas es la
        sesion remota de quien lo pulse. Preguntar de mas cuesta un clic.
        """
        return (
            QMessageBox.warning(
                self,
                "Este perfil corta la conectividad local",
                f"Abrir el cliente de «{summary.display_name}» no deberia conectar "
                f"nada.\n\nPero si ese cliente esta configurado para conectar al "
                f"arrancar, perderas la red de este equipo, y con ella cualquier "
                f"sesion remota contra el.\n\n¿Abrirlo de todas formas?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            == QMessageBox.StandardButton.Yes
        )

    def act_on(self, summary: ProfileSummary) -> None:
        if is_open(summary):
            # DISCONNECT vale para las dos cosas: pedirle al cliente que
            # desconecte, y —cuando nadie puede comprobarlo ni cerrarlo— que el
            # servicio lo de por cerrado porque lo dice quien esta delante.
            if can_act(summary):
                self._watching.discard(summary.id)
                self._report(summary, self._client.disconnect(summary.id))
            return

        if needs_asking_first(summary) and not self._confirm_losing_the_network(summary):
            self.note(f"· {summary.display_name}: cancelado por el usuario")
            return

        # Siempre CONNECT: solo ese camino pasa por el arbitro, guarda el
        # estado de red y arma el watchdog. El servicio decide si el conector
        # sabe conectar o solo abrir el cliente.
        response = self._client.connect(summary.id, user_confirmed=summary.needs_confirmation)
        if response.ok:
            self._watching.add(summary.id)
        self._report(summary, response)
        self.requested_refresh()

    def _confirm_losing_the_network(self, summary: ProfileSummary) -> bool:
        """HU-03. Se pregunta antes de cortar la red, no despues."""
        return (
            QMessageBox.warning(
                self,
                "Vas a perder la conexion local",
                f"Conectar «{summary.display_name}» corta la conectividad local de este "
                f"equipo.\n\nSi estas trabajando por escritorio remoto contra el, "
                f"perderas la sesion en cuanto se conecte.\n\n¿Seguro que quieres "
                f"continuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            == QMessageBox.StandardButton.Yes
        )

    def _report(self, summary: ProfileSummary, response: Response) -> None:
        mark = "·" if response.ok else "✕"
        self.note(f"{mark} {summary.display_name}: {response.message or 'hecho'}")
        for warning in response.warnings:
            self.note(f"  ⚠ {warning}")

        if response.manual_disconnect_first:
            pending = ", ".join(response.manual_disconnect_first)
            self.note(f"  → hay que desconectar a mano: {pending}")
            QMessageBox.warning(
                self,
                "Hay que desconectar algo a mano",
                f"{response.message}\n\nCierra estas VPN desde su propio cliente y "
                f"vuelve a intentarlo:\n{pending}",
            )
        elif not response.ok:
            QMessageBox.warning(self, "No se pudo", response.message)

    # -- Cierre ------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        """Cerrar la ventana no cierra la aplicacion.

        Mientras la interfaz vive es quien confirma las conexiones. Si se
        cerrara del todo, el servicio daria por muerta la interfaz y desharia
        los tuneles a los 90 segundos.
        """
        event.ignore()
        self.hide()


def _tunnel_item(summary: ProfileSummary) -> QTableWidgetItem:
    item = QTableWidgetItem(_TUNNEL_LABEL.get(summary.tunnel_type.value, "?"))
    if summary.needs_confirmation:
        item.setText(f"{item.text()} ⚠")
        item.setToolTip("Corta la conectividad local de este equipo al conectarse")
    return item


def _state_item(summary: ProfileSummary) -> QTableWidgetItem:
    item = QTableWidgetItem(summary.state.value)
    item.setForeground(QColor(_STATE_COLOR.get(summary.state, "#57606a")))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return item
