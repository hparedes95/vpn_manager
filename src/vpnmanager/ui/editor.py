"""Editor del catalogo. Corre elevado y en su propio proceso.

**Por que en otro proceso y con privilegios.** Este fichero decide que binario
ejecuta un servicio que corre como SYSTEM. Si la bandeja —que corre sin
privilegios a proposito— pudiera escribirlo, cualquier usuario del puesto
elegiria que se ejecuta como SYSTEM: eso es una escalada de privilegios local,
y es justo lo que CLAUDE.md prohibe.

Quien abra esto tiene que pasar por UAC. Y quien pasa por UAC ya podia editar
el mismo fichero con el Bloc de notas, asi que no gana ningun permiso: solo
deja de sufrir. El usuario normal sigue viendo la lista y nada mas.

Tampoco pasa por el pipe. El servicio no acepta rutas ni argumentos de nadie;
lee el catalogo del disco, y el disco lo protege su ACL.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from vpnmanager.connectors.providers import PROVIDERS
from vpnmanager.core.models import (
    DisconnectStrategy,
    LaunchContext,
    LaunchKind,
    LaunchSpec,
    Profile,
    TunnelType,
)
from vpnmanager.security.catalog import dump_catalog, load_catalog

log = logging.getLogger("vpnmgr.ui")


class _OwnAuthority:
    """Lee el catalogo sin mirar la firma, y solo aqui dentro.

    No se reutiliza el verificador de pruebas del servicio: alli aceptar un
    catalogo sin firma es peligroso —el servicio ejecuta lo que ponga, como
    SYSTEM— y por eso vive en cuarentena. Aqui es otra cosa. Este proceso esta
    elevado y va a sobrescribir ese mismo fichero; quien manda es la ACL del
    disco, no una firma que todavia no existe.
    """

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return True


CATALOG_PATH = Path(r"C:\ProgramData\VpnManager\profiles.json")
SERVICE_NAME = "VpnManagerSvc"

_TUNNELS = [
    (TunnelType.SPLIT, "Parcial — solo las redes indicadas"),
    (TunnelType.FULL, "Completo — captura TODO el trafico"),
    (TunnelType.APP, "Por aplicacion — IAP Desktop, no es una VPN"),
]

_STRATEGIES = [
    (DisconnectStrategy.NONE, "No se puede: hay que cerrarla en su cliente"),
    (DisconnectStrategy.CLI, "El cliente admite que se le pida (verificado)"),
    (DisconnectStrategy.TERMINATE, "Matar el proceso (solo si esta comprobado)"),
]


def is_elevated() -> bool:
    """Si este proceso puede escribir el catalogo."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def relaunch_elevated() -> bool:
    """Vuelve a lanzar esta aplicacion pidiendo elevacion, en modo editor.

    Devuelve si el usuario acepto el aviso de UAC. Si dice que no, no pasa
    nada: no habia forma de escribir ese fichero sin ser administrador, y esa
    es la proteccion, no un estorbo.
    """
    try:
        import ctypes

        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, "--editar-catalogo", None, 1
        )
        return int(result) > 32
    except Exception:
        log.exception("no se pudo pedir elevacion para el editor")
        return False


class ProfileDialog(QDialog):
    """Los datos de una VPN. Valida antes de dejar guardar."""

    def __init__(self, parent: QWidget | None, profile: Profile | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("VPN" if profile else "Nueva VPN")
        self.setMinimumWidth(560)

        self._id = QLineEdit(profile.id if profile else "")
        self._id.setPlaceholderText("wireguard-central")
        self._name = QLineEdit(profile.display_name if profile else "")
        self._name.setPlaceholderText("WireGuard - central")

        self._connector = QComboBox()
        for provider in PROVIDERS:
            self._connector.addItem(f"{provider.display_name}  ({provider.name})", provider.name)
        if profile:
            index = self._connector.findData(profile.connector)
            if index >= 0:
                self._connector.setCurrentIndex(index)

        self._target = QLineEdit(profile.launch.target if profile else "")
        self._target.setPlaceholderText(r"C:\Program Files\WireGuard\wireguard.exe")
        browse = QPushButton("Examinar…")
        browse.clicked.connect(self._pick_executable)
        target_row = QHBoxLayout()
        target_row.addWidget(self._target, 1)
        target_row.addWidget(browse)

        self._args = QLineEdit(" ".join(profile.launch.args) if profile else "")
        self._args.setPlaceholderText("/installtunnelservice   (opcional)")

        self._tunnel = QComboBox()
        for value, label in _TUNNELS:
            self._tunnel.addItem(label, value)
        if profile:
            self._tunnel.setCurrentIndex(self._tunnel.findData(profile.tunnel_type))

        self._networks = QLineEdit(", ".join(profile.target_networks) if profile else "")
        self._networks.setPlaceholderText("10.0.0.0/8, 172.16.4.0/24")

        self._probe = QLineEdit(profile.probe_ip or "" if profile else "")
        self._probe.setPlaceholderText("10.20.0.1 — una IP interna que responda a ping")

        self._routes = QLineEdit(", ".join(profile.routes) if profile else "")
        self._routes.setPlaceholderText("opcional: rutas a aplicar")

        self._dns = QLineEdit(", ".join(profile.dns) if profile else "")
        self._dns.setPlaceholderText("opcional: 10.0.0.53")

        self._breaks = QCheckBox("Corta la conectividad local (pide confirmacion al usuario)")
        self._breaks.setChecked(profile.breaks_local_connectivity if profile else False)

        self._strategy = QComboBox()
        for value, label in _STRATEGIES:
            self._strategy.addItem(label, value)
        if profile:
            self._strategy.setCurrentIndex(self._strategy.findData(profile.disconnect_strategy))

        self._notes = QLineEdit(profile.notes if profile else "")

        form = QFormLayout()
        form.addRow("Identificador", self._id)
        form.addRow("Nombre visible", self._name)
        form.addRow("Cliente", self._connector)
        form.addRow("Ejecutable", target_row)
        form.addRow("Argumentos", self._args)
        form.addRow("Tipo de tunel", self._tunnel)
        form.addRow("Redes destino", self._networks)
        form.addRow("IP testigo", self._probe)
        form.addRow("Rutas", self._routes)
        form.addRow("DNS", self._dns)
        form.addRow("", self._breaks)
        form.addRow("Al desconectar", self._strategy)
        form.addRow("Notas", self._notes)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        hint = QLabel(
            "El identificador es lo unico que viaja por el pipe: letras, digitos, "
            "punto, guion y guion bajo.\nLa IP testigo es lo que demuestra que el "
            "tunel funciona de verdad; sin ella no se puede saber."
        )
        hint.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addWidget(buttons)

        self.profile: Profile | None = None

    def _pick_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Ejecutable del cliente VPN", r"C:\Program Files", "Ejecutables (*.exe)"
        )
        if path:
            # Con separadores de Windows: es lo que espera la validacion y lo
            # que se va a ejecutar.
            self._target.setText(str(Path(path)).replace("/", "\\"))

    def _save(self) -> None:
        profile = self._build()
        issues = profile.validate()
        if issues:
            # Se enseñan todas: quien esta rellenando esto las arregla de una.
            QMessageBox.warning(self, "Faltan cosas", "\n".join(f"· {issue}" for issue in issues))
            return
        self.profile = profile
        self.accept()

    def _build(self) -> Profile:
        tunnel = self._tunnel.currentData()
        return Profile(
            id=self._id.text().strip(),
            display_name=self._name.text().strip(),
            connector=self._connector.currentData(),
            launch=LaunchSpec(
                kind=LaunchKind.EXE,
                target=self._target.text().strip(),
                args=tuple(self._args.text().split()),
                # Los clientes con ventana se lanzan en la sesion del usuario.
                # Correr como SYSTEM es un caso raro que se edita a mano.
                context=LaunchContext.USER_SESSION,
            ),
            tunnel_type=tunnel,
            target_networks=_split(self._networks.text()),
            probe_ip=self._probe.text().strip() or None,
            routes=_split(self._routes.text()),
            dns=_split(self._dns.text()),
            breaks_local_connectivity=self._breaks.isChecked(),
            disconnect_strategy=self._strategy.currentData(),
            notes=self._notes.text().strip(),
        )


class CatalogEditor(QDialog):
    """La lista de VPN del catalogo, con anadir, editar y quitar."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Catalogo de VPN — VPN Manager (administrador)")
        self.resize(620, 420)

        self._profiles: list[Profile] = []
        self._list = QListWidget()

        add = QPushButton("Anadir…")
        add.clicked.connect(self._add)
        edit = QPushButton("Editar…")
        edit.clicked.connect(self._edit)
        remove = QPushButton("Quitar")
        remove.clicked.connect(self._remove)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Close
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        actions = QHBoxLayout()
        actions.addWidget(add)
        actions.addWidget(edit)
        actions.addWidget(remove)
        actions.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Se guarda en {CATALOG_PATH}"))
        layout.addWidget(self._list, 1)
        layout.addLayout(actions)
        layout.addWidget(buttons)

        self._load()

    def _load(self) -> None:
        try:
            payload = CATALOG_PATH.read_bytes()
        except OSError:
            payload = b""

        if payload:
            # Sin verificar la firma: aqui el que manda es quien tiene permiso
            # de escritura sobre el fichero, que es la misma proteccion que
            # habria con un editor de texto.
            load = load_catalog(payload, b"", _OwnAuthority())
            if load.issues:
                QMessageBox.warning(
                    self,
                    "El catalogo actual tiene problemas",
                    "Se abre vacio para no empeorarlo. Revisa el fichero:\n\n"
                    + "\n".join(f"· {issue}" for issue in load.issues),
                )
            self._profiles = list(load.profiles)
        self._refresh()

    def _refresh(self) -> None:
        self._list.clear()
        for profile in self._profiles:
            mark = " ⚠ corta la red local" if profile.breaks_local_connectivity else ""
            self._list.addItem(f"{profile.display_name}  ({profile.tunnel_type.value}){mark}")

    def _add(self) -> None:
        dialog = ProfileDialog(self)
        if dialog.exec() and dialog.profile is not None:
            self._profiles.append(dialog.profile)
            self._refresh()

    def _edit(self) -> None:
        row = self._list.currentRow()
        if row < 0:
            return
        dialog = ProfileDialog(self, self._profiles[row])
        if dialog.exec() and dialog.profile is not None:
            self._profiles[row] = dialog.profile
            self._refresh()

    def _remove(self) -> None:
        row = self._list.currentRow()
        if row < 0:
            return
        if (
            QMessageBox.question(self, "Quitar", f"¿Quitar «{self._profiles[row].display_name}»?")
            == QMessageBox.StandardButton.Yes
        ):
            del self._profiles[row]
            self._refresh()

    def _save(self) -> None:
        try:
            payload = dump_catalog(self._profiles)
        except ValueError as error:
            QMessageBox.warning(self, "No se puede guardar", str(error))
            return

        try:
            CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            CATALOG_PATH.write_bytes(payload)
        except OSError as error:
            QMessageBox.critical(
                self,
                "No se pudo guardar",
                f"{error.strerror}\n\nHace falta ser administrador para escribir ahi.",
            )
            return

        self._offer_restart()
        self.accept()

    def _offer_restart(self) -> None:
        """El catalogo se lee al arrancar: sin reiniciar, no cambia nada."""
        if (
            QMessageBox.question(
                self,
                "Guardado",
                "El servicio lee el catalogo al arrancar, asi que los cambios no se "
                "veran hasta reiniciarlo.\n\n¿Reiniciarlo ahora?",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        for arguments in (["stop", SERVICE_NAME], ["start", SERVICE_NAME]):
            subprocess.run(
                [r"C:\Windows\System32\sc.exe", *arguments],
                shell=False,
                capture_output=True,
                timeout=30,
                check=False,
            )


def _split(text: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in text.replace(";", ",").split(",") if part.strip())
