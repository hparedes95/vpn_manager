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

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from vpnmanager.connectors.providers import PROVIDERS, PROVIDERS_BY_NAME, Provider, detect
from vpnmanager.core.models import (
    DisconnectStrategy,
    LaunchContext,
    LaunchKind,
    LaunchSpec,
    Profile,
    TunnelType,
    suggest_profile_id,
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


WHERE_THE_CONNECTION_LIVES = (
    "La direccion del gateway, el puerto, el usuario y el certificado se "
    "configuran <b>en el cliente oficial</b>, no aqui. Un FortiClient con dos "
    "gateways sigue siendo una conexion suya.\n\n"
    "Aqui solo se dice <b>cual</b> abrir y <b>como comprobar</b> que el tunel "
    "esta levantado."
)

WHAT_THE_WITNESS_IP_IS = (
    "Una IP de <b>dentro</b> de la red remota: la que solo responde si el tunel "
    "esta en pie. No la del gateway — esa responde igual con la VPN caida, y el "
    "perfil diria «conectado» sin estarlo.\n\n"
    "Si todavia no la sabes, dejalo vacio: la VPN se abrira igual y su estado "
    "dira «abierto — sin comprobar» hasta que la rellenes."
)


class ProfileDialog(QDialog):
    """Los datos de una VPN. Valida antes de dejar guardar.

    Lo justo arriba y lo demas escondido. De los trece campos que habia, hoy
    solo cuatro necesitan que alguien piense: el resto se deduce del nombre,
    se busca en el disco o es para cuando exista un conector verificado.
    """

    def __init__(self, parent: QWidget | None, profile: Profile | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("VPN" if profile else "Nueva VPN")
        self.setMinimumWidth(600)

        # Al editar no se toca nada solo: lo que hay puesto lo puso alguien.
        self._id_is_automatic = profile is None
        self._breaks_is_automatic = profile is None
        self._target_is_automatic = profile is None

        # Lo que el formulario NO enseña y por tanto no puede reconstruir. Se
        # guarda y se devuelve tal cual al grabar.
        #
        # Sin esto, abrir el perfil de WireGuard del ejemplo y darle a Guardar
        # sin tocar nada le cambiaba el `context` de `service` a `user_session`
        # —y `/installtunnelservice` dejaba de correr como SYSTEM— ademas de
        # borrarle `post_connect_apps` y `expected_client_version`. En silencio.
        self._original = profile

        self._name = QLineEdit(profile.display_name if profile else "")
        self._name.setPlaceholderText("Ivanti - Cliente B")
        self._name.textChanged.connect(self._on_name_changed)

        self._connector = QComboBox()
        self._connector.currentIndexChanged.connect(self._on_connector_changed)

        self._client_profile = QLineEdit(profile.client_profile_name if profile else "")
        self._client_profile_label = QLabel("Conexion en el cliente")

        self._tunnel = QComboBox()
        for value, label in _TUNNELS:
            self._tunnel.addItem(label, value)
        self._tunnel.currentIndexChanged.connect(self._on_tunnel_changed)

        self._probe = QLineEdit(profile.probe_ip or "" if profile else "")
        self._probe.setPlaceholderText("10.20.0.1   (se puede dejar para despues)")

        self._networks = QLineEdit(", ".join(profile.target_networks) if profile else "")
        self._networks.setPlaceholderText("10.0.0.0/8, 172.16.4.0/24   (opcional)")

        # -- Lo avanzado, escondido tras un boton --------------------------
        self._id = QLineEdit(profile.id if profile else "")
        self._id.setPlaceholderText("sale del nombre")
        self._id.textEdited.connect(self._on_id_edited)

        self._target = QLineEdit(profile.launch.target if profile else "")
        self._target.setPlaceholderText("se busca solo al elegir el cliente")
        self._target.textEdited.connect(self._on_target_edited)
        self._browse = QPushButton("Examinar…")
        self._browse.clicked.connect(self._pick_executable)

        self._args = QLineEdit(" ".join(profile.launch.args) if profile else "")
        self._args.setPlaceholderText("normalmente vacio")

        self._routes = QLineEdit(", ".join(profile.routes) if profile else "")
        self._routes.setPlaceholderText("para cuando un conector sepa conectar")

        self._dns = QLineEdit(", ".join(profile.dns) if profile else "")
        self._dns.setPlaceholderText("para cuando un conector sepa conectar")

        self._breaks = QCheckBox("Corta la conectividad local (pide confirmacion al usuario)")
        self._breaks.setChecked(profile.breaks_local_connectivity if profile else False)
        self._breaks.clicked.connect(self._on_breaks_clicked)

        self._strategy = QComboBox()
        for value, label in _STRATEGIES:
            self._strategy.addItem(label, value)

        self._notes = QLineEdit(profile.notes if profile else "")

        # Se mira el disco UNA vez. Son hasta cuatro rutas por cada uno de los
        # ocho clientes, en `Program Files`, y eso con redireccion de carpetas
        # o un antivirus mirando puede tardar. Antes se hacia al construir el
        # dialogo y otra vez en cada cambio del desplegable, en el hilo de la
        # interfaz.
        self._installed = {provider.name: detect(provider) for provider in PROVIDERS}

        # El desplegable se rellena al final: al elegir el primero se dispara
        # `_on_connector_changed`, que ya necesita existir todo lo de arriba.
        for provider in PROVIDERS:
            self._connector.addItem(self._describe(provider), provider.name)

        self.profile: Profile | None = None
        self._restore(profile)
        layout = QVBoxLayout(self)
        layout.addWidget(_note(WHERE_THE_CONNECTION_LIVES))
        layout.addWidget(self._essentials())
        layout.addWidget(self._verification())
        layout.addWidget(self._advanced_toggle())
        layout.addWidget(self._advanced)
        layout.addWidget(self._buttons())

    # -- Construccion de las secciones -------------------------------------

    def _essentials(self) -> QWidget:
        form = QFormLayout()
        form.addRow("Cliente VPN", self._connector)
        form.addRow("Nombre visible", self._name)
        form.addRow(self._client_profile_label, self._client_profile)
        form.addRow("Tipo de tunel", self._tunnel)

        box = QGroupBox("Lo imprescindible")
        box.setLayout(form)
        return box

    def _verification(self) -> QWidget:
        form = QFormLayout()
        form.addRow("IP testigo", self._probe)
        form.addRow("Redes destino", self._networks)
        form.addRow("", _note(WHAT_THE_WITNESS_IP_IS))

        box = QGroupBox("Como se comprueba que esta conectada  (opcional)")
        box.setLayout(form)
        return box

    def _advanced_toggle(self) -> QWidget:
        self._advanced = QWidget()
        form = QFormLayout()
        form.addRow("Identificador", self._id)
        form.addRow("Ejecutable", self._target_row())
        form.addRow("Argumentos", self._args)
        form.addRow("Rutas", self._routes)
        form.addRow("DNS", self._dns)
        form.addRow("", self._breaks)
        form.addRow("Al desconectar", self._strategy)
        form.addRow("Notas", self._notes)
        self._advanced.setLayout(form)
        self._advanced.setVisible(False)

        button = QPushButton("Opciones avanzadas")
        button.setCheckable(True)
        button.setFlat(True)
        button.toggled.connect(self._advanced.setVisible)
        return button

    def _buttons(self) -> QWidget:
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        return buttons

    def _restore(self, profile: Profile | None) -> None:
        if profile is None:
            self._on_connector_changed()
            return

        index = self._connector.findData(profile.connector)
        if index >= 0:
            self._connector.setCurrentIndex(index)
        else:
            # Un conector que no esta en la lista: catalogo escrito a mano, o
            # un conector retirado. Callarse dejaria el desplegable en el
            # primero, y guardar reasignaria el perfil a OTRO cliente —con otro
            # LaunchKind— sin que nadie se enterase.
            QMessageBox.warning(
                self,
                "Conector desconocido",
                f"Este perfil usa el conector «{profile.connector}», que no esta en la "
                f"lista de clientes conocidos.\n\nSi guardas, quedara asignado a "
                f"«{PROVIDERS[0].display_name}». Cancela si no es lo que quieres.",
            )
        self._tunnel.setCurrentIndex(self._tunnel.findData(profile.tunnel_type))
        self._strategy.setCurrentIndex(self._strategy.findData(profile.disconnect_strategy))

    # -- Reacciones --------------------------------------------------------

    def _describe(self, provider: Provider) -> str:
        """El desplegable dice cual esta instalado de verdad en esta maquina.

        Menos con las MSIX. `detect` no mira el disco para esas —una app de
        Store no tiene ruta que comprobar— asi que decir "instalado" seria
        afirmar algo que nadie ha comprobado. Se dice lo que es.
        """
        if provider.launch_kind is LaunchKind.MSIX:
            return f"{provider.display_name}  — app de Store"
        found = self._installed.get(provider.name)
        return f"{provider.display_name}  — {'instalado' if found else 'no encontrado'}"

    def _current_provider(self) -> Provider:
        return PROVIDERS_BY_NAME[self._connector.currentData()]

    def _on_connector_changed(self) -> None:
        provider = self._current_provider()
        self._client_profile_label.setText(f"Nombre del {provider.connection_word}")
        self._client_profile.setPlaceholderText(
            f"como se llama este {provider.connection_word} dentro de "
            f"{provider.display_name}   (opcional)"
        )
        # Solo se rellena solo lo que no ha tocado nadie: si alguien busco el
        # .exe a mano, cambiar de cliente no puede borrarselo.
        if self._target_is_automatic:
            self._target.setText(self._installed.get(provider.name) or "")
        self._browse.setEnabled(provider.launch_kind is LaunchKind.EXE)

    def _on_name_changed(self, text: str) -> None:
        if self._id_is_automatic:
            self._id.setText(suggest_profile_id(text))

    def _on_id_edited(self) -> None:
        self._id_is_automatic = False

    def _on_target_edited(self) -> None:
        self._target_is_automatic = False

    def _on_breaks_clicked(self) -> None:
        self._breaks_is_automatic = False

    def _on_tunnel_changed(self) -> None:
        """Un tunel completo corta la red local salvo que alguien diga lo contrario.

        Es el valor prudente: marcarlo de mas solo cuesta una confirmacion, y
        no marcarlo cuando tocaba cuesta la sesion RDP del que lo pulse.
        """
        if self._breaks_is_automatic:
            self._breaks.setChecked(self._tunnel.currentData() is TunnelType.FULL)

    def _target_row(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._target, 1)
        layout.addWidget(self._browse)
        return row

    def _pick_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Ejecutable del cliente VPN", r"C:\Program Files", "Ejecutables (*.exe)"
        )
        if path:
            # Con separadores de Windows: es lo que espera la validacion y lo
            # que se va a ejecutar.
            self._target.setText(str(Path(path)).replace("/", "\\"))
            self._target_is_automatic = False

    def _save(self) -> None:
        profile = self._build()
        issues = profile.validate()
        if issues:
            # Se enseñan todas: quien esta rellenando esto las arregla de una.
            QMessageBox.warning(self, "Faltan cosas", "\n".join(f"· {issue}" for issue in issues))
            return

        # Los avisos no impiden guardar, pero se dicen: quien deja el perfil a
        # medias tiene que saber que lo deja a medias.
        warnings = profile.warnings()
        if warnings and not self._accepts(warnings):
            return

        self.profile = profile
        self.accept()

    def _accepts(self, warnings: list[str]) -> bool:
        return (
            QMessageBox.question(
                self,
                "Se puede guardar, pero…",
                "\n".join(f"· {warning}" for warning in warnings) + "\n\n¿Guardar asi?",
            )
            == QMessageBox.StandardButton.Yes
        )

    def _build(self) -> Profile:
        provider = self._current_provider()
        original = self._original
        return Profile(
            id=self._id.text().strip(),
            display_name=self._name.text().strip(),
            connector=provider.name,
            launch=LaunchSpec(
                kind=provider.launch_kind,
                target=self._target.text().strip(),
                args=tuple(self._args.text().split()),
                # Los clientes con ventana se lanzan en la sesion del usuario, y
                # eso es lo que se elige para una VPN nueva: correr como SYSTEM
                # hay que justificarlo, no cae por comodidad.
                #
                # Pero al editar se conserva lo que hubiera. Reponerlo a
                # USER_SESSION dejaba `wireguard.exe /installtunnelservice` sin
                # privilegios solo por abrir el formulario y darle a Guardar.
                context=original.launch.context if original else LaunchContext.USER_SESSION,
            ),
            tunnel_type=self._tunnel.currentData(),
            client_profile_name=self._client_profile.text().strip(),
            target_networks=_split(self._networks.text()),
            probe_ip=self._probe.text().strip() or None,
            routes=_split(self._routes.text()),
            dns=_split(self._dns.text()),
            breaks_local_connectivity=self._breaks.isChecked(),
            disconnect_strategy=self._strategy.currentData(),
            notes=self._notes.text().strip(),
            # Nada de esto se enseña en el formulario, asi que el formulario no
            # puede reconstruirlo: viaja intacto del perfil original.
            post_connect_apps=original.post_connect_apps if original else (),
            expected_client_version=original.expected_client_version if original else None,
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
            self._list.addItem(_describe_profile(profile))

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


def _describe_profile(profile: Profile) -> str:
    """Una linea por VPN, con lo que distingue una de otra.

    El nombre de la conexion va aqui porque es justo lo que separa tres
    tuneles del mismo FortiClient: sin el, las tres filas dirian lo mismo.
    """
    parts = [profile.display_name]
    if profile.client_profile_name:
        parts.append(f"→ {profile.client_profile_name}")
    parts.append(f"({profile.tunnel_type.value})")
    if profile.breaks_local_connectivity:
        parts.append("⚠ corta la red local")
    if not profile.can_verify_state and profile.needs_verification:
        parts.append("· sin IP testigo")
    return "  ".join(parts)


def _note(text: str) -> QLabel:
    """Un parrafo explicativo, no un campo. Con saltos de linea de verdad."""
    label = QLabel(text.replace("\n", "<br>"))
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.RichText)
    return label
