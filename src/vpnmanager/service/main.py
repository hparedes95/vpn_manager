"""Arranque de `vpnmgr-svc`: monta las piezas y las pone a funcionar.

Es la raiz de composicion del servicio. Aqui se decide con que
implementaciones concretas se rellenan los puertos, y no hay ninguna otra
logica: si algo hay que decidir sobre una conexion, se decide en el
orquestador.

Se puede correr de dos formas. En consola, como administrador, que es como se
prueba y como se depura; y como servicio Windows, que es como se despliega.
Para las primeras pruebas en una VM, la consola vale y ahorra pelearse con la
instalacion del servicio.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path
from typing import Final

from vpnmanager.connectors.process import WindowsProcessLauncher
from vpnmanager.connectors.providers import build_registry
from vpnmanager.net.probe import PowerShellProbe
from vpnmanager.net.state import PowerShellNetworkController
from vpnmanager.security.catalog import CatalogVerifier, RejectingVerifier, load_catalog
from vpnmanager.service.dispatcher import DeferredUserSession
from vpnmanager.service.orchestrator import Orchestrator
from vpnmanager.service.pipe import DEFAULT_ALLOWED_GROUPS, PipeServer

log = logging.getLogger("vpnmgr")

DATA_DIR: Final = Path(r"C:\ProgramData\VpnManager")
CATALOG_PATH: Final = DATA_DIR / "profiles.json"
SIGNATURE_PATH: Final = DATA_DIR / "profiles.json.sig"

# Cada cuanto se mira si alguna ventana del watchdog ha vencido. Con la
# ventana en 90 s, mirar cada segundo deja la reversion casi inmediata sin
# gastar nada.
TICK_SECONDS: Final = 1.0


def build_orchestrator(verifier: CatalogVerifier) -> tuple[Orchestrator, DeferredUserSession]:
    """Monta el orquestador con las implementaciones de verdad."""
    load = load_catalog(_read(CATALOG_PATH), _read(SIGNATURE_PATH), verifier)
    for issue in load.issues:
        # Se registran todas: quien edita el catalogo las arregla de una vez.
        log.error("catalogo: %s", issue)
    if not load.ok:
        log.error("no se ha cargado ningun perfil. El servicio sigue vivo para poder decirlo.")

    user_session = DeferredUserSession()
    registry = build_registry(WindowsProcessLauncher(user_session))

    # Lo que el catalogo pide frente a lo que los conectores pueden. Se avisa
    # y se sigue: un perfil que pide una desconexion que nadie implementa se
    # puede abrir igual, solo que habra que cerrarlo a mano.
    for issue in registry.validate_catalog(load.profiles):
        log.warning("catalogo: %s", issue)

    orchestrator = Orchestrator(
        catalog=load.as_catalog(),
        registry=registry,
        network=PowerShellNetworkController(),
        probe=PowerShellProbe(),
    )
    return orchestrator, user_session


def run_watchdog_loop(orchestrator: Orchestrator, stop: threading.Event) -> None:
    """Vigila las ventanas de confirmacion y deshace lo que nadie confirmo.

    Va en su propio hilo porque no puede depender de que llegue una peticion:
    el caso que justifica todo esto es precisamente que no llegue ninguna.
    """
    while not stop.is_set():
        for reversion in orchestrator.tick():
            level = logging.INFO if reversion.ok else logging.ERROR
            log.log(level, "reversion: %s", reversion.message)
        stop.wait(TICK_SECONDS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpnmgr-svc", description="Servicio de VPN Manager")
    parser.add_argument(
        "--allow-unsigned-catalog",
        action="store_true",
        help="SOLO PRUEBAS: acepta profiles.json sin comprobar su firma",
    )
    parser.add_argument(
        "--allowed-group",
        action="append",
        default=None,
        help="grupo que puede hablar por el pipe (por defecto, Administradores)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    verifier = _verifier(allow_unsigned=args.allow_unsigned_catalog)
    orchestrator, user_session = build_orchestrator(verifier)

    stop = threading.Event()
    watchdog = threading.Thread(
        target=run_watchdog_loop,
        args=(orchestrator, stop),
        name="watchdog",
        daemon=True,
    )
    watchdog.start()

    groups = tuple(args.allowed_group) if args.allowed_group else DEFAULT_ALLOWED_GROUPS
    server = PipeServer(orchestrator, user_session, allowed_groups=groups)
    log.info("escuchando en el pipe; acceso permitido a: %s", ", ".join(groups))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("parando")
    finally:
        stop.set()
        # Un ultimo repaso: si algo estaba armado, se deshace antes de irse en
        # vez de dejar un tunel a medias sin nadie que lo vigile.
        for reversion in orchestrator.tick():
            log.info("reversion al parar: %s", reversion.message)
    return 0


def _verifier(*, allow_unsigned: bool) -> CatalogVerifier:
    """El verificador del catalogo. Por defecto, el que no se fia de nada."""
    if not allow_unsigned:
        return RejectingVerifier()

    # Import local y no arriba: asi no hay ninguna forma de que este modulo
    # acabe usandolo sin pasar por aqui.
    from vpnmanager.security.unsafe_dev import WARNING, UnsafeUnsignedCatalogVerifier

    log.warning("=" * 70)
    log.warning(WARNING)
    log.warning("=" * 70)
    return UnsafeUnsignedCatalogVerifier()


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        log.error("no se pudo leer %s: %s", path, error.strerror)
        return b""


if __name__ == "__main__":
    raise SystemExit(main())
