"""Envoltorio para que `vpnmgr-svc.exe` sea un servicio de Windows de verdad.

Un ejecutable normal no vale. El Administrador de servicios espera que el
proceso se registre y conteste en unos segundos; si no, `sc start` falla con
el error 1053 y el servicio nunca llega a correr. Eso es exactamente lo que
pasaba: el .exe era una aplicacion de consola registrada con `sc create`.

Aqui no hay logica: se arranca lo mismo que en consola y se atiende la orden
de parar. Todo lo que decide algo esta en `main.py` y en el orquestador.

No se puede probar sin Windows ni sin pywin32, asi que se ha dejado lo mas
corto posible.
"""

from __future__ import annotations

import logging
import threading

log = logging.getLogger("vpnmgr")


def is_service_start(argv: list[str]) -> bool:
    """Si nos ha arrancado el Administrador de servicios.

    Lo hace sin argumentos. Cualquier cosa que venga por linea de comandos
    significa que lo ha lanzado una persona en una consola.
    """
    return len(argv) <= 1


def run_as_service() -> None:
    """Entrega el proceso al Administrador de servicios.

    `StartServiceCtrlDispatcher` y no `HandleCommandLine`: el segundo sirve
    para gestionar el servicio desde una consola —instalarlo, pararlo— y sin
    argumentos imprime la ayuda y termina con codigo 0. Arrancado por el
    Administrador de servicios eso se ve como un servicio que se para solo
    nada mas empezar, sin ningun error que mirar.
    """
    import servicemanager

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(VpnManagerService)
    servicemanager.StartServiceCtrlDispatcher()


try:  # pragma: no cover - sin pywin32 no hay servicio que definir
    import win32event
    import win32service
    import win32serviceutil

    class VpnManagerService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "VpnManagerSvc"
        _svc_display_name_ = "VPN Manager"
        _svc_description_ = "Orquesta los clientes VPN oficiales instalados en el equipo."

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._server = None
            self._orchestrator = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self._server is not None:
                self._server.stop()
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self) -> None:
            from vpnmanager.service.main import (
                allow_unsigned_from_registry,
                build_orchestrator,
                run_watchdog_loop,
                setup_logging,
                verifier_for,
            )
            from vpnmanager.service.pipe import PipeServer

            setup_logging()
            log.info("arrancando como servicio de Windows")

            # Todo el arranque va dentro del try. Aqui no hay consola ni nadie
            # mirando: una excepcion al montar el orquestador se la queda
            # pywin32, el Administrador de servicios dice lo suyo, y el fichero
            # de log —que es lo unico que se puede leer despues— se corta a
            # media frase sin decir por que.
            try:
                verifier = verifier_for(allow_unsigned=allow_unsigned_from_registry())
                self._orchestrator, user_session = build_orchestrator(verifier)
                stop = threading.Event()
                threading.Thread(
                    target=run_watchdog_loop,
                    args=(self._orchestrator, stop),
                    name="watchdog",
                    daemon=True,
                ).start()

                server = PipeServer(self._orchestrator, user_session)
                self._server = server
                orchestrator = self._orchestrator
            except Exception:
                log.exception("no se ha podido arrancar el servicio")
                raise

            try:
                server.serve_forever()
            finally:
                stop.set()
                for reversion in orchestrator.shutdown():
                    log.info("reversion al parar: %s", reversion.message)
                log.info("servicio parado")

except ImportError:  # pragma: no cover - fuera de Windows
    VpnManagerService = None  # type: ignore[assignment,misc]
