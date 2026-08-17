"""Foto y restauracion del estado de red.

Implementa el puerto `NetworkController`. Es la mitad del watchdog que toca la
maquina: si esto no funciona, el equipo se queda inalcanzable hasta que
alguien vaya andando hasta el.

La foto se guarda entera, tal como la devolvio el script, y se le devuelve
igual al restaurar. `NetworkSnapshot.routes` y `.dns` llevan solo un resumen
legible para el log y la interfaz; lo que se usa para restaurar es `payload`.
Reconstruirlo a partir del resumen seria restaurar una interpretacion nuestra
de la red en vez de la red que habia.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
from pathlib import Path

from vpnmanager.core.watchdog import NetworkSnapshot
from vpnmanager.net.powershell import RESTORE_TIMEOUT_SECONDS, PowerShellRunner, Script


class PowerShellNetworkController:
    """Controlador de verdad. Sin verificar en un puesto todavia."""

    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = PowerShellRunner() if runner is None else runner

    def snapshot(self) -> NetworkSnapshot:
        """La foto de antes de tocar nada.

        Si no se puede sacar, la foto sale vacia y **eso importa**: restaurar
        una foto vacia no deshace nada. Quien vaya a conectar un tunel
        completo tiene que mirar `NetworkSnapshot.usable` antes de armar el
        watchdog, o estara confiando en un seguro sin nada dentro.
        """
        result = self._runner.run(Script.GET_NET_STATE)
        if not result.ok:
            return NetworkSnapshot()

        return NetworkSnapshot(
            routes=_route_summary(result.data),
            dns=_dns_summary(result.data),
            payload=json.dumps(result.data, ensure_ascii=False, separators=(",", ":")),
        )

    def restore(self, snapshot: NetworkSnapshot) -> bool:
        """Devuelve la red a como estaba. Dice si lo consiguio del todo."""
        if not snapshot.usable:
            # Restaurar una foto vacia dejaria la red como este ahora y
            # devolveria un exito que no es tal.
            return False

        # La foto va por fichero y no como argumento: PowerShell reinterpreta
        # las comillas de los argumentos de -File, asi que el JSON llegaba
        # roto. Ademas una tabla de rutas grande se acerca al limite de
        # longitud de la linea de comandos.
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - se cierra abajo
            mode="w", suffix=".json", encoding="utf-8", delete=False
        )
        try:
            with handle:
                handle.write(snapshot.payload)
            # Con su propio plazo: restaurar hace una llamada al sistema por
            # ruta y por adaptador, y que el plazo de una lectura corte una
            # restauracion a medias es el peor resultado posible.
            return self._runner.run(
                Script.RESTORE_NET_STATE,
                timeout_seconds=RESTORE_TIMEOUT_SECONDS,
                StatePath=handle.name,
            ).ok
        finally:
            with contextlib.suppress(OSError):
                Path(handle.name).unlink()


def _route_summary(data: dict[str, object]) -> tuple[str, ...]:
    """Rutas en una linea, para el log. No se usa para restaurar."""
    routes = data.get("routes")
    if not isinstance(routes, list):
        return ()
    return tuple(
        f"{entry.get('destination')} via {entry.get('next_hop')} (if {entry.get('interfaceIndex')})"
        for entry in routes
        if isinstance(entry, dict)
    )


def _dns_summary(data: dict[str, object]) -> tuple[str, ...]:
    entries = data.get("dns")
    if not isinstance(entries, list):
        return ()
    summary: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        servers = entry.get("servers")
        if isinstance(servers, list) and servers:
            joined = ", ".join(str(server) for server in servers)
            summary.append(f"{entry.get('interfaceAlias')}: {joined}")
    return tuple(summary)
