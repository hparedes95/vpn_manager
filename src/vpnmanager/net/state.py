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

import json

from vpnmanager.core.watchdog import NetworkSnapshot
from vpnmanager.net.powershell import PowerShellRunner, Script


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

        return self._runner.run(Script.RESTORE_NET_STATE, State=snapshot.payload).ok


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
