"""La sonda: si un perfil esta conectado de verdad.

Implementa el puerto `ConnectionProbe`. Las tres comprobaciones —adaptador
activo, ruta hacia la red destino y respuesta de la IP testigo interna— las
hace `Test-TunnelState.ps1` y las devuelve por separado.

El icono del cliente oficial no aparece por ningun lado, a proposito: no es
fuente de verdad. Un FortiClient puede estar en verde con el tunel caido.
"""

from __future__ import annotations

from vpnmanager.core.models import ProbeResult, Profile, TunnelType
from vpnmanager.net.powershell import PowerShellRunner, Script


class PowerShellProbe:
    """Sonda de verdad. Sin verificar en un puesto todavia."""

    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = PowerShellRunner() if runner is None else runner

    def check(self, profile: Profile) -> ProbeResult:
        if profile.tunnel_type is TunnelType.APP or profile.probe_ip is None:
            # Un tunel APP no monta adaptador ni pone rutas: no hay nada que
            # sondear, y decir que esta caido seria mentir.
            return ProbeResult(checked=False)

        # Un argumento vacio no sobrevive a `powershell.exe -File`: se pierde
        # y el parametro siguiente se queda sin valor, asi que el script falla
        # antes de empezar. Si no hay redes declaradas, no se manda.
        networks = ",".join(profile.target_networks)
        result = (
            self._runner.run(Script.TEST_TUNNEL, ProbeIp=profile.probe_ip, TargetNetworks=networks)
            if networks
            else self._runner.run(Script.TEST_TUNNEL, ProbeIp=profile.probe_ip)
        )
        if not result.ok:
            # No se pudo mirar. Distinto de haber mirado y estar caido: si se
            # confundieran, un fallo del propio script se veria como un tunel
            # roto y dispararia desconexiones que nadie ha pedido.
            return ProbeResult(checked=False)

        return ProbeResult(
            adapter_up=_flag(result.data, "adapterUp"),
            routed=_flag(result.data, "routed"),
            probe_answers=_flag(result.data, "probeAnswers"),
            checked=True,
        )

    def is_really_connected(self, profile: Profile) -> bool:
        return self.check(profile).connected


def _flag(data: dict[str, object], key: str) -> bool:
    """Solo un booleano de verdad cuenta como cierto.

    Nada de veracidad: si el script devuelve otra cosa, es que no dijo que si.
    """
    return data.get(key) is True
