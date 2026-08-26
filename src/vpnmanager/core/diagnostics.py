"""El informe de diagnostico: que se comprueba y como se cuenta.

Existe porque depurar esto estaba costando una tanda de comandos de PowerShell
por cada fallo, dictados uno a uno. Eso no escala y no es trabajo del usuario:
lo que hay que mirar lo sabe el programa, asi que lo mira el programa.

Aqui solo esta la parte que no toca la maquina: el modelo de un resultado, el
del informe entero y como se escribe. Quien va a buscar los datos —si existe un
fichero, si el pipe esta ahi, que devuelve un script— vive en la capa que puede
tocar Windows y se le pasa por parametro. Asi el formato del informe, que es lo
unico con reglas, se prueba en CI sin un puesto delante.

Tres estados y no dos. `None` es "no se pudo comprobar", que no es lo mismo que
"mal": confundirlos es como poner que un tunel esta caido porque el script que
lo mira no arranco.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Un informe se lee y se pega en un mensaje. Si un detalle se desmadra —la
# salida entera de un script, un PATH de dos mil caracteres— se corta: mas alla
# de esto no informa, estorba.
MAX_DETAIL = 300


@dataclass(frozen=True)
class Check:
    """Una comprobacion y como salio."""

    name: str
    ok: bool | None  # None: no se pudo comprobar. No es lo mismo que fallar.
    detail: str = ""

    @property
    def mark(self) -> str:
        if self.ok is None:
            return "?"
        return "OK" if self.ok else "FALLA"

    def render(self) -> str:
        detail = _shorten(self.detail)
        return f"[{self.mark:>5}] {self.name}" + (f"\n         {detail}" if detail else "")


@dataclass(frozen=True)
class Report:
    """Todo lo que se ha podido averiguar del puesto, en un solo sitio."""

    version: str
    checks: tuple[Check, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def failed(self) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if check.ok is False)

    @property
    def unknown(self) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if check.ok is None)

    @property
    def all_ok(self) -> bool:
        """Solo si TODO salio bien. Lo que no se pudo comprobar cuenta en contra.

        Un informe que dice "todo bien" porque la mitad no se pudo mirar es
        peor que no tener informe.
        """
        return bool(self.checks) and all(check.ok is True for check in self.checks)

    def render(self) -> str:
        """El informe entero, para pegarlo en un mensaje tal cual.

        El resumen va arriba: quien lo lea tiene que saber en la primera linea
        si hay algo roto, sin recorrerse la lista.
        """
        lines = [
            "VPN Manager — diagnostico",
            f"version: {self.version}",
            "",
            self._summary(),
            "",
        ]
        lines.extend(check.render() for check in self.checks)
        if self.notes:
            lines.extend(["", "Notas:", *(f"  - {_shorten(note)}" for note in self.notes)])
        return "\n".join(lines)

    def _summary(self) -> str:
        if not self.checks:
            return "No se pudo comprobar nada."
        if self.all_ok:
            return f"Todo correcto ({len(self.checks)} comprobaciones)."

        parts = []
        if self.failed:
            parts.append(f"{len(self.failed)} falla(n): " + ", ".join(c.name for c in self.failed))
        if self.unknown:
            parts.append(
                f"{len(self.unknown)} sin comprobar: " + ", ".join(c.name for c in self.unknown)
            )
        return "; ".join(parts)


def _shorten(text: str) -> str:
    """Una linea, y no muy larga. Los saltos romperian la lista."""
    flat = " ".join(text.split())
    if len(flat) <= MAX_DETAIL:
        return flat
    return flat[: MAX_DETAIL - 1] + "…"
