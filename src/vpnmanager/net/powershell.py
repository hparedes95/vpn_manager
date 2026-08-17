"""Ejecutor de los scripts de red. El unico sitio que invoca PowerShell.

Las operaciones de red van en `.ps1` versionados, con entrada y salida en
JSON. No se reimplementa `Get-NetRoute` parseando texto en Python: el formato
de texto cambia entre versiones de Windows y el JSON no.

**El script no es un dato, es un nombre de un conjunto cerrado.** `Script` es
un enum y el fichero se resuelve contra el directorio de este paquete. No hay
ninguna forma de pedirle a este modulo que ejecute otra cosa, ni pasandole una
ruta ni pasandole un nombre: si no esta en el enum, no existe. Eso importa
porque esto corre como SYSTEM.

**Los parametros van en lista.** `-File`, nunca `-Command`. Un `-Command` con
la orden montada en una cadena es una inyeccion esperando a que alguien meta
una comilla en un nombre de perfil.

**Siempre con temporizador.** Un PowerShell colgado no puede colgar al
servicio: si el que se cuelga es el que restaura la red, el equipo se queda
sin red y sin nadie que lo arregle.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final

# El interprete por ruta absoluta: buscarlo en el PATH seria dejar que quien
# controle el PATH del servicio elija que se ejecuta como SYSTEM.
POWERSHELL: Final = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

SCRIPT_DIR: Final = Path(__file__).resolve().parent / "ps"

DEFAULT_TIMEOUT_SECONDS: Final = 30.0

# La salida de un script no deberia pasar de unos pocos kilobytes. El tope
# esta para que una tabla de rutas absurda no se coma la memoria del servicio.
MAX_OUTPUT_BYTES: Final = 1024 * 1024


class Script(Enum):
    """Lo unico que se puede ejecutar. Conjunto cerrado a proposito."""

    GET_NET_STATE = "Get-NetState.ps1"
    RESTORE_NET_STATE = "Restore-NetState.ps1"
    TEST_TUNNEL = "Test-TunnelState.ps1"

    @property
    def path(self) -> Path:
        return SCRIPT_DIR / self.value


@dataclass(frozen=True)
class ScriptResult:
    """Lo que devolvio un script, ya en JSON y comprobado."""

    ok: bool
    data: dict[str, object] = field(default_factory=dict)
    error: str = ""


class PowerShellRunner:
    """Invoca los scripts de `ps/` y devuelve su JSON.

    Nunca lanza por un fallo del script: un error de red es informacion, no
    una excepcion. Lo que si es un error de programacion —un script que no
    esta donde deberia— tambien sale como resultado, porque el servicio tiene
    que seguir vivo para poder contarlo.
    """

    def __init__(
        self,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        executable: str = POWERSHELL,
    ) -> None:
        self._timeout = timeout_seconds
        self._executable = executable

    def run(self, script: Script, **parameters: str) -> ScriptResult:
        """Ejecuta un script con parametros con nombre.

        Los valores llegan del catalogo firmado. Van como elementos de la
        lista de argumentos, asi que un espacio o una comilla son un caracter
        mas y no cambian la orden.
        """
        if not script.path.is_file():
            return ScriptResult(
                ok=False, error=f"falta el script '{script.value}' en la instalacion"
            )

        try:
            completed = subprocess.run(
                self._argv(script, parameters),
                shell=False,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScriptResult(
                ok=False,
                error=f"'{script.value}' no respondio en {self._timeout:g} s",
            )
        except OSError as error:
            return ScriptResult(ok=False, error=f"no se pudo ejecutar PowerShell: {error.strerror}")

        return self._read(script, completed.returncode, completed.stdout)

    def _argv(self, script: Script, parameters: dict[str, str]) -> list[str]:
        argv = [
            self._executable,
            "-NoProfile",
            "-NonInteractive",
            # Los scripts se instalan junto al ejecutable, en un directorio con
            # escritura solo para Administradores y SYSTEM. Cuando exista el
            # certificado de firma de codigo hay que firmarlos y pasar esto a
            # AllSigned: entonces la politica dejaria de ser una formalidad.
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script.path),
        ]
        for name, value in parameters.items():
            argv.extend([f"-{name}", value])
        return argv

    def _read(self, script: Script, returncode: int, stdout: bytes) -> ScriptResult:
        if len(stdout) > MAX_OUTPUT_BYTES:
            return ScriptResult(ok=False, error=f"'{script.value}' devolvio una salida enorme")

        # Se ignora stderr a proposito: puede llevar rutas, nombres de
        # adaptador o restos de una traza, y esto acaba en el log.
        if not stdout.strip():
            return ScriptResult(
                ok=False,
                error=f"'{script.value}' no devolvio nada (codigo {returncode})",
            )

        try:
            parsed: object = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ScriptResult(ok=False, error=f"'{script.value}' no devolvio JSON valido")

        if not isinstance(parsed, dict):
            return ScriptResult(ok=False, error=f"'{script.value}' no devolvio un objeto JSON")

        data = dict(parsed)
        if data.get("ok") is True:
            return ScriptResult(ok=True, data=data)

        detail = data.get("error")
        return ScriptResult(
            ok=False,
            data=data,
            error=detail
            if isinstance(detail, str)
            else f"'{script.value}' fallo sin decir por que",
        )
