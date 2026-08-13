# `net/` — rutas, DNS y adaptadores

Capa que toca la red de verdad. Solo se ejecuta dentro de `vpnmgr-svc`, en
SYSTEM. La UI nunca importa nada de aquí.

## Qué irá aquí

- `routes.py`, `dns.py`, `adapters.py` — envoltorios finos sobre los scripts de
  `ps/`.
- `probe.py` — la comprobación de estado real: adaptador activo + ruta hacia la
  red destino + respuesta de la IP testigo interna. Las tres, o no está
  `CONNECTED`. El icono del cliente oficial no es fuente de verdad.
- `snapshot.py` — foto del estado de red previo a un perfil `FULL`, que es lo
  que el watchdog restaura si la UI no confirma dentro de la ventana (90 s).

## `ps/` — las operaciones de red van en PowerShell versionado

Entrada y salida en JSON (`ConvertTo-Json`). No se reimplementa `Get-NetRoute`
parseando texto en Python: el formato de texto cambia entre versiones de Windows
y el JSON no.

Los `.ps1` se invocan con lista de argumentos y sus parámetros salen del catálogo
firmado. Nunca se construye una línea de PowerShell concatenando datos.
