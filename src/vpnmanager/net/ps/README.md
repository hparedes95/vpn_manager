# `ps/` — scripts de red

Aquí viven los `.ps1` versionados que ejecuta el servicio.

Contrato de cada script:

- Parámetros tipados con `param(...)` y `[ValidateSet]`/`[ValidatePattern]` donde
  aplique. Se invocan con lista de argumentos, nunca concatenando una orden.
- Salida **siempre** en JSON: `ConvertTo-Json -Depth N -Compress`. Nada de texto
  para parsear.
- Errores en el mismo JSON, con un campo de estado. Un `throw` sin más deja al
  servicio adivinando.
- `$ErrorActionPreference = 'Stop'` al principio.

Pendientes: `Get-RouteTable.ps1`, `Add-Route.ps1`, `Remove-Route.ps1`,
`Get-DnsConfig.ps1`, `Set-DnsConfig.ps1`, `Get-Adapters.ps1`.
