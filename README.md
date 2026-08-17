# VPN Manager

Orquestador local de conexiones VPN para Windows. Gobierna los **clientes VPN
oficiales ya instalados** en el equipo: no implementa túneles ni reimplementa
protocolos.

El contexto completo del proyecto —qué es, qué no es, y las reglas que no se
negocian— está en [`CLAUDE.md`](CLAUDE.md). Léelo antes de tocar nada.

## Arquitectura en dos líneas

- **`vpnmgr-svc`** — servicio Windows en SYSTEM. Único que toca red, rutas, DNS y
  procesos de VPN.
- **`vpnmgr-ui`** — proceso en sesión de usuario, PySide6 con icono de bandeja.
  Sin privilegios.

Se comunican por named pipe con ACL restringida a un grupo de AD. El servicio
**solo** acepta `connect(profile_id)` y `disconnect(profile_id)` sobre ids del
catálogo firmado: nunca rutas, binarios ni argumentos llegados por el pipe.

## Entorno de desarrollo

Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Comprobaciones

Lo mismo que ejecuta CI:

```bash
ruff check .            # lint
ruff format --check .   # formato
mypy                    # tipado estricto sobre src/ y tests/
pytest                  # tests
```

El núcleo se testea **en Linux**, sin Windows y sin ningún cliente VPN instalado.
No es casualidad: `tests/test_portability.py` lee el AST de cada módulo de `core/`
y de `connectors/base.py`, y falla si aparece un import de Windows, de red, o de
otra capa. Si ese test se vuelve incómodo, el problema es el código que lo
incomoda.

## Estructura

```
src/vpnmanager/
├── core/         # modelos, arbitro, estado, log. Logica pura, testeable
├── connectors/   # base.py + uno por proveedor
├── net/          # rutas, DNS, adaptadores + ps/*.ps1
├── security/     # firma del catalogo, saneado de logs
├── service/      # vpnmgr-svc: servicio y servidor del pipe
└── ui/           # vpnmgr-ui: PySide6
```

Cada capa tiene su propio `README.md` con lo que va dentro y por qué. Los
paquetes están creados pero vacíos a propósito: no hay esqueletos con
`NotImplementedError` esperando a que alguien los rellene.

## Estado

- **Fase 4 (entorno), completada**: estructura, empaquetado, lint, tipado
  estricto, tests y CI.
- **`connectors/base.py`, completado**: interfaz de conector, `LauncherConnector`,
  el puerto `ProcessLauncher` y el registro. Lógica pura, sin implementación de
  Windows todavía — ver la pregunta abierta en
  [`src/vpnmanager/connectors/README.md`](src/vpnmanager/connectors/README.md).
- **`core/arbiter.py`, completado**: un solo túnel `FULL` a la vez, los `SPLIT`
  conviven, los `APP` fuera del árbitro. Devuelve un `ConnectionPlan` —a quién
  desconectar antes, si hace falta confirmación, si hay que armar el watchdog—
  y no ejecuta nada. Si lo que estorba es un cliente que no se sabe desconectar
  solo, rechaza el plan y dice cuál hay que cerrar a mano.
- **Validación del catálogo, completada**: rutas de binario absolutas y fuera de
  recursos de red, `post_connect_apps` sometidas al mismo filtro que el cliente,
  y formato comprobado de IPs y CIDR antes de que ningún valor llegue a un
  `.ps1` ejecutado como SYSTEM.

- **`core/protocol.py`, completado**: el contrato entre los dos procesos.
  Gramática cerrada en la que no cabe una ruta ni un argumento, decodificador
  estricto y errores que nunca repiten lo recibido.

- **`core/watchdog.py`, completado**: la ventana de 90 s que deshace una
  conexión que la interfaz no confirma. Máquina de estados sobre un reloj
  inyectado, sin hilos: el temporizador real y la restauración de red son del
  servicio.

- **`security/catalog.py`, completado**: verificación de firma y lectura del
  catálogo. No se parsea nada sin verificar antes, el verificador por defecto
  rechaza todo, y o carga el catálogo entero o no carga nada. El esquema de
  firma es un puerto sin implementar, a la espera de decidirlo. Ejemplo en
  [`docs/profiles.example.json`](docs/profiles.example.json).

- **`service/orchestrator.py`, completado**: la pieza que ata las demás. Recibe
  una petición, consulta al árbitro, arma el watchdog, habla con el conector y
  devuelve una respuesta. El recorrido entero —incluida la reversión cuando
  nadie confirma— se prueba en CI, con la red y los clientes tras dos puertos
  que implementará `net/`.

**Todo lo que se puede escribir sin un Windows delante está escrito.** Lo que
queda son adaptadores de plataforma y dos decisiones pendientes:

- **`connectors/process.py` y `net/`, completados**: el lanzador de procesos, los
  tres `.ps1` versionados, la sonda de estado real y la foto/restauración de red.
  Escritos pero **sin ejecutar nunca**: no hay Windows en CI. Sus tests
  comprueban qué se le pide al sistema, no qué contesta.

| Falta | Bloqueado por |
|---|---|
| `CatalogVerifier` de verdad | Decidir el esquema de firma |
| Servidor del pipe con ACL | El grupo de AD |
| UI PySide6 y el `UserSessionLauncher` real | — |
| Los ocho conectores por proveedor | — |
| Empaquetado PyInstaller + Intune | Certificado de firma |
| Verificar `docs/CONECTORES.md` | Un puesto real con los clientes |

Los conectores y las versiones de cliente verificadas se anotan en
[`docs/CONECTORES.md`](docs/CONECTORES.md). Hoy no hay ninguna verificada.
