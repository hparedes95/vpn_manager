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

Pendiente, por orden: árbitro de túnel, protocolo del pipe, watchdog de
reversión, carga y verificación del catálogo firmado, implementación de
`ProcessLauncher` para Windows y los conectores por proveedor.

Los conectores y las versiones de cliente verificadas se anotan en
[`docs/CONECTORES.md`](docs/CONECTORES.md). Hoy no hay ninguna verificada.
