# `security/` — firma del catálogo y saneado de logs

## Qué hay

- `catalog.py` — `load_catalog(payload, signature, verifier)`. Verifica la firma
  y, solo si valida, lee el JSON. Hay un ejemplo comentado en
  [`docs/profiles.example.json`](../../../docs/profiles.example.json), y un test
  que lo carga para que no se pudra cuando cambie el esquema.

## Qué falta

- **El verificador de verdad.** `CatalogVerifier` es un puerto: entran bytes y
  firma, sale sí o no. Está sin implementar porque el esquema no está decidido
  —firma detached con la clave del certificado de firma de código, Authenticode
  sobre el fichero, u otra cosa—. Mientras tanto el verificador por defecto es
  `RejectingVerifier`, que dice que no a todo.
- **Leer el fichero de `%ProgramData%\VpnManager\profiles.json`** con su ACL
  (escritura solo para Administradores y SYSTEM). Eso es del servicio: aquí solo
  entran bytes.
- `redact.py` — saneado de logs. No se escriben credenciales, tokens ni cookies,
  ni siquiera truncados.

## Las tres decisiones de `catalog.py`

**No se parsea nada sin verificar antes.** El parser es el código más delicado
del módulo y nunca ve datos que no estén firmados.

**La firma es detached.** Si fuera un campo dentro del JSON habría que decidir
cómo se serializa el resto para firmarlo, y cualquier diferencia de espacios o
de orden de claves entre quien firma y quien verifica se convierte en un fallo
intermitente imposible de depurar.

**O carga todo o no carga nada** — también cuando el problema es un perfil mal
escrito, no solo cuando falla la firma. Un catálogo a medias deja al usuario sin
encontrar su VPN sin que nadie sepa por qué, y deja al árbitro con sesiones vivas
cuyo perfil ya no existe, que es el estado incoherente del que tiene que
defenderse. Es una línea de código cambiarlo si algún día pesa más la
disponibilidad parcial.

## Por qué importa

El catálogo define qué binario ejecuta un servicio corriendo en SYSTEM. Si un
usuario sin privilegios puede influir en su contenido, tiene ejecución como
SYSTEM en su puesto. De ahí la firma y la ACL, y de ahí que el pipe solo acepte
`profile_id` del catálogo: nunca rutas, argumentos ni comandos.

La v1 **no gestiona secretos**. Cada cliente oficial sigue usando su propio
almacén de credenciales.
