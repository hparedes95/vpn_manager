# `security/` — firma del catálogo y saneado de logs

## Qué irá aquí

- `catalog.py` — carga y **verificación de firma** de
  `%ProgramData%\VpnManager\profiles.json` (ACL de escritura solo para
  Administradores y SYSTEM). El servicio verifica la firma en cada carga; si no
  valida, **no arranca ningún perfil** y lo registra. Un catálogo que no valida
  no es un catálogo vacío: es un fallo que se ve.
- `redact.py` — saneado de logs. No se escriben credenciales, tokens ni cookies,
  ni siquiera truncados.

## Por qué importa

El catálogo define qué binario ejecuta un servicio corriendo en SYSTEM. Si un
usuario sin privilegios puede influir en su contenido, tiene ejecución como
SYSTEM en su puesto. De ahí la firma y la ACL, y de ahí que el pipe solo acepte
`profile_id` del catálogo: nunca rutas, argumentos ni comandos.

La v1 **no gestiona secretos**. Cada cliente oficial sigue usando su propio
almacén de credenciales.
