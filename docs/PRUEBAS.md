# Cómo probar esto sin quedarte fuera del equipo

Nada del código que toca Windows se ha ejecutado nunca. Estas pruebas no son
una formalidad: son la primera vez que este software se encuentra con una
máquina de verdad.

## Antes de empezar

**No pruebes en el PC de oficina.** Usa una VM con acceso por consola, donde
perder la red no cueste un viaje. El software está pensado para correr en un
equipo que es destino de sesiones RDP, y su fallo característico es dejarlo
inalcanzable.

El instalador **no está firmado**. Windows y SmartScreen avisarán: es esperado.

## Orden de las pruebas

Está pensado para que cada paso solo pueda romper lo que el anterior ya
demostró que funciona.

### 1. Los scripts de red, a mano y sin el servicio

Es lo más importante y lo que más probable es que falle. Como administrador:

```powershell
cd "C:\Program Files\VpnManager\vpnmanager\net\ps"
$estado = & powershell -ExecutionPolicy Bypass -File .\Get-NetState.ps1
$estado    # ¿es JSON? ¿aparecen tus rutas y tus DNS?
```

Ahora rompe algo a propósito —añade una ruta, cambia el DNS de un adaptador— y
restaura:

```powershell
& powershell -ExecutionPolicy Bypass -File .\Restore-NetState.ps1 -State $estado
```

**Si esto no deja la red como estaba, para aquí.** El watchdog entero depende
de este paso, y sin él conectar un túnel completo es apostarse el equipo.

### 2. El servicio en consola

En consola es más fácil de depurar que como servicio. Como administrador:

```powershell
& "C:\Program Files\VpnManager\vpnmgr-svc.exe" --allow-unsigned-catalog
```

Debe escribir el aviso de catálogo sin verificar, decir cuántos perfiles cargó
y quedarse escuchando. Si el catálogo tiene erratas, las dice todas de una vez:
edita `C:\ProgramData\VpnManager\profiles.json` y vuelve a arrancar.

### 3. La bandeja

Abre `vpnmgr-ui.exe`. Deberías ver tus perfiles con **«Abrir cliente»** en
todos: es correcto, porque ningún conector se ha verificado todavía.

Prueba un perfil `APP` o `SPLIT` primero. No tocan la ruta por defecto, así que
no pueden dejarte fuera.

### 4. El watchdog, a propósito

**Antes de confiar en él.** Con la VM delante y acceso por consola:

1. Conecta un perfil `FULL`.
2. **Cierra la bandeja** en cuanto acepte.
3. Espera 90 segundos mirando el log del servicio.

Tiene que aparecer una línea de reversión y la red tiene que volver a como
estaba. Si no aparece, el watchdog no protege nada y no debe salir de la VM.

### 5. Un `FULL` de verdad

Solo ahora, y la primera vez con alguien físicamente al lado de la máquina.

## Qué anotar

Cada cliente VPN que pruebes va a `CONECTORES.md`: versión exacta, orden
probada, qué devuelve, y si pide interacción. Es lo que decide si un conector
puede dejar de ser un simple lanzador.

Y lo que falle, que fallará: el mensaje de error del log tal cual. Están
escritos para que digan qué parte no pudo hacerse, no solo que algo no se pudo.

## Lo que esta versión no es

- **No está firmada**, ni el ejecutable ni el catálogo.
- Con `--allow-unsigned-catalog`, quien pueda escribir `profiles.json` en esa
  máquina elige qué binario ejecuta un servicio que corre como SYSTEM. En una
  VM de pruebas da igual. En el equipo de un compañero, no.
- El pipe solo admite Administradores hasta que exista el grupo de AD.

Nada de esto se despliega hasta que haya certificado y grupo.
