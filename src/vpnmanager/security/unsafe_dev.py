"""VERIFICADOR DE PRUEBAS. NO PUEDE LLEGAR A UN PUESTO DE LA EMPRESA.

Acepta cualquier catalogo, firmado o no. Existe solo para poder probar el
software en una VM antes de que exista el certificado de firma de codigo.

**Lo que esto significa:** con este verificador puesto, el catalogo de
`%ProgramData%\\VpnManager\\profiles.json` deja de estar protegido por una
firma. Si en esa maquina alguien puede escribir ese fichero, puede elegir que
binario ejecuta un servicio que corre como SYSTEM. En una VM de pruebas eso da
igual; en el portatil de un compañero es una escalada de privilegios.

Por eso:

- Hay que pedirlo a mano, con `--allow-unsigned-catalog`. Nunca es el
  comportamiento por defecto.
- El servicio lo grita en el log cada vez que arranca asi.
- Un test comprueba que ningun modulo del proyecto lo importa salvo el
  arranque del servicio, para que no se cuele por la puerta de atras.

Cuando exista el certificado, esto se borra. No se "deja por si acaso".
"""

from __future__ import annotations

WARNING = (
    "CATALOGO SIN VERIFICAR: se esta aceptando profiles.json sin comprobar su "
    "firma. Esto es solo para pruebas. En un equipo de la empresa, cualquiera "
    "que pueda escribir ese fichero elige que ejecuta el servicio como SYSTEM."
)


class UnsafeUnsignedCatalogVerifier:
    """Da por bueno cualquier catalogo. Solo para pruebas."""

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return True
