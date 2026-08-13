"""Nucleo del orquestador: modelos, arbitro, estado y log.

Logica pura. No importa nada de Windows ni de red, y no depende de las
demas capas del paquete: las dependencias apuntan siempre hacia aqui.
`tests/core/test_core_es_portable.py` lo comprueba en CI.
"""

from __future__ import annotations
