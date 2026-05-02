# ICC610 — Proyecto: Detección y Análisis de Vulnerabilidades

Resumen breve
---------------

Herramienta para detectar, analizar y visualizar vulnerabilidades en repositorios del dataset AIDev. El sistema está compuesto por tres componentes separados: Miner (extracción), Analyzer (análisis) y Visualizer (presentación).

Equipo
------

- Jonathan Chaves
- Joaquin Arriagada
- Lucas Colomera

Curso y Universidad
-------------------

ICC610 Ciberseguridad — Universidad de La Frontera

Estructura del proyecto
-----------------------

- `miner/` — scripts y utilidades para clonar repositorios, ejecutar CodeQL, generar SBOM (Syft) y escanear dependencias (Grype).
- `analyzer/` — notebooks y scripts para el análisis exploratorio (frecuencia, severidad, patrones).
- `visualizer/` — código para generar visualizaciones interactivas y reportes.
- `devcontainer/` — configuración para reproducir el entorno (Dev Container).
- `data/` — salidas estructuradas generadas por el Miner (dataset de vulnerabilidades).

Requisitos y reproducibilidad
----------------------------

El proyecto está diseñado para ejecutarse dentro de un Dev Container que incluya: Python, Node.js, CodeQL, Syft y Grype. Instrucciones rápidas:

```bash
# abrir en VS Code con Dev Container (recomendado)
# ejecutar los pasos del miner (ejemplo):
python -m miner.run --org <ORGANIZACION> --limit 50

# analizar resultados (notebook):
jupyter lab analyzer/

# generar visualizaciones:
node visualizer/start.js
```

Cómo contribuir
---------------

1. Crear una rama `feature/<tema>`.
2. Añadir cambios y pruebas mínimas.
3. Abrir PR explicando objetivos y pasos para reproducir.

Entregables
-----------

- Repositorio público con todo el código y la configuración del Dev Container.
- Poster físico y presentación de 3 minutos (resumen de hallazgos y arquitectura).

Contacto
-------

Para dudas: contactar a cualquiera de los integrantes del equipo (ver sección Equipo).

Licencia
-------

Contenido del curso — adaptar según políticas de la universidad.
