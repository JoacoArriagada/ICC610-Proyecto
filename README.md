# ICC610 — Proyecto: Detección y Análisis de Vulnerabilidades

Resumen breve
---------------

Herramienta para detectar, analizar y visualizar vulnerabilidades en repositorios del dataset AIDev. El sistema está compuesto por tres componentes: Miner (extracción), Analyzer (análisis) y Visualizer (presentación).

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

- `miner/` — Orquestador y scripts para extraer repositorios, generar SBOMs (Syft), escanear dependencias (Grype) y ejecutar análisis estático (CodeQL).
- `analyzer/` — Notebooks Jupyter para análisis exploratorio de vulnerabilidades (frecuencia, severidad, patrones).
- `tests/` — Pruebas unitarias para modelos y scanners.
- `.devcontainer/` — Configuración Docker para reproducir el entorno completo (Python, Node.js, CodeQL, Syft, Grype).
- `data/` — Salidas generadas por el Miner (repos clonados, SBOMs, resultados de escaneos).

Requisitos y reproducibilidad
----------------------------

El proyecto se ejecuta mediante Docker Compose con un entorno completo que incluye:
- Python 3.11 con dependencias (pandas, seaborn, jupyterlab, etc.)
- Node.js 20.x
- CodeQL CLI v2.20.3 con paquetes de consulta (Python, JavaScript, Java)
- Syft y Grype (instalados via scripts oficiales)

---

## Tecnologías usadas

**Lenguajes y frameworks:**
- Python 3.11 (Miner y Analyzer)
- JavaScript/Node.js 20.x (pendiente: Visualizer)

**Herramientas de análisis:**
- **CodeQL** v2.20.3 — Análisis estático de código (queries para Python, JavaScript, Java)
- **Syft** v1.44.0 — Generación de SBOMs (Software Bill of Materials)
- **Grype** v0.112.0 — Escaneo de vulnerabilidades en dependencias

**Bibliotecas Python principales:**
- `requests` — Consumo de API de GitHub
- `python-dotenv` — Gestión de variables de entorno
- `GitPython` — Clonación y manejo de repositorios
- `pandas` y `seaborn` — Análisis y visualización de datos
- `jupyterlab` — Entorno interactivo para notebooks
- `PyYAML` — Procesamiento de archivos YAML
- `beautifulsoup4` — Parsing de HTML/XML

**Infraestructura:**
- Docker + Docker Compose — Contenerización y orquestación
- Dev Containers — Reproducibilidad del entorno de desarrollo

### Configuración inicial

#### 1. Crear archivo de variables de entorno

Crear un archivo `.env` en la raíz del proyecto:

```bash
# En Linux/Mac
touch .env
echo "GITHUB_TOKEN=tu_token_aquí" >> .env

# En Windows (CMD)
type nul > .env
echo GITHUB_TOKEN=tu_token_aquí >> .env
```

**Obtener token de GitHub:**
1. Ir a GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generar nuevo token con permiso `public_repo` (o `repo` para repos privados)
3. Copiar el token y colocarlo en el archivo `.env`

#### 2. Iniciar los contenedores Docker

```bash
# Construir imágenes (primera vez o después de cambios)
docker compose build

# Levantar contenedores en background
docker compose up -d

# Verificar que estén corriendo
docker compose ps
```

#### 3. Acceder a los servicios

```bash
# Entrar al contenedor del Miner
docker compose exec miner bash

# Acceder al Analyzer (Jupyter Lab)
# Abrir en el navegador: http://localhost:8888
```

### Uso con Docker Compose (Recomendado)

```bash
# Ejecutar el Miner completo (fetch + SBOMs + Grype + CodeQL + limpieza)
docker compose exec miner bash
python miner/run.py --org FlowiseAI --limit 5

# Extraer vulnerabilidades críticas
python extract_critical_vulns.py
```

### Uso directo de los componentes

```bash
# Obtener repositorios
python miner/scanners/fetch_repos.py --org FlowiseAI --limit 5

# Generar SBOMs y escanear vulnerabilidades
python miner/scanners/generate_sboms.py

# Ejecutar análisis CodeQL
python miner/scanners/generate_codeql.py

# Extraer vulnerabilidades críticas
python extract_critical_vulns.py

# Ejecutar pruebas
python -m pytest tests/
```

Estado actual
-------------

- ✅ **Miner**: Implementado con fetch de repos, generación de SBOMs, escaneo de dependencias y análisis CodeQL
- ✅ **Analyzer**: Notebooks Jupyter para análisis de resultados
- ✅ **Entorno reproducible**: Dockerfile y Docker Compose configurados
- ✅ **Pruebas**: Unit tests para modelos y scanners
- ⚠️ **Visualizer**: Pendiente de implementación (requisito obligatorio en JavaScript)

Cómo contribuir
--------------

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
