# ICC610 — Proyecto: Detección y Análisis de Vulnerabilidades

Resumen breve
---------------

Herramienta para detectar, analizar y visualizar vulnerabilidades en repositorios del dataset AIDev. El sistema está compuesto por tres componentes: Miner (extracción), Analyzer (análisis) y Visualizer (presentación).

Equipo
------

- Jonathan Chavez
- Joaquin Arriagada
- Lucas Colomera

Curso y Universidad
-------------------

ICC610 Ciberseguridad — Universidad de La Frontera

Estructura del proyecto
-----------------------

- `miner/` — Orquestador y scripts para extraer repositorios, generar SBOMs (Syft), escanear dependencias (Grype) y ejecutar análisis estático (CodeQL).
- `analyzer/` — Notebooks Jupyter para análisis exploratorio de vulnerabilidades (frecuencia, severidad, patrones).
- `visualizer/` — Dashboard web interactivo (HTML/JS/CSS) para explorar, filtrar y visualizar las métricas y vulnerabilidades extraídas.
- `tests/` — Pruebas unitarias para modelos y scanners.
- `.devcontainer/` — Configuración Docker para reproducir el entorno completo (Python, Node.js, CodeQL, Syft, Grype).
- `data/` — Salidas generadas por el Miner (repos clonados, SBOMs, resultados de escaneos).

```
├── miner/
│   ├── __init__.py           # Package init
│   ├── models.py             # Repository dataclass
│   ├── run.py                # CLI entrypoint
│   └── scanners/
│       ├── __init__.py       # Scanner classes (CodeQL, Syft, Grype)
│       ├── fetch_repos.py    # GitHub API client
│       ├── generate_sboms.py # git clone + SBOM + Grype + CI/CD scan
│       ├── generate_codeql.py# CodeQL static analysis
│       ├── queries/          # QL queries personalizadas
│       └── run_codeql.sh     # Shell helper para CodeQL
├── data/
│   └── results/
│       ├── repos_activos.json
│       ├── sast/             # Reportes CodeQL SARIF
│       ├── sboms/            # SBOMs generados por Syft
│       ├── vulns/            # Escaneos de Grype
│       └── cicd/             # Hallazgos CI/CD
├── analyzer/
│   └── analisis_vulnerabilidades.ipynb  # Jupyter notebook
├── visualizer/
│   ├── index.html            # Dashboard HTML
│   ├── app.js                # Lógica del dashboard
│   ├── charts.js             # Gráficos (Chart.js + D3.js)
│   └── styles.css            # Estilos
├── tests/
│   ├── test_models.py        # Tests de modelos
│   └── test_scanner_interface.py  # Tests de scanners
├── .devcontainer/
│   ├── Dockerfile            # Imagen con Python + Node + CodeQL + Syft + Grype
│   └── devcontainer.json     # Config VSCode Dev Container
├── serve.py                  # Servidor HTTP para visualizer
├── docker-compose.yml        # Orquestación (miner, analyzer, visualizer)
├── requirements.txt
└── .env.example
```
Requisitos y reproducibilidad
----------------------------

El proyecto se ejecuta mediante Docker Compose con un entorno completo que incluye:
- Python 3.11 con dependencias (pandas, seaborn, jupyterlab, etc.)
- Node.js 20.x
- CodeQL CLI v2.25.3 con paquetes de consulta (Python, JavaScript, Java)
- Syft y Grype (instalados via scripts oficiales)

---

## Tecnologías usadas

**Lenguajes y frameworks:**
- Python 3.11 (Miner y Analyzer)
- JavaScript/Node.js 20.x (Visualizer)

**Herramientas de análisis:**
- **CodeQL** v2.25.3 — Análisis estático de código (queries para Python, JavaScript, Java)
- **Syft** (latest) — Generación de SBOMs (Software Bill of Materials)
- **Grype** (latest) — Escaneo de vulnerabilidades en dependencias

**Bibliotecas Python principales:**
- `requests` — Consumo de API de GitHub
- `python-dotenv` — Gestión de variables de entorno
- `GitPython` — Clonación y manejo de repositorios
- `pandas` y `seaborn` — Análisis y visualización de datos
- `jupyterlab` — Entorno interactivo para notebooks
- `PyYAML` — Procesamiento de archivos YAML
- `beautifulsoup4` — Parsing de HTML/XML
- `pytest` — Pruebas de funcionamiento

**Infraestructura:**
- Docker + Docker Compose — Contenerización y orquestación
- Dev Containers — Reproducibilidad del entorno de desarrollo

### Configuración inicial

#### 1. Crear archivo de variables de entorno

Copia el archivo de ejemplo para crear tu propio `.env` en la raíz del proyecto:

```bash
# En Linux/Mac
cp .env.example .env

# En Windows (CMD)
copy .env.example .env
```

**Obtener token de GitHub:**
1. Ir a GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generar nuevo token con permiso `public_repo` (o `repo` para repos privados)
3. Copiar el token y reemplazar el valor en tu nuevo archivo `.env`

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
Abrir en el navegador: http://localhost:8888

# Acceder al Visualizer (Dashboard Web)
Abrir en el navegador: http://localhost:8080
```

### Uso con Docker Compose (Recomendado)

```bash
# Ejecutar el Miner completo Generico (fetch + SBOMs + Grype + CodeQL + limpieza)
docker compose exec miner bash
python miner/run.py --org <organizacion> --limit <cantidad>

# Ejecutar el Miner completo (fetch + SBOMs + Grype + CodeQL + limpieza)
docker compose exec miner bash
python miner/run.py --org FlowiseAI --limit 5
```

Estado actual
-------------

- ✅ **Miner**: Implementado con fetch de repos, generación de SBOMs, escaneo de dependencias y análisis CodeQL
- ✅ **Analyzer**: Notebooks Jupyter para análisis de resultados
- ✅ **Entorno reproducible**: Dockerfile y Docker Compose configurados
- ✅ **Pruebas**: Unit tests para modelos y scanners
- ✅ **Visualizer**: Implementado dashboard interactivo para exploración de vulnerabilidades

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
