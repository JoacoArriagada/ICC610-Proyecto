import argparse
import logging
import shutil
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Miner: Extrae y analiza vulnerabilidades de una organizacion de GitHub")
    parser.add_argument("--org", type=str, default="", help="Nombre de la organizacion en GitHub")
    parser.add_argument("--limit", type=int, default=5, help="Numero maximo de repositorios a procesar")

    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent

    LOGGER.info("=" * 60)
    LOGGER.info("INICIANDO MINER PARA ORGANIZACION: %s", args.org)
    LOGGER.info("=" * 60)

    # Paso 1: Fetch repos
    LOGGER.info("[1/4] Obteniendo repositorios...")
    from miner.scanners.fetch_repos import get_top_repos
    import json
    import os

    results_dir = str(project_root / "data" / "results")
    output_file = os.path.join(results_dir, "repos_activos.json")
    os.makedirs(results_dir, exist_ok=True)

    repos = get_top_repos(args.org, args.limit)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(repos, f, indent=2)
    LOGGER.info("Se han guardado %d repositorios.", len(repos))

    if not repos:
        LOGGER.warning("No se encontraron repositorios para %s", args.org)
        return 1

    # Paso 2: Generate SBOMs y escanear con Grype
    LOGGER.info("[2/4] Generando SBOMs y escaneando vulnerabilidades...")
    from miner.scanners.generate_sboms import procesar_repositorios
    procesar_repositorios()

    # Paso 3: Ejecutar analisis CodeQL
    LOGGER.info("[3/4] Ejecutando analisis CodeQL...")
    from miner.scanners.generate_codeql import CodeQLAnalyzer
    analyzer = CodeQLAnalyzer(
        repos_path=str(project_root / "data" / "repos"),
        output_path=str(project_root / "data" / "results" / "sast"),
    )
    analyzer.run()

    # Paso 4: Limpieza de repositorios clonados
    LOGGER.info("[4/4] Limpiando repositorios clonados...")
    repos_path = project_root / "data" / "repos"
    if repos_path.exists():
        shutil.rmtree(repos_path, ignore_errors=True)
        LOGGER.info("Directorio %s eliminado.", repos_path)
    else:
        LOGGER.info("No se encontro el directorio de repositorios para limpiar.")

    LOGGER.info("=" * 60)
    LOGGER.info("MINER COMPLETADO EXITOSAMENTE")
    LOGGER.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
