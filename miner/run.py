import argparse
import subprocess
import sys
import shutil
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Miner: Extrae y analiza vulnerabilidades de una organización de GitHub")
    parser.add_argument("--org", type=str, default="", help="Nombre de la organización en GitHub")
    parser.add_argument("--limit", type=int, default=5, help="Número máximo de repositorios a procesar")
    
    args = parser.parse_args()
    
    base_dir = Path(__file__).resolve().parent
    scanners_dir = base_dir / "scanners"
    
    print("=" * 60)
    print(f"INICIANDO MINER PARA ORGANIZACIÓN: {args.org}")
    print("=" * 60)
    
    # Paso 1: Fetch repos
    print("\n[1/3] Obteniendo repositorios...")
    result = subprocess.run(
        [sys.executable, str(scanners_dir / "fetch_repos.py"), "--org", args.org, "--limit", str(args.limit)],
        cwd=str(base_dir.parent)
    )
    if result.returncode != 0:
        print("Error al obtener repositorios")
        return 1
    
    # Paso 2: Generate SBOMs y escanear con Grype
    print("\n[2/3] Generando SBOMs y escaneando vulnerabilidades...")
    result = subprocess.run(
        [sys.executable, str(scanners_dir / "generate_sboms.py")],
        cwd=str(base_dir.parent)
    )
    if result.returncode != 0:
        print("Error al generar SBOMs")
        return 1
    
    # Paso 3: Ejecutar análisis CodeQL
    print("\n[3/3] Ejecutando análisis CodeQL...")
    result = subprocess.run(
        [sys.executable, str(scanners_dir / "generate_codeql.py")],
        cwd=str(base_dir.parent)
    )
    if result.returncode != 0:
        print("Error en análisis CodeQL")
        return 1
    
    # Paso 4: Limpieza de repositorios clonados
    print("\n[4/4] Limpiando repositorios clonados...")
    repos_path = base_dir.parent / "data" / "repos"
    if repos_path.exists():
        shutil.rmtree(repos_path, ignore_errors=True)
        print(f"Directorio {repos_path} eliminado.")
    else:
        print("No se encontró el directorio de repositorios para limpiar.")
    
    print("\n" + "=" * 60)
    print("MINER COMPLETADO EXITOSAMENTE")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
