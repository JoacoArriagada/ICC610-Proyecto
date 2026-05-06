import os
import requests
import json
import argparse
import logging
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")
RESULTS_DIR = "data/results"
OUTPUT_FILE = os.path.join(RESULTS_DIR, "repos_activos.json")

HEADERS = {"Authorization": f"token {TOKEN}"}
LOGGER = logging.getLogger(__name__)


def get_stars(repo):
    return repo.get("stargazers_count", 0)


def get_top_repos(org, limit=5):
    url = f"https://api.github.com/orgs/{org}/repos?per_page=100&type=public"
    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        LOGGER.error("Error al obtener repositorios: HTTP %s", response.status_code)
        return []

    repos = response.json()
    repos.sort(key=get_stars, reverse=True)
    top = repos[:limit]

    active = []
    for r in top:
        active.append({
            "name": r["name"],
            "clone_url": r["clone_url"],
            "language": r["language"],
            "stargazers_count": r["stargazers_count"]
        })
    return active


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(description="Fetch top repositories from a GitHub organization")
    parser.add_argument("--org", type=str, default="", help="GitHub organization name")
    parser.add_argument("--limit", type=int, default=5, help="Number of top repositories to fetch")

    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    LOGGER.info("Buscando los %d repositorios principales de %s...", args.limit, args.org)
    repos = get_top_repos(args.org, args.limit)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(repos, f, indent=2)
    LOGGER.info("Se han guardado %d repositorios exitosamente.", len(repos))
