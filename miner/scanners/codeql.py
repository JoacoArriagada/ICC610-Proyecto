from miner.models import Repository
from miner.scanners.base import Scanner


class CodeQLScanner(Scanner):
    def run(self, repository: Repository) -> object:
        return {"scanner": "codeql", "repository_id": repository.id}
