from miner.models import Repository
from miner.scanners.base import Scanner


class SyftScanner(Scanner):
    def run(self, repository: Repository) -> object:
        return {"scanner": "syft", "repository_id": repository.id}
