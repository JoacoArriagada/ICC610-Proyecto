from miner.models import Repository
from miner.scanners.base import Scanner


class GrypeScanner(Scanner):
    def run(self, repository: Repository) -> object:
        return {"scanner": "grype", "repository_id": repository.id}
