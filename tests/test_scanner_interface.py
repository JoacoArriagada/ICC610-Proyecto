from miner.models import Repository, RepositoryStatus
from miner.scanners import CodeQLScanner, GrypeScanner, SyftScanner


def test_codeql_scanner_instantiation() -> None:
    scanner = CodeQLScanner()
    repo = Repository(id="r1", name="repo", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    result = scanner.run(repo)
    assert result["scanner"] == "codeql"


def test_syft_scanner_instantiation() -> None:
    scanner = SyftScanner()
    repo = Repository(id="r1", name="repo", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    result = scanner.run(repo)
    assert result["scanner"] == "syft"


def test_grype_scanner_instantiation() -> None:
    scanner = GrypeScanner()
    repo = Repository(id="r1", name="repo", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    result = scanner.run(repo)
    assert result["scanner"] == "grype"
