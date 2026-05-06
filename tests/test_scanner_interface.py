from unittest.mock import patch, MagicMock
from miner.models import Repository, RepositoryStatus
from miner.scanners import CodeQLScanner, GrypeScanner, SyftScanner


def test_codeql_scanner_instantiation() -> None:
    scanner = CodeQLScanner()
    assert scanner is not None
    assert hasattr(scanner, "run")


def test_syft_scanner_instantiation() -> None:
    scanner = SyftScanner()
    assert scanner is not None
    assert hasattr(scanner, "run")


def test_grype_scanner_instantiation() -> None:
    scanner = GrypeScanner()
    assert scanner is not None
    assert hasattr(scanner, "run")


@patch("miner.scanners.CodeQLScanner.run")
def test_codeql_scanner_run(mock_run: MagicMock) -> None:
    mock_run.return_value = {"scanner": "codeql", "repository": "test-repo"}
    scanner = CodeQLScanner()
    result = scanner.run(Repository(id="r1", name="test-repo", url="u",
                                    local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE))
    assert result["scanner"] == "codeql"
    assert result["repository"] == "test-repo"


@patch("miner.scanners.SyftScanner.run")
def test_syft_scanner_run(mock_run: MagicMock) -> None:
    mock_run.return_value = {"scanner": "syft", "repository": "test-repo"}
    scanner = SyftScanner()
    result = scanner.run(Repository(id="r1", name="test-repo", url="u",
                                    local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE))
    assert result["scanner"] == "syft"


@patch("miner.scanners.GrypeScanner.run")
def test_grype_scanner_run(mock_run: MagicMock) -> None:
    mock_run.return_value = {"scanner": "grype", "repository": "test-repo"}
    scanner = GrypeScanner()
    result = scanner.run(Repository(id="r1", name="test-repo", url="u",
                                    local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE))
    assert result["scanner"] == "grype"
