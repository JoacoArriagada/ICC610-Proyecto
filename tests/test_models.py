from datetime import datetime, UTC

import pytest

from miner.models import (
    CodeQLAlert,
    Dataset,
    Dependency,
    GrypeFinding,
    Location,
    Organization,
    Repository,
    RepositoryStatus,
    SBOM,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityType,
)


def test_dependency_instantiation() -> None:
    dependency = Dependency(name="pkg", version="1.0.0", license="MIT")
    assert dependency.name == "pkg"


def test_sbom_requires_dependency() -> None:
    dependency = Dependency(name="pkg", version="1.0.0", license="MIT")
    sbom = SBOM(id="sbom-1", format="spdx", generated_at=datetime.now(UTC), dependencies=[dependency])
    assert sbom.dependencies[0].name == "pkg"


def test_sbom_empty_dependencies_raises() -> None:
    with pytest.raises(ValueError):
        SBOM(id="sbom-2", format="spdx", generated_at=datetime.now(UTC), dependencies=[])


def test_codeql_alert_instantiation() -> None:
    alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
    assert alert.rule_id == "r1"


def test_location_instantiation() -> None:
    location = Location(file_path="a.py", start_line=1, end_line=2, symbol="f")
    assert location.file_path == "a.py"


def test_grype_finding_instantiation() -> None:
    finding = GrypeFinding(
        vulnerability_id="CVE-0000",
        package_name="pkg",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        severity="high",
    )
    assert finding.package_name == "pkg"


def test_vulnerability_allows_single_source() -> None:
    alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
    location = Location(file_path="a.py", start_line=1, end_line=2, symbol="f")
    vuln = Vulnerability(
        id="v1",
        type=VulnerabilityType.CODE,
        severity=SeverityLevel.HIGH,
        repository_id="repo1",
        source=VulnerabilitySource.CODEQL,
        codeql_alert=alert,
        location=location,
    )
    assert vuln.codeql_alert is not None
    assert vuln.grype_finding is None


def test_vulnerability_rejects_dual_source() -> None:
    alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
    finding = GrypeFinding(
        vulnerability_id="CVE-0000",
        package_name="pkg",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        severity="high",
    )
    with pytest.raises(ValueError):
        Vulnerability(
            id="v1",
            type=VulnerabilityType.CODE,
            severity=SeverityLevel.HIGH,
            repository_id="repo1",
            source=VulnerabilitySource.CODEQL,
            codeql_alert=alert,
            grype_finding=finding,
        )


def test_vulnerability_requires_codeql_alert() -> None:
    with pytest.raises(ValueError):
        Vulnerability(
            id="v1",
            type=VulnerabilityType.CODE,
            severity=SeverityLevel.HIGH,
            repository_id="repo1",
            source=VulnerabilitySource.CODEQL,
        )


def test_vulnerability_requires_grype_finding() -> None:
    with pytest.raises(ValueError):
        Vulnerability(
            id="v1",
            type=VulnerabilityType.DEPENDENCY,
            severity=SeverityLevel.HIGH,
            repository_id="repo1",
            source=VulnerabilitySource.GRYPE,
        )


def test_repository_instantiation() -> None:
    repo = Repository(id="r1", name="repo", url="https://example.com", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    assert repo.name == "repo"


def test_repository_with_vulnerabilities() -> None:
    alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
    vuln = Vulnerability(
        id="v1",
        type=VulnerabilityType.CODE,
        severity=SeverityLevel.HIGH,
        repository_id="r1",
        source=VulnerabilitySource.CODEQL,
        codeql_alert=alert,
    )
    repo = Repository(
        id="r1",
        name="repo",
        url="https://example.com",
        local_path="/tmp/repo",
        status=RepositoryStatus.ANALYSIS_COMPLETE,
        vulnerabilities=[vuln],
    )
    assert len(repo.vulnerabilities) == 1


def test_organization_repo_limit() -> None:
    repositories = [
        Repository(id=str(i), name=f"r{i}", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
        for i in range(50)
    ]
    organization = Organization(id="o1", name="org", dataset_source="AIDev", repositories=repositories)
    assert len(organization.repositories) == 50


def test_organization_repo_limit_exceeded() -> None:
    repositories = [
        Repository(id=str(i), name=f"r{i}", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
        for i in range(51)
    ]
    with pytest.raises(ValueError):
        Organization(id="o1", name="org", dataset_source="AIDev", repositories=repositories)


def test_dataset_instantiation() -> None:
    repo = Repository(id="r1", name="repo", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
    vuln = Vulnerability(
        id="v1",
        type=VulnerabilityType.CODE,
        severity=SeverityLevel.HIGH,
        repository_id="r1",
        source=VulnerabilitySource.CODEQL,
        codeql_alert=alert,
    )
    organization = Organization(id="o1", name="org", dataset_source="AIDev", repositories=[repo])
    dataset = Dataset(
        dataset_id="d1",
        organization=organization,
        format="json",
        generated_at=datetime.now(UTC),
        repositories=[repo],
        vulnerabilities=[vuln],
    )
    assert dataset.dataset_id == "d1"


def test_dataset_requires_organization_source() -> None:
    repo = Repository(id="r1", name="repo", url="u", local_path="/tmp/repo", status=RepositoryStatus.ANALYSIS_COMPLETE)
    organization = Organization(id="o1", name="org", dataset_source="", repositories=[repo])
    with pytest.raises(ValueError):
        Dataset(
            dataset_id="d1",
            organization=organization,
            format="json",
            generated_at=datetime.now(UTC),
            repositories=[repo],
            vulnerabilities=[],
        )
