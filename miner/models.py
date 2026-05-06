from __future__ import annotations

from datetime import datetime, UTC
from enum import Enum
from typing import Optional


class RepositoryStatus(Enum):
    FETCHED = "fetched"
    CLONED = "cloned"
    SBOM_GENERATED = "sbom_generated"
    GRYPE_SCANNED = "grype_scanned"
    CODEQL_ANALYZED = "codeql_analyzed"
    ANALYSIS_COMPLETE = "analysis_complete"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class VulnerabilityType(Enum):
    CODE = "code"
    DEPENDENCY = "dependency"


class VulnerabilitySource(Enum):
    CODEQL = "codeql"
    GRYPE = "grype"


class Dependency:
    def __init__(self, name: str, version: str, license: str) -> None:
        self.name = name
        self.version = version
        self.license = license


class SBOM:
    def __init__(
        self,
        id: str,
        format: str,
        generated_at: datetime,
        dependencies: list[Dependency],
    ) -> None:
        if not dependencies:
            raise ValueError("SBOM must have at least one dependency")
        self.id = id
        self.format = format
        self.generated_at = generated_at
        self.dependencies = dependencies


class CodeQLAlert:
    def __init__(
        self,
        rule_id: str,
        message: str,
        file_path: str,
        line_start: int,
        severity: str,
    ) -> None:
        self.rule_id = rule_id
        self.message = message
        self.file_path = file_path
        self.line_start = line_start
        self.severity = severity


class Location:
    def __init__(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        symbol: Optional[str] = None,
    ) -> None:
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.symbol = symbol


class GrypeFinding:
    def __init__(
        self,
        vulnerability_id: str,
        package_name: str,
        installed_version: str,
        fixed_version: str,
        severity: str,
    ) -> None:
        self.vulnerability_id = vulnerability_id
        self.package_name = package_name
        self.installed_version = installed_version
        self.fixed_version = fixed_version
        self.severity = severity


class Vulnerability:
    def __init__(
        self,
        id: str,
        type: VulnerabilityType,
        severity: SeverityLevel,
        repository_id: str,
        source: VulnerabilitySource,
        codeql_alert: Optional[CodeQLAlert] = None,
        grype_finding: Optional[GrypeFinding] = None,
        location: Optional[Location] = None,
    ) -> None:
        if source == VulnerabilitySource.CODEQL and codeql_alert is None:
            raise ValueError("Vulnerability from CODEQL requires codeql_alert")
        if source == VulnerabilitySource.GRYPE and grype_finding is None:
            raise ValueError("Vulnerability from GRYPE requires grype_finding")
        if codeql_alert is not None and grype_finding is not None:
            raise ValueError("Vulnerability cannot have both codeql_alert and grype_finding")
        self.id = id
        self.type = type
        self.severity = severity
        self.repository_id = repository_id
        self.source = source
        self.codeql_alert = codeql_alert
        self.grype_finding = grype_finding
        self.location = location


class Repository:
    def __init__(
        self,
        id: str,
        name: str,
        url: str,
        local_path: str,
        status: RepositoryStatus,
        vulnerabilities: Optional[list[Vulnerability]] = None,
    ) -> None:
        self.id = id
        self.name = name
        self.url = url
        self.local_path = local_path
        self.status = status
        self.vulnerabilities = vulnerabilities or []


class Organization:
    def __init__(
        self,
        id: str,
        name: str,
        dataset_source: str,
        repositories: list[Repository],
    ) -> None:
        if len(repositories) > 50:
            raise ValueError("Organization cannot have more than 50 repositories")
        self.id = id
        self.name = name
        self.dataset_source = dataset_source
        self.repositories = repositories


class Dataset:
    def __init__(
        self,
        dataset_id: str,
        organization: Organization,
        format: str,
        generated_at: datetime,
        repositories: list[Repository],
        vulnerabilities: list[Vulnerability],
    ) -> None:
        if not organization.dataset_source:
            raise ValueError("Dataset requires organization with dataset_source")
        self.dataset_id = dataset_id
        self.organization = organization
        self.format = format
        self.generated_at = generated_at
        self.repositories = repositories
        self.vulnerabilities = vulnerabilities
