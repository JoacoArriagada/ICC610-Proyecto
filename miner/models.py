from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class SeverityLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityType(str, Enum):
    CODE = "CODE"
    DEPENDENCY = "DEPENDENCY"
    SECURITY = "SECURITY"
    UNKNOWN = "UNKNOWN"


class VulnerabilitySource(str, Enum):
    CODEQL = "CODEQL"
    GRYPE = "GRYPE"


class RepositoryStatus(str, Enum):
    PENDING = "PENDING"
    CLONING = "CLONING"
    ANALYSIS_IN_PROGRESS = "ANALYSIS_IN_PROGRESS"
    ANALYSIS_COMPLETE = "ANALYSIS_COMPLETE"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    license: str


@dataclass(frozen=True)
class SBOM:
    id: str
    format: str
    generated_at: datetime
    dependencies: List[Dependency]

    def __post_init__(self) -> None:
        if len(self.dependencies) < 1:
            raise ValueError("SBOM must include at least one dependency")


@dataclass(frozen=True)
class CodeQLAlert:
    rule_id: str
    message: str
    file_path: str
    line_start: int
    severity: str


@dataclass(frozen=True)
class GrypeFinding:
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str


@dataclass(frozen=True)
class Location:
    file_path: str
    start_line: int
    end_line: int
    symbol: str


@dataclass(frozen=True)
class Vulnerability:
    id: str
    type: VulnerabilityType
    severity: SeverityLevel
    repository_id: str
    source: VulnerabilitySource
    location: Optional[Location] = None
    codeql_alert: Optional[CodeQLAlert] = None
    grype_finding: Optional[GrypeFinding] = None

    def __post_init__(self) -> None:
        if self.codeql_alert and self.grype_finding:
            raise ValueError("Vulnerability cannot include both CodeQLAlert and GrypeFinding")
        if self.source == VulnerabilitySource.CODEQL and self.codeql_alert is None:
            raise ValueError("CodeQL source requires CodeQLAlert")
        if self.source == VulnerabilitySource.GRYPE and self.grype_finding is None:
            raise ValueError("Grype source requires GrypeFinding")


@dataclass(frozen=True)
class Repository:
    id: str
    name: str
    url: str
    local_path: str
    status: RepositoryStatus
    sbom: Optional[SBOM] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass(frozen=True)
class Organization:
    id: str
    name: str
    dataset_source: str
    repositories: List[Repository] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.repositories) > 50:
            raise ValueError("Organization repository limit exceeded")


@dataclass(frozen=True)
class Dataset:
    dataset_id: str
    organization: Organization
    format: str
    generated_at: datetime
    repositories: List[Repository]
    vulnerabilities: List[Vulnerability]

    def __post_init__(self) -> None:
        if not self.organization.dataset_source:
            raise ValueError("Organization dataset_source is required")
