# Como-Usar

## Contenedor

1. Abrir este repositorio en Visual Studio Code.
2. Instalar la extensión Dev Containers.
3. Ejecutar el comando Reopen in Container.

## Comandos dentro del contenedor

python -m pip install -r requirements.txt
python -m pytest

## Uso de modelos en Python

from datetime import datetime, UTC

from miner.models import (
    CodeQLAlert,
    Dataset,
    Dependency,
    GrypeFinding,
    Organization,
    Repository,
    SBOM,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityType,
)

dependency = Dependency(name="pkg", version="1.0.0", license="MIT")
sbom = SBOM(id="sbom-1", format="spdx", generated_at=datetime.now(UTC), dependencies=[dependency])
repository = Repository(id="r1", name="repo", url="https://example.com", status="ANALYZED", sbom=sbom)
organization = Organization(id="o1", name="org", dataset_source="AIDev", repositories=[repository])
alert = CodeQLAlert(rule_id="r1", message="m", file_path="a.py", line_start=1, severity="high")
vulnerability = Vulnerability(
    id="v1",
    type=VulnerabilityType.CODE,
    severity=SeverityLevel.HIGH,
    repository_id="r1",
    source=VulnerabilitySource.CODEQL,
    codeql_alert=alert,
)
dataset = Dataset(
    dataset_id="d1",
    organization_id=organization.id,
    generated_at=datetime.now(UTC),
    repositories=[repository],
    vulnerabilities=[vulnerability],
)
