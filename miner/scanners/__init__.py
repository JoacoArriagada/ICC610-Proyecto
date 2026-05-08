from miner.models import Repository


class CodeQLScanner:
    def run(self, repo: Repository) -> dict:
        from miner.scanners.generate_codeql import CodeQLAnalyzer
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        analyzer = CodeQLAnalyzer(
            repos_path=str(project_root / "data" / "repos"),
            output_path=str(project_root / "data" / "results" / "sast"),
        )
        try:
            analyzer.codeql_path = analyzer._resolver_codeql()
            sarif_data = analyzer.run_codeql(f"data/repos/{repo.name}", language=None)
            result = analyzer.parse_sarif(sarif_data)
        except Exception:
            result = {
                "total_issues": 0,
                "issues_by_severity": {"error": 0, "warning": 0, "note": 0},
                "issues": [],
            }
        result["scanner"] = "codeql"
        result["repository"] = repo.name
        return result


class SyftScanner:
    def run(self, repo: Repository) -> dict:
        import subprocess
        import json
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        repo_path = str(project_root / "data" / "repos" / repo.name)
        sbom_path = str(project_root / "data" / "results" / "sboms" / f"{repo.name}_sbom.json")

        subprocess.run(["syft", f"dir:{repo_path}", "-o", f"json={sbom_path}"],
                       check=True, stderr=subprocess.DEVNULL)
        with open(sbom_path, encoding="utf-8") as f:
            return {"scanner": "syft", "repository": repo.name, "data": json.load(f)}


class GrypeScanner:
    def run(self, repo: Repository) -> dict:
        import subprocess
        import json
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        sbom_path = str(project_root / "data" / "results" / "sboms" / f"{repo.name}_sbom.json")
        vuln_path = str(project_root / "data" / "results" / "vulns" / f"{repo.name}_vuln.json")

        subprocess.run(["grype", f"sbom:{sbom_path}", "-o", f"json={vuln_path}"],
                       check=True, stderr=subprocess.DEVNULL)
        with open(vuln_path, encoding="utf-8") as f:
            return {"scanner": "grype", "repository": repo.name, "data": json.load(f)}


__all__ = ["CodeQLScanner", "SyftScanner", "GrypeScanner"]
