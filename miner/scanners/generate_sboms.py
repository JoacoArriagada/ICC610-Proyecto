import os
import json
import subprocess
import shutil
import yaml
from git import Repo

REPOS_JSON = "data/results/repos_activos.json"
REPOS_DIR = "data/repos"
SBOMS_DIR = "data/results/sboms"
VULNS_DIR = "data/results/vulns"
CICD_DIR = "data/results/cicd"

for directory in [REPOS_DIR, SBOMS_DIR, VULNS_DIR, CICD_DIR]:
    os.makedirs(directory, exist_ok=True)


def scan_workflow(file_path):
    issues = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if "npm install" in content and "npm ci" not in content:
            issues.append("Falta npm ci")
        
        with open(file_path, "r", encoding="utf-8") as f:
            parsed = yaml.safe_load(f)
        
        if not isinstance(parsed, dict):
            return issues
        
        permissions = parsed.get("permissions")
        if permissions == "write-all":
            issues.append("Permisos excesivos: write-all")
        elif isinstance(permissions, dict):
            if permissions.get("contents") == "write":
                issues.append("Permiso contents: write")
    except Exception:
        pass
    return issues


def procesar_repositorios():
    with open(REPOS_JSON, "r", encoding="utf-8") as f:
        repos = json.load(f)
    
    for repo in repos:
        name = repo["name"]
        clone_url = repo["clone_url"]
        repo_path = os.path.join(REPOS_DIR, name)
        
        sbom_path = os.path.join(SBOMS_DIR, f"{name}_sbom.json")
        vuln_path = os.path.join(VULNS_DIR, f"{name}_vuln.json")
        cicd_path = os.path.join(CICD_DIR, f"{name}_cicd.json")
        
        if not os.path.exists(repo_path):
            Repo.clone_from(clone_url, repo_path, depth=1)
        
        subprocess.run(["syft", f"dir:{repo_path}", "-o", f"json={sbom_path}"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["grype", f"sbom:{sbom_path}", "-o", f"json={vuln_path}"], check=True, stderr=subprocess.DEVNULL)
        
        workflows_dir = os.path.join(repo_path, ".github", "workflows")
        repo_issues = []
        if os.path.exists(workflows_dir):
            for file_name in os.listdir(workflows_dir):
                if file_name.endswith(".yml") or file_name.endswith(".yaml"):
                    file_path = os.path.join(workflows_dir, file_name)
                    issues = scan_workflow(file_path)
                    if issues:
                        repo_issues.append({
                            "workflow": file_name,
                            "issues": issues
                        })
        
        with open(cicd_path, "w", encoding="utf-8") as cicd_file:
            json.dump({"repositorio": name, "hallazgos": repo_issues}, cicd_file, indent=2)


if __name__ == "__main__":
    procesar_repositorios()
