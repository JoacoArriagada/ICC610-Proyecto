from abc import ABC, abstractmethod
from pathlib import Path
import subprocess
import json

class Scanner(ABC):
    """Base class for all scanners."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
    
    @abstractmethod
    def run(self, repo_name: str, repo_path: Path) -> dict:
        """Run the scanner on a repository."""
        pass
    
    def save_results(self, output_path: Path, data: dict) -> None:
        """Save scanner results to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
