from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from miner.models import Repository


class Scanner(ABC):
    @abstractmethod
    def run(self, repository: Repository) -> object:
        raise NotImplementedError
