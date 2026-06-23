"""Abstract base class for all Kraken modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from kraken.models import AttackResult, EngagementContext


class BaseModule(ABC):

    name: str = "base"

    @abstractmethod
    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        ...
