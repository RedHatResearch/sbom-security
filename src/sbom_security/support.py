"""Bring together the places support status comes from.

A project's published lifecycle, from endoflife.date, is the stronger answer and is
used wherever there is one. A project's own security policy, read by the policy agent,
fills in for the rest.

Reading policies is slow, so it never happens while a report is produced. Whatever a
report could not answer is handed on, where a queue is running, for a worker to look
up afterwards, and the next report includes it.
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sbom_security.endoflife import EndOfLifeClient
from sbom_security.models import Dependency, Support
from sbom_security.policy import PolicyAgent

# Receives the packages, as name and ecosystem pairs, whose support is still unknown.
Pending = Callable[[list[list[str]]], Awaitable[Any]]


class SupportFinder(Protocol):
    """Anything a report can ask for the support status of its dependencies."""

    async def find_support(self, dependencies: Sequence[Dependency]) -> dict[str, Support]:
        ...


@dataclass(frozen=True)
class SupportSources:
    """Every source of support status, asked together.

    ``pending`` is given the packages a report could not answer for and that have not
    been looked up yet; where it is None, nothing is looked up.
    """

    published: EndOfLifeClient
    extracted: PolicyAgent
    pending: Pending | None = None

    async def find_support(self, dependencies: Sequence[Dependency]) -> dict[str, Support]:
        """Return each dependency's support status, keyed by Package URL."""
        published, extracted = await asyncio.gather(
            self.published.find_support(dependencies),
            self.extracted.find_support(dependencies),
        )
        found = {**extracted, **published}

        unknown = self.extracted.unexamined(
            [dependency for dependency in dependencies if dependency.purl not in found]
        )
        if self.pending is not None and unknown:
            try:
                await self.pending(unknown)
            except Exception:  # pylint: disable=broad-exception-caught
                # The report is complete without it, and the next report that lacks
                # the same answers hands them on again.
                pass
        return found

    async def discover(self, packages: Sequence[Sequence[str]]) -> None:
        """Look up the security policies of packages, as submitted work."""
        await self.extracted.discover(packages)
