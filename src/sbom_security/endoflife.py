"""Look up whether a dependency's release line still receives fixes.

Many large projects publish how long each release line is supported, but no package
registry records it. endoflife.date collects it for several hundred products, per
release line, and lists the Package URLs that belong to each product, so a dependency
is looked up by the identifier it already has.

Two kinds of document are read: the list of Package URLs and their products, and each
product's release lines. Both change rarely, so both are kept for a while rather than
fetched for every report. A status is never kept, only the dates it is worked out
from, so the answer stays right as those dates pass.
"""

import asyncio
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version

from sbom_security.cache import ExpiringCache, Stored
from sbom_security.models import (
    ACTIVE,
    END_OF_LIFE,
    LIMITED,
    PUBLISHED,
    PYPI,
    SUPPORTED,
    Dependency,
    Support,
)
from sbom_security.purl import package_key

ENDOFLIFE_API = "https://endoflife.date/api/v1"
ENDOFLIFE_SITE = "https://endoflife.date"
PACKAGE_URLS = "identifiers/purl"

# A report touches only a handful of products, but a cold cache meeting a large tree
# should still not open more connections than a free community service deserves.
MAX_CONCURRENT_FETCHES = 5

_LEADING_NUMBERS = re.compile(r"\d+(?:\.\d+)*")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EndOfLifeClient:
    """Reads published support lifecycles from endoflife.date.

    ``transport`` exists so tests can answer requests without network access, and
    ``clock`` so that they can say what today is.
    """

    cache: ExpiringCache
    base_url: str = ENDOFLIFE_API
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None
    clock: Callable[[], datetime] = utc_now

    async def find_support(
        self, dependencies: Sequence[Dependency]
    ) -> dict[str, Support]:
        """Return the support status of each dependency, keyed by Package URL.

        A dependency is absent when endoflife.date does not cover its project, or
        covers the project but not the release line its version belongs to.
        """
        if not dependencies:
            return {}

        now = self.clock()
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            index = await self._fetch(client, PACKAGE_URLS, now)
            products = _products_by_package(index.document)
            wanted = {
                dependency.purl: products.get(package_key(dependency.purl))
                for dependency in dependencies
            }
            documents = await self._fetch_products(
                client, {name for name in wanted.values() if name}, now
            )

        found: dict[str, Support] = {}
        for dependency in dependencies:
            name = wanted[dependency.purl]
            if name in documents:
                support = _support(dependency, name, documents[name], now.date())
                if support is not None:
                    found[dependency.purl] = support
        return found

    async def _fetch_products(
        self, client: httpx.AsyncClient, names: set[str], now: datetime
    ) -> dict[str, Stored]:
        """Fetch the release lines of each product, a few at a time."""
        limit = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

        async def fetch(name: str) -> tuple[str, Stored | None]:
            async with limit:
                path = f"products/{quote(name, safe='')}"
                return name, await self._fetch(client, path, now, missing_ok=True)

        results = await asyncio.gather(*(fetch(name) for name in sorted(names)))
        return {name: stored for name, stored in results if stored is not None}

    async def _fetch(
        self,
        client: httpx.AsyncClient,
        path: str,
        now: datetime,
        missing_ok: bool = False,
    ) -> Stored | None:
        """Return a document, from the cache while it is fresh and from the source after.

        When the source cannot be reached, an expired copy stands in rather than the
        report failing: its retrieval time goes into the report with it, so its age is
        never hidden. With nothing kept there is no honest answer, and the failure
        propagates.

        ``missing_ok`` turns a 404 into None, for a document the source says no longer
        exists. That is an answer rather than a failure, so no older copy stands in.
        """
        cached = self.cache.get(path)
        if cached is not None and self.cache.is_fresh(cached, now):
            return cached

        try:
            response = await client.get(f"{self.base_url}/{path}")
            if missing_ok and response.status_code == 404:
                return None
            response.raise_for_status()
            fetched = Stored(document=response.json(), retrieved_at=now)
        except (httpx.HTTPError, ValueError):
            if cached is None:
                raise
            return cached

        self.cache.put(path, fetched)
        return fetched


def _products_by_package(index: Mapping[str, Any]) -> dict[tuple[str, str], str]:
    """Map every package endoflife.date lists to the product it belongs to.

    An entry that cannot be read is skipped: it names nothing a dependency could be
    matched against, and one malformed entry should not cost every other answer.
    """
    products: dict[tuple[str, str], str] = {}
    for entry in index.get("result") or []:
        try:
            key = package_key(entry["identifier"])
            name = entry["product"]["name"]
        except (KeyError, TypeError, ValueError):
            continue
        products.setdefault(key, name)
    return products


def _support(
    dependency: Dependency, name: str, stored: Stored, today: date
) -> Support | None:
    """Describe the support of the release line a dependency's version belongs to."""
    product = stored.document.get("result") or {}
    release = _release_for(dependency, product.get("releases") or [])
    if release is None:
        return None

    status, phase = _status(release, product.get("labels") or {}, today)
    return Support(
        line=release["name"],
        status=status,
        phase=phase,
        active_support_until=release.get("eoasFrom"),
        support_until=release.get("eolFrom"),
        basis=PUBLISHED,
        source=(product.get("links") or {}).get("html") or f"{ENDOFLIFE_SITE}/{name}",
        retrieved_at=stored.retrieved_at.isoformat(timespec="seconds"),
    )


def _release_for(
    dependency: Dependency, releases: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    """Return the release line a version belongs to, or None if it is on none of them.

    Lines are compared number by number, never as text: ``2.10.0`` belongs to
    ``2.10``, not to ``2.1``. A project may name lines at more than one depth, as Vue
    names ``1``, ``2.7`` and ``3.4``, so the most specific line that matches wins.
    """
    version = _version_numbers(dependency)
    best: Mapping[str, Any] | None = None
    best_depth = 0
    for release in releases:
        line = _leading_numbers(str(release.get("name", "")))
        if len(line) > best_depth and version[: len(line)] == line:
            best, best_depth = release, len(line)
    return best


def _version_numbers(dependency: Dependency) -> tuple[int, ...]:
    """Return the numbers that place a version on a release line.

    Python versions are read the way pip reads them: PEP 440 allows forms such as
    ``1!2.0``, whose leading digits are an epoch rather than the release.
    """
    if dependency.ecosystem == PYPI:
        try:
            return Version(dependency.version).release
        except InvalidVersion:
            return ()
    return _leading_numbers(dependency.version)


def _leading_numbers(text: str) -> tuple[int, ...]:
    """Return the dotted numbers text begins with: ``5.0.0-beta.3`` gives (5, 0, 0)."""
    match = _LEADING_NUMBERS.match(text)
    return tuple(int(part) for part in match.group().split(".")) if match else ()


def _status(
    release: Mapping[str, Any], labels: Mapping[str, Any], today: date
) -> tuple[str, str | None]:
    """Say how much support a line receives today, and what its project calls that.

    ``labels`` holds the project's own names for its periods of support. A project
    with no name for a main period, such as Express, does not distinguish one from a
    later, reduced one, so its lines can only be said to be supported or not.
    """
    if _has_ended(release.get("isEol"), release.get("eolFrom"), today):
        return END_OF_LIFE, None
    if not labels.get("eoas"):
        return SUPPORTED, labels.get("eol")
    if _has_ended(release.get("isEoas"), release.get("eoasFrom"), today):
        return LIMITED, labels.get("eol")
    return ACTIVE, labels.get("eoas")


def _has_ended(flag: Any, announced: str | None, today: date) -> bool:
    """Say whether a period of support is over.

    An announced date decides. The flag stored beside it was true on the day
    endoflife.date generated the document, which may have been weeks ago, so it
    decides only for periods that ended without a date being recorded.
    """
    if announced:
        return date.fromisoformat(announced) <= today
    return bool(flag)
