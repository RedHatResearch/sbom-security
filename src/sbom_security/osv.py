"""Query OSV.dev for the vulnerabilities affecting a set of dependencies.

OSV aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability
database and around twenty further ecosystem-native feeds behind a single schema with
consistent version-range semantics. Consuming it means we do not maintain a
vulnerability database of our own.

Lookups take two calls. ``/v1/querybatch`` answers "which vulnerabilities affect these
packages" for up to a thousand packages at a time, but returns only identifiers.
``/v1/vulns/{id}`` then returns the full record for each identifier found. The second
step dominates the time taken, so those requests are issued concurrently.
"""

import asyncio
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from sbom_security.models import Dependency, Vulnerability

OSV_API = "https://api.osv.dev"
MAX_QUERIES_PER_BATCH = 1000

# Enough concurrency to make the fetches fast, bounded so that a large project does
# not open hundreds of simultaneous connections against a free public service.
MAX_CONCURRENT_FETCHES = 20


@dataclass(frozen=True)
class OsvClient:
    """Reads vulnerability data from OSV.dev.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = OSV_API
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    async def find_vulnerabilities(
        self, dependencies: Sequence[Dependency]
    ) -> dict[str, tuple[Vulnerability, ...]]:
        """Return the vulnerabilities affecting each dependency, keyed by Package URL.

        Dependencies with no known vulnerabilities are absent from the result rather
        than present with an empty value.
        """
        if not dependencies:
            return {}

        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            ids_per_dependency = await self._query_ids(client, dependencies)

            # The same advisory routinely affects several dependencies, so fetch each
            # record once rather than once per dependency that references it.
            unique_ids = {vuln_id for ids in ids_per_dependency for vuln_id in ids}
            records = await self._fetch_records(client, unique_ids)

        found: dict[str, tuple[Vulnerability, ...]] = {}
        for dependency, ids in zip(dependencies, ids_per_dependency, strict=True):
            if ids:
                found[dependency.purl] = tuple(
                    _to_vulnerability(records[vuln_id], dependency) for vuln_id in ids
                )
        return found

    async def _query_ids(
        self, client: httpx.AsyncClient, dependencies: Sequence[Dependency]
    ) -> list[list[str]]:
        """Return the vulnerability identifiers for each dependency, in the same order."""
        chunks = list(_chunked(dependencies, MAX_QUERIES_PER_BATCH))
        responses = await asyncio.gather(
            *(self._query_chunk(client, chunk) for chunk in chunks)
        )

        ids: list[list[str]] = []
        for chunk, results in zip(chunks, responses, strict=True):
            # Results are positional. A short response would silently attribute one
            # package's vulnerabilities to another, so refuse to continue instead.
            if len(results) != len(chunk):
                raise RuntimeError(
                    f"OSV returned {len(results)} results for {len(chunk)} queries"
                )
            ids.extend(
                [vuln["id"] for vuln in result.get("vulns") or []] for result in results
            )
        return ids

    async def _query_chunk(
        self, client: httpx.AsyncClient, chunk: Sequence[Dependency]
    ) -> list[dict[str, Any]]:
        payload = {"queries": [{"package": {"purl": item.purl}} for item in chunk]}
        response = await client.post(f"{self.base_url}/v1/querybatch", json=payload)
        response.raise_for_status()
        return response.json().get("results", [])

    async def _fetch_records(
        self, client: httpx.AsyncClient, vuln_ids: set[str]
    ) -> dict[str, dict[str, Any]]:
        """Fetch every advisory record concurrently, bounded by a semaphore."""
        limit = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

        async def fetch(vuln_id: str) -> tuple[str, dict[str, Any]]:
            async with limit:
                response = await client.get(f"{self.base_url}/v1/vulns/{vuln_id}")
                response.raise_for_status()
                return vuln_id, response.json()

        return dict(await asyncio.gather(*(fetch(v) for v in sorted(vuln_ids))))


def _to_vulnerability(raw: dict[str, Any], dependency: Dependency) -> Vulnerability:
    """Reduce an OSV record to the fields the report uses."""
    return Vulnerability(
        id=raw["id"],
        aliases=tuple(raw.get("aliases") or ()),
        summary=raw.get("summary"),
        severity=_severity(raw),
        fixed_version=_fixed_version(raw, dependency.name),
    )


def _severity(raw: dict[str, Any]) -> str | None:
    """Return a severity label, preferring a plain rating over a CVSS vector.

    Advisories sourced from GitHub carry a word such as ``HIGH``; others provide only
    a scoring vector, which is still more useful than nothing.
    """
    database_specific = raw.get("database_specific") or {}
    if severity := database_specific.get("severity"):
        return severity

    scores = raw.get("severity") or []
    if scores:
        return scores[0].get("score")
    return None


def _fixed_version(raw: dict[str, Any], name: str) -> str | None:
    """Return the version that fixes this vulnerability for the given package.

    A record can describe several packages, so only the entry matching this
    dependency is considered.
    """
    for affected in raw.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("name") != name:
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _chunked(
    dependencies: Sequence[Dependency], size: int
) -> Iterator[Sequence[Dependency]]:
    for start in range(0, len(dependencies), size):
        yield dependencies[start : start + size]
