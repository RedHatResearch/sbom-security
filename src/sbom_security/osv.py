"""Query OSV.dev for the vulnerabilities affecting a set of dependencies.

OSV aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability
database and around twenty further ecosystem-native feeds behind a single schema with
consistent version-range semantics, along with the advisories Linux distributions
publish for their own packages. Consuming it means we do not maintain a vulnerability
database of our own.

Lookups take two calls. ``/v1/querybatch`` answers "which vulnerabilities affect these
packages" for up to a thousand packages at a time, but returns only identifiers.
``/v1/vulns/{id}`` then returns the full record for each identifier found. The second
step dominates the time taken, so those requests are issued concurrently.

A language package is asked about by its Package URL. A distribution package is asked
about under its distribution's own name and version for it, which ``distribution``
works out, because matching it against upstream advisories would report backported
fixes as vulnerable.
"""

import asyncio
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from packageurl import PackageURL

from sbom_security import distribution
from sbom_security.models import Dependency, Vulnerability

OSV_API = "https://api.osv.dev"
MAX_QUERIES_PER_BATCH = 1000

# The page a person reads, as opposed to the API a program calls. It exists for every
# identifier OSV returns, whichever database the record came from.
OSV_PAGE = "https://osv.dev/vulnerability"

# Enough concurrency to make the fetches fast, bounded so that a large project does
# not open hundreds of simultaneous connections against a free public service.
MAX_CONCURRENT_FETCHES = 20


@dataclass(frozen=True)
class _Query:
    """One question for OSV, and how to recognise its answer within an advisory.

    ``ecosystem`` is None for a question asked by Package URL, whose answer is found by
    the package's name alone.
    """

    body: dict[str, Any]
    name: str
    ecosystem: str | None = None


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

        asked = [
            (index, query)
            for index, dependency in enumerate(dependencies)
            for query in _queries_for(dependency)
        ]
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            ids_per_query = await self._query_ids(client, [query for _, query in asked])

            # Which advisories affect each dependency, and in answer to which question.
            # A distribution package is asked about in each repository it could come
            # from, and the same advisory may answer more than one of them.
            matched: list[dict[str, list[_Query]]] = [{} for _ in dependencies]
            for (index, query), ids in zip(asked, ids_per_query, strict=True):
                for vuln_id in ids:
                    matched[index].setdefault(vuln_id, []).append(query)

            # The same advisory routinely affects several dependencies, so fetch each
            # record once rather than once per dependency that references it.
            unique_ids = {vuln_id for found in matched for vuln_id in found}
            records = await self._fetch_records(client, unique_ids)

        return {
            dependency.purl: tuple(
                _to_vulnerability(records[vuln_id], queries)
                for vuln_id, queries in found.items()
            )
            for dependency, found in zip(dependencies, matched, strict=True)
            if found
        }

    async def _query_ids(
        self, client: httpx.AsyncClient, queries: Sequence[_Query]
    ) -> list[list[str]]:
        """Return the vulnerability identifiers answering each query, in the same order."""
        chunks = list(_chunked(queries, MAX_QUERIES_PER_BATCH))
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
        self, client: httpx.AsyncClient, chunk: Sequence[_Query]
    ) -> list[dict[str, Any]]:
        payload = {"queries": [query.body for query in chunk]}
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


def _queries_for(dependency: Dependency) -> tuple[_Query, ...]:
    """Return what to ask OSV about a dependency.

    A distribution package is asked about once for each ecosystem its advisories could
    be filed under. One from a distribution not handled here is not asked about at all,
    rather than by Package URL, which upstream advisories would answer wrongly.
    """
    purl = PackageURL.from_string(dependency.purl)
    if purl.type not in distribution.PACKAGE_TYPES:
        return (_Query(body={"package": {"purl": dependency.purl}}, name=dependency.name),)

    name, version = distribution.advisory_package(purl)
    return tuple(
        _Query(
            body={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
            name=name,
            ecosystem=ecosystem,
        )
        for ecosystem in distribution.ecosystems(purl)
    )


def _to_vulnerability(raw: dict[str, Any], queries: Sequence[_Query]) -> Vulnerability:
    """Reduce an OSV record to the fields the report uses."""
    return Vulnerability(
        id=raw["id"],
        aliases=_aliases(raw),
        summary=raw.get("summary"),
        severity=_severity(raw),
        fixed_version=_fixed_version(raw, queries),
        url=f"{OSV_PAGE}/{raw['id']}",
    )


def _aliases(raw: dict[str, Any]) -> tuple[str, ...]:
    """Return the other identifiers for the same issue, the CVE number among them.

    A distribution names the CVE its advisory addresses as ``upstream`` rather than as
    an alias: RHSA-2024:0310 is Red Hat's fix for CVE-2023-5363. Either way it is the
    number a reader looks for.
    """
    return tuple(
        dict.fromkeys([*(raw.get("aliases") or ()), *(raw.get("upstream") or ())])
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


def _fixed_version(raw: dict[str, Any], queries: Sequence[_Query]) -> str | None:
    """Return the version that fixes this vulnerability for the package asked about.

    A record can describe several packages, and a distribution's record several of its
    releases, each fixed in a version of its own, so only an entry matching a question
    that was actually asked is considered.
    """
    for affected in raw.get("affected") or []:
        package = affected.get("package") or {}
        if not any(_answers(query, package) for query in queries):
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _answers(query: _Query, package: dict[str, Any]) -> bool:
    """Say whether an advisory's entry is about the package a query asked about."""
    return package.get("name") == query.name and query.ecosystem in (
        None,
        package.get("ecosystem"),
    )


def _chunked(queries: Sequence[_Query], size: int) -> Iterator[Sequence[_Query]]:
    for start in range(0, len(queries), size):
        yield queries[start : start + size]
