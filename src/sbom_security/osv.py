"""Query OSV.dev for the vulnerabilities affecting a set of dependencies.

OSV aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability
database and around twenty further ecosystem-native feeds behind a single schema with
consistent version-range semantics. Consuming it means we do not maintain a
vulnerability database of our own.

Lookups take two calls. ``/v1/querybatch`` answers "which vulnerabilities affect these
packages" for up to a thousand packages at a time, but returns only identifiers.
``/v1/vulns/{id}`` then returns the full record for each identifier found.
"""

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from sbom_security.models import Dependency, Vulnerability

OSV_API = "https://api.osv.dev"
MAX_QUERIES_PER_BATCH = 1000


@dataclass(frozen=True)
class OsvClient:
    """Reads vulnerability data from OSV.dev.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = OSV_API
    timeout: float = 30.0
    transport: httpx.BaseTransport | None = None

    def find_vulnerabilities(
        self, dependencies: Sequence[Dependency]
    ) -> dict[str, tuple[Vulnerability, ...]]:
        """Return the vulnerabilities affecting each dependency, keyed by Package URL.

        Dependencies with no known vulnerabilities are absent from the result rather
        than present with an empty value.
        """
        if not dependencies:
            return {}

        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            ids_per_dependency = self._query_ids(client, dependencies)

            # The same advisory routinely affects several dependencies, so fetch each
            # record once rather than once per dependency that references it.
            unique_ids = {vuln_id for ids in ids_per_dependency for vuln_id in ids}
            records = {vuln_id: self._fetch_record(client, vuln_id) for vuln_id in sorted(unique_ids)}

        found: dict[str, tuple[Vulnerability, ...]] = {}
        for dependency, ids in zip(dependencies, ids_per_dependency, strict=True):
            if ids:
                found[dependency.purl] = tuple(
                    _to_vulnerability(records[vuln_id], dependency) for vuln_id in ids
                )
        return found

    def _query_ids(
        self, client: httpx.Client, dependencies: Sequence[Dependency]
    ) -> list[list[str]]:
        """Return the vulnerability identifiers for each dependency, in the same order."""
        ids: list[list[str]] = []
        for chunk in _chunked(dependencies, MAX_QUERIES_PER_BATCH):
            payload = {"queries": [{"package": {"purl": item.purl}} for item in chunk]}
            response = client.post(f"{self.base_url}/v1/querybatch", json=payload)
            response.raise_for_status()
            results = response.json().get("results", [])

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

    def _fetch_record(self, client: httpx.Client, vuln_id: str) -> dict[str, Any]:
        response = client.get(f"{self.base_url}/v1/vulns/{vuln_id}")
        response.raise_for_status()
        return response.json()


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
