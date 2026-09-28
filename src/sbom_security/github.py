"""Read npm dependency files directly from a public GitHub repository.

Only the dependency files themselves are fetched, never the repository. Nothing is
cloned, no package manager runs, and no code from the repository is executed.
"""

from dataclasses import dataclass
from typing import Any

import httpx

RAW_HOST = "https://raw.githubusercontent.com"
LOCKFILE = "package-lock.json"
MANIFEST = "package.json"
REQUIREMENTS = "requirements.txt"

# "HEAD" resolves to whatever the repository's default branch is called, which avoids
# having to guess between main, master and anything else.
DEFAULT_REF = "HEAD"


class FileNotFound(Exception):
    """The repository does not expose that file at the given ref."""


class LockfileNotFound(FileNotFound):
    """The repository does not expose a package-lock.json at the given ref."""


@dataclass(frozen=True)
class GitHubSource:
    """Fetches dependency files from raw.githubusercontent.com.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = RAW_HOST
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def file_url(self, owner: str, repo: str, ref: str, filename: str) -> str:
        return f"{self.base_url}/{owner}/{repo}/{ref}/{filename}"

    def lockfile_url(self, owner: str, repo: str, ref: str = DEFAULT_REF) -> str:
        return self.file_url(owner, repo, ref, LOCKFILE)

    async def fetch_lockfile(
        self, owner: str, repo: str, ref: str = DEFAULT_REF
    ) -> dict[str, Any]:
        """Return the parsed package-lock.json for a public repository."""
        try:
            return await self._fetch(owner, repo, ref, LOCKFILE)
        except FileNotFound as missing:
            raise LockfileNotFound(str(missing)) from missing

    async def fetch_manifest(
        self, owner: str, repo: str, ref: str = DEFAULT_REF
    ) -> dict[str, Any]:
        """Return the parsed package.json for a public repository."""
        return await self._fetch(owner, repo, ref, MANIFEST)

    async def fetch_requirements(
        self, owner: str, repo: str, ref: str = DEFAULT_REF
    ) -> str:
        """Return the requirements.txt of a public repository, as text."""
        response = await self._get(owner, repo, ref, REQUIREMENTS)
        return response.text

    async def _fetch(
        self, owner: str, repo: str, ref: str, filename: str
    ) -> dict[str, Any]:
        response = await self._get(owner, repo, ref, filename)
        return response.json()

    async def _get(
        self, owner: str, repo: str, ref: str, filename: str
    ) -> httpx.Response:
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport, follow_redirects=True
        ) as client:
            response = await client.get(self.file_url(owner, repo, ref, filename))

        if response.status_code == 404:
            raise FileNotFound(f"{owner}/{repo} has no {filename} at {ref}")
        response.raise_for_status()
        return response
