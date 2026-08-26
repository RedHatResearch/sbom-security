"""Read an npm lockfile directly from a public GitHub repository.

Only the lockfile is fetched, never the repository itself. Nothing is cloned, no
package manager runs, and no code from the repository is executed.
"""

from dataclasses import dataclass
from typing import Any

import httpx

RAW_HOST = "https://raw.githubusercontent.com"
LOCKFILE = "package-lock.json"

# "HEAD" resolves to whatever the repository's default branch is called, which avoids
# having to guess between main, master and anything else.
DEFAULT_REF = "HEAD"


class LockfileNotFound(Exception):
    """The repository does not expose a package-lock.json at the given ref."""


@dataclass(frozen=True)
class GitHubSource:
    """Fetches lockfiles from raw.githubusercontent.com.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = RAW_HOST
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def lockfile_url(self, owner: str, repo: str, ref: str = DEFAULT_REF) -> str:
        return f"{self.base_url}/{owner}/{repo}/{ref}/{LOCKFILE}"

    async def fetch_lockfile(
        self, owner: str, repo: str, ref: str = DEFAULT_REF
    ) -> dict[str, Any]:
        """Return the parsed package-lock.json for a public repository."""
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport, follow_redirects=True
        ) as client:
            response = await client.get(self.lockfile_url(owner, repo, ref))

        if response.status_code == 404:
            raise LockfileNotFound(
                f"{owner}/{repo} has no {LOCKFILE} at {ref}. "
                "Repositories that publish a library, or that use yarn or pnpm, "
                "often do not commit one."
            )
        response.raise_for_status()
        return response.json()
