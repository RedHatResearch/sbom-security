"""Store one SBOM per package version on disk.

A published version is immutable, so the set of dependencies it declares never
changes. That makes these entries permanently valid: once written, they never need
invalidating, and a package depended on by fifty others is resolved once rather than
fifty times.

Vulnerability data is deliberately not cached here. Which advisories affect a version
changes whenever a new one is published, so that lookup stays live.

Files are used rather than a database: the data is a simple key to document mapping,
and keeping it on disk means one less service to run.
"""

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from sbom_security.models import PackageRef, Sbom


@dataclass(frozen=True)
class SbomCache:
    """A directory of SBOMs, one file per package version."""

    directory: Path

    def path_for(self, purl: str) -> Path:
        """Return the file a Package URL is stored in.

        The whole Package URL is escaped into a single flat filename. Encoding it
        rather than mirroring it as directories means a package name can never be
        interpreted as a path, so no name can reach outside the cache directory.
        """
        return self.directory / f"{quote(purl, safe='')}.json"

    def has(self, purl: str) -> bool:
        return self.path_for(purl).exists()

    def get(self, purl: str) -> Sbom | None:
        """Return a stored SBOM, or None if it has not been built yet."""
        path = self.path_for(purl)
        if not path.exists():
            return None

        record = json.loads(path.read_text(encoding="utf-8"))
        return Sbom(
            purl=record["purl"],
            dependencies=tuple(
                PackageRef(name=item["name"], version=item["version"])
                for item in record["dependencies"]
            ),
        )

    def put(self, sbom: Sbom) -> None:
        """Store an SBOM, replacing any existing entry.

        The file is written under a temporary name and then renamed, because a rename
        is atomic. A reader therefore sees either the previous contents or the new
        ones, never a half-written file, even when several workers write at once.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {
            "purl": sbom.purl,
            "dependencies": [
                {"name": ref.name, "version": ref.version} for ref in sbom.dependencies
            ],
        }

        handle, temporary = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as file:
                json.dump(record, file, indent=2)
            os.replace(temporary, self.path_for(sbom.purl))
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
