"""Keep what has been looked up on disk, for exactly as long as it stays true.

Each kind of data is kept for as long as it can be relied on:

- The dependencies of a published version never change, because the version itself
  cannot. These SBOMs are kept for good, so a package depended on by fifty others is
  resolved once rather than fifty times.
- A project's support policy changes rarely, but it does change: a long-term support
  line is extended, an end of life is announced. It is kept for a while and then
  fetched again.
- Which vulnerabilities affect a version changes whenever an advisory is published, so
  that is not kept at all and every lookup stays live.

Files are used rather than a database: the data is a simple key to document mapping,
and keeping it on disk means one less service to run.
"""

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sbom_security.models import PackageRef, Sbom

# Long enough that a report rarely waits for a fetch, short enough that an announced
# change reaches reports within a month.
DEFAULT_LIFETIME = timedelta(days=30)


def _file_for(directory: Path, key: str) -> Path:
    """Return the file a key is stored in.

    The whole key is escaped into a single flat filename. Encoding it rather than
    mirroring it as directories means a key can never be interpreted as a path, so no
    key can reach outside the cache directory.
    """
    return directory / f"{quote(key, safe='')}.json"


def _write_atomically(path: Path, record: Any) -> None:
    """Write a JSON document so that no reader ever sees it half-written.

    The file is written under a temporary name and then renamed, because a rename is
    atomic. A reader therefore sees either the previous contents or the new ones, even
    when several workers write at once.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            json.dump(record, file, indent=2)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class SbomCache:
    """A directory of SBOMs, one file per package version.

    Entries never expire: a published version cannot change what it depends on.
    """

    directory: Path

    def path_for(self, purl: str) -> Path:
        return _file_for(self.directory, purl)

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
        """Store an SBOM, replacing any existing entry."""
        _write_atomically(
            self.path_for(sbom.purl),
            {
                "purl": sbom.purl,
                "dependencies": [
                    {"name": ref.name, "version": ref.version}
                    for ref in sbom.dependencies
                ],
            },
        )


@dataclass(frozen=True)
class Stored:
    """A document as it was retrieved from its source, and when."""

    document: Any
    retrieved_at: datetime


@dataclass(frozen=True)
class ExpiringCache:
    """A directory of documents relied on for a set time after they were retrieved.

    An expired entry is not deleted, and is still returned. The caller decides whether
    to fetch a fresh copy or, when the source cannot be reached, to fall back on the
    old one. The retrieval time travels with every entry, so its age is never hidden.
    """

    directory: Path
    lifetime: timedelta = DEFAULT_LIFETIME

    def path_for(self, key: str) -> Path:
        return _file_for(self.directory, key)

    def get(self, key: str) -> Stored | None:
        """Return a stored document, fresh or not, or None if there is none."""
        path = self.path_for(key)
        if not path.exists():
            return None

        record = json.loads(path.read_text(encoding="utf-8"))
        return Stored(
            document=record["document"],
            retrieved_at=datetime.fromisoformat(record["retrieved_at"]),
        )

    def put(self, key: str, stored: Stored) -> None:
        """Store a document, replacing any existing entry."""
        _write_atomically(
            self.path_for(key),
            {
                "retrieved_at": stored.retrieved_at.isoformat(),
                "document": stored.document,
            },
        )

    def is_fresh(self, stored: Stored, now: datetime) -> bool:
        """Say whether a stored document is still within its lifetime."""
        return now - stored.retrieved_at < self.lifetime
