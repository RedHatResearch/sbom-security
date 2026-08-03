"""Read npm lockfiles.

A lockfile already pins every dependency in the tree to an exact version, so no
resolution is needed: parsing it yields the complete set directly.
"""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sbom_security.models import PackageRef

_NODE_MODULES = "node_modules/"


def parse_package_lock(path: Path) -> tuple[PackageRef, ...]:
    """Read a package-lock.json file and return every dependency it pins."""
    with path.open(encoding="utf-8") as handle:
        return parse_package_lock_data(json.load(handle))


def parse_package_lock_data(data: dict[str, Any]) -> tuple[PackageRef, ...]:
    """Extract dependencies from the contents of a package-lock.json.

    Lockfile versions 2 and 3 key entries by install path under ``packages``.
    Version 1 instead nests them under ``dependencies``, so it is handled separately.
    """
    packages = data.get("packages")
    if packages is not None:
        return _deduplicate(_from_packages(packages))
    return _deduplicate(_from_nested_dependencies(data.get("dependencies", {})))


def _from_packages(packages: dict[str, Any]) -> Iterable[PackageRef]:
    for path, entry in packages.items():
        if not path:
            # The empty key is the project itself, not one of its dependencies.
            continue
        if entry.get("link"):
            # A workspace symlink; the real entry appears elsewhere in the file.
            continue
        version = entry.get("version")
        if version:
            yield PackageRef(name=_name_from_path(path), version=version)


def _name_from_path(path: str) -> str:
    """Return the package name from an install path.

    Nested dependencies appear as ``node_modules/a/node_modules/b``, so the name is
    whatever follows the final ``node_modules/``. Scopes survive this unchanged,
    since ``node_modules/@scope/pkg`` yields ``@scope/pkg``.
    """
    _, _, name = path.rpartition(_NODE_MODULES)
    return name or path


def _from_nested_dependencies(dependencies: dict[str, Any]) -> Iterable[PackageRef]:
    for name, entry in dependencies.items():
        version = entry.get("version")
        if version:
            yield PackageRef(name=name, version=version)
        yield from _from_nested_dependencies(entry.get("dependencies", {}))


def _deduplicate(refs: Iterable[PackageRef]) -> tuple[PackageRef, ...]:
    """Drop repeats while preserving order.

    The same name and version can legitimately appear at several points in the tree,
    but it only needs to be reported, and queried, once.
    """
    return tuple(dict.fromkeys(refs))
