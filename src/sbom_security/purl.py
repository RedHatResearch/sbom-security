"""Normalize package references to Package URLs, and tell when two name one package.

A Package URL identifies a package unambiguously within its ecosystem, which is what
makes matching against vulnerability data precise: ``pkg:npm/express`` cannot collide
with a similarly named package from another ecosystem.
"""

import re
from collections.abc import Iterable

from packageurl import PackageURL

from sbom_security.models import NPM, PYPI, Dependency, PackageRef

__all__ = ["NPM", "PYPI", "package_key", "to_purl", "to_dependency", "to_dependencies"]

# Runs of these are equivalent in a Python package name, which pip compares in lower case.
_PYTHON_NAME_SEPARATORS = re.compile(r"[-_.]+")


def to_purl(ref: PackageRef) -> str:
    """Return the Package URL for a package reference.

    An npm scope becomes the Package URL namespace, so ``@babel/core`` is carried as
    the namespace ``@babel`` and the name ``core``. Ecosystems without scopes have no
    namespace at all.
    """
    namespace: str | None = None
    name = ref.name

    if ref.ecosystem == NPM and "/" in name:
        namespace, _, name = name.rpartition("/")

    return PackageURL(
        type=ref.ecosystem,
        namespace=namespace,
        name=name,
        version=ref.version,
    ).to_string()


def to_dependency(ref: PackageRef) -> Dependency:
    """Attach a Package URL to a package reference."""
    return Dependency(
        name=ref.name,
        version=ref.version,
        purl=to_purl(ref),
        ecosystem=ref.ecosystem,
    )


def to_dependencies(refs: Iterable[PackageRef]) -> tuple[Dependency, ...]:
    """Attach Package URLs to a collection of package references."""
    return tuple(to_dependency(ref) for ref in refs)


def package_key(purl: str) -> tuple[str, str]:
    """Identify the package a Package URL names, whatever its version.

    Two spellings of one package give the same key, so a dependency read from a
    lockfile can be matched against a Package URL another source published:
    ``pkg:npm/%40angular/core@17.0.0`` and ``pkg:npm/@angular/core`` are one package.
    Python names are compared the way pip compares them, so ``zope.interface`` and
    ``Zope_Interface`` are one package too.
    """
    parsed = PackageURL.from_string(purl)
    name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
    if parsed.type == PYPI:
        name = _PYTHON_NAME_SEPARATORS.sub("-", name).lower()
    return parsed.type, name
