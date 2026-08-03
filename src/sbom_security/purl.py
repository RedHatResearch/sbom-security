"""Normalize package references to Package URLs.

A Package URL identifies a package unambiguously within its ecosystem, which is what
makes matching against vulnerability data precise: ``pkg:npm/express`` cannot collide
with a similarly named package from another ecosystem.
"""

from collections.abc import Iterable

from packageurl import PackageURL

from sbom_security.models import Dependency, PackageRef

NPM = "npm"


def to_purl(ref: PackageRef) -> str:
    """Return the Package URL for a package reference.

    An npm scope becomes the Package URL namespace, so ``@babel/core`` is carried as
    the namespace ``@babel`` and the name ``core``.
    """
    namespace, _, name = ref.name.rpartition("/")
    return PackageURL(
        type=NPM,
        namespace=namespace or None,
        name=name,
        version=ref.version,
    ).to_string()


def to_dependency(ref: PackageRef) -> Dependency:
    """Attach a Package URL to a package reference."""
    return Dependency(name=ref.name, version=ref.version, purl=to_purl(ref))


def to_dependencies(refs: Iterable[PackageRef]) -> tuple[Dependency, ...]:
    """Attach Package URLs to a collection of package references."""
    return tuple(to_dependency(ref) for ref in refs)
