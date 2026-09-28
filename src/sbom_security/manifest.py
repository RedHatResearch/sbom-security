"""Read npm manifests.

A manifest says what a project asked for; a lockfile records what it got. Where a
repository commits no lockfile — libraries usually do not, and yarn and pnpm projects
never produce one — the declared ranges are all there is to go on, and they have to be
resolved before anything can be matched against vulnerability data.
"""

from typing import Any

from sbom_security.models import Requirement

# Both are installed, and both can carry vulnerabilities. Separating what only runs at
# build time from what reaches production is worth doing, but it is a question about
# relevance rather than about reading the file, so it is not decided here.
DEPENDENCY_FIELDS = ("dependencies", "devDependencies")


def parse_package_json(data: dict[str, Any]) -> tuple[Requirement, ...]:
    """Extract the dependencies a package.json declares, as name and range pairs."""
    requirements: list[Requirement] = []
    seen: set[str] = set()

    for field in DEPENDENCY_FIELDS:
        declared = data.get(field) or {}
        for name, version_range in declared.items():
            if name in seen or not isinstance(version_range, str):
                continue
            seen.add(name)
            requirements.append(Requirement(name=name, range=version_range))

    return tuple(requirements)


def project_name(data: dict[str, Any]) -> str:
    """Return what the manifest calls the project."""
    name = data.get("name")
    return name if isinstance(name, str) and name else "unnamed project"
