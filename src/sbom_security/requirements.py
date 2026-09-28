"""Read Python requirements files.

A requirements file mixes two things that elsewhere live apart: some lines pin an
exact version, others give a range. Both are read the same way here and separated
later, since a pin is simply a range that admits one version.

Only the file's own contents are read. Lines that refer somewhere else — another
requirements file, a local path, a URL, an editable install — name something this
cannot resolve, and are reported rather than passed over.
"""

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PackagingRequirement

from sbom_security.models import PYPI, Requirement

# Lines beginning with these are directives rather than dependencies.
DIRECTIVES = ("-", "--")


def parse_requirements_txt(content: str) -> tuple[tuple[Requirement, ...], tuple[str, ...]]:
    """Read a requirements file into requirements, and lines that are not ones.

    Returns what could be understood, and the text of what could not, so that a file
    which is partly unreadable still yields the part that is.
    """
    understood: list[Requirement] = []
    ignored: list[str] = []

    for raw in content.splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith(DIRECTIVES):
            ignored.append(line)
            continue

        parsed = _parse_line(line)
        if parsed is None:
            ignored.append(line)
        else:
            understood.append(parsed)

    return tuple(understood), tuple(ignored)


def _strip_comment(line: str) -> str:
    """Remove a trailing comment.

    A hash only begins a comment at the start of a line or after whitespace, so that a
    fragment such as ``#egg=name`` in a URL survives.
    """
    if line.lstrip().startswith("#"):
        return ""
    head, hash_mark, _ = line.partition(" #")
    return head if hash_mark else line


def _parse_line(line: str) -> Requirement | None:
    """Turn one line into a requirement, or None if it is not one."""
    try:
        parsed = PackagingRequirement(line)
    except InvalidRequirement:
        return None

    # A requirement pointing at a URL or a local directory names something the index
    # cannot answer for, whatever version specifier it carries.
    if parsed.url:
        return None

    return Requirement(
        name=parsed.name,
        range=str(parsed.specifier),
        ecosystem=PYPI,
    )
