"""Find the support policy a project states in its SECURITY.md, and have Claude read it.

endoflife.date covers a few dozen npm and PyPI projects. Many more say which of their
versions receive security fixes in a SECURITY.md, usually under the Supported Versions
heading GitHub's template suggests, either in the repository itself or in one their
organisation shares across all its repositories.

Finding that text is ordinary work: the registry names the repository, and the file is
fetched from GitHub. Reading it is not. Projects write it as a table of release lines,
as version ranges, as a rule such as "only the latest release", or about other
products altogether, so a model turns it into rules. It does nothing else: whether a
given version is supported is worked out from those rules when a report is produced,
the same way endoflife.date's dates are.

The model is slow and costs money, so it never runs while a report is being produced.
A report reads what earlier lookups found, and a lookup for what is still missing runs
afterwards as submitted work.
"""

import asyncio
import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import quote

import anthropic
import httpx
from nodesemver import satisfies

from sbom_security.cache import ExpiringCache, Stored
from sbom_security.models import (
    END_OF_LIFE,
    EXTRACTED,
    LIMITED,
    NPM,
    PYPI,
    SUPPORTED,
    Dependency,
    Support,
)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_INDEX = "https://pypi.org"
RAW_GITHUB = "https://raw.githubusercontent.com"
GITHUB = "https://github.com"

# Where GitHub looks for a security policy, in the order it looks. An organisation's
# shared policy lives in the same places in its repository named ".github".
POLICY_FILES = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
SHARED_REPOSITORY = ".github"

# A text mentioning neither support nor versions is instructions for reporting a
# vulnerability, not a policy, and is not worth a model's time. Of 230 SECURITY.md
# files among Juice Shop's dependencies this leaves 71, and keeps all 53 that have a
# Supported Versions section.
_MENTIONS_SUPPORT = re.compile(r"support|maintain|end[- ]of[- ]life|\beol\b", re.I)
_MENTIONS_VERSIONS = re.compile(r"version|release", re.I)

# No security policy seen so far comes near this; a text that does is not sent.
MAX_TEXT = 40_000

MAX_CONCURRENT_LOOKUPS = 5

DEFAULT_MODEL = "claude-opus-5-5"

# Kinds of policy a text can state.
VERSIONS = "versions"
LATEST_RELEASE = "latest_release"
LATEST_MINOR = "latest_minor"
LATEST_MAJOR = "latest_major"
NONE = "none"

# Statuses a rule can give a release line.
RULE_SUPPORTED = "supported"
RULE_SECURITY_ONLY = "security_only"
RULE_UNSUPPORTED = "unsupported"

_LEADING_NUMBERS = re.compile(r"\d+(?:\.\d+)*")
_GITHUB_REPOSITORY = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Rule:
    """Which versions a policy covers, and what it gives them.

    ``versions`` is an npm semver range, such as ``4.x`` or ``>=2.4.0``. ``until`` is
    the date that support ends, where the policy gives one.
    """

    versions: str
    status: str
    until: str | None = None


@dataclass(frozen=True)
class Policy:
    """What a security policy says about one package, as rules rather than prose.

    ``kind`` is ``versions`` for explicit rules, one of the ``latest_`` kinds for a
    policy that supports only the newest release, minor line or major line, and
    ``none`` for a text that says nothing about the package. ``evidence`` quotes what
    the answer rests on, so that it can be checked against the text.
    """

    kind: str
    rules: tuple[Rule, ...] = ()
    evidence: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        return cls(
            kind=data["kind"],
            rules=tuple(Rule(**rule) for rule in data.get("rules") or ()),
            evidence=data.get("evidence", ""),
        )


class PolicyUnreadable(Exception):
    """The model gave no usable reading of a policy."""


INSTRUCTIONS = """You read a project's security policy and report which versions of one \
named package receive security fixes. Report only what the text states; never infer, and \
never fill gaps from what you know about the project.

- applies: false if the text does not state supported versions for this package, for \
example when it only explains how to report a vulnerability, or when it is about other \
products.
- kind: "versions" for explicit versions or ranges; "latest_release", "latest_minor" or \
"latest_major" when only the newest release, the newest minor line or the newest major \
line is supported; "none" when applies is false.
- rules: for kind "versions" only. Write versions as an npm semver range: "4.x" for a \
4.x line, keep ranges such as ">=2.4.0", "^3.0.1" or "<4.7" as written. status \
"security_only" when the text limits a line to security fixes or a sunset period. until: \
a date in YYYY-MM-DD only if the text gives one for that line, else null.
- GitHub's unedited template lists 5.1.x, 5.0.x, 4.0.x and < 4.0 as examples. Those \
example values are not a policy: answer applies false. A template sentence kept above \
real, project-specific versions does not make them examples.
- evidence: the sentence or table rows your answer rests on, quoted exactly; empty if \
applies is false."""

SCHEMA = {
    "type": "object",
    "properties": {
        "applies": {"type": "boolean"},
        "kind": {
            "type": "string",
            "enum": [VERSIONS, LATEST_RELEASE, LATEST_MINOR, LATEST_MAJOR, NONE],
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "versions": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": [RULE_SUPPORTED, RULE_SECURITY_ONLY, RULE_UNSUPPORTED],
                    },
                    "until": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                },
                "required": ["versions", "status", "until"],
                "additionalProperties": False,
            },
        },
        "evidence": {"type": "string"},
    },
    "required": ["applies", "kind", "rules", "evidence"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class ClaudeReader:
    """Reads a security policy with Claude and returns its rules.

    ``client`` is an ``anthropic.AsyncAnthropic``; tests pass a fake. If none is given,
    one is made on first use from ANTHROPIC_API_KEY.

    A declined request is re-run on another model by the API itself, so a false alarm
    from a safety classifier does not cost the answer.
    """

    model: str = DEFAULT_MODEL
    client: Any = None

    async def read(self, package: str, text: str) -> Policy:
        client = self.client or anthropic.AsyncAnthropic()
        response = await client.beta.messages.create(
            model=self.model,
            max_tokens=4000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=INSTRUCTIONS,
            messages=[
                {"role": "user", "content": f"Package: {package}\n\nSecurity policy:\n\n{text}"}
            ],
            output_config={"format": {"type": "json_schema", "schema": SCHEMA}, "effort": "low"},
        )
        if response.stop_reason != "end_turn":
            raise PolicyUnreadable(f"the model stopped with {response.stop_reason}")
        answer = next((block.text for block in response.content if block.type == "text"), "")
        try:
            data = json.loads(answer)
        except ValueError as unreadable:
            raise PolicyUnreadable("the model's answer was not JSON") from unreadable
        if not data.get("applies") or data.get("kind") == NONE:
            return Policy(kind=NONE)
        return Policy.from_dict(data)


def reader_from_environment() -> ClaudeReader | None:
    """Return a reader if an API key is configured, or None to look nothing up.

    Without a key the rest of the service works as before; support policies are only
    read from what has already been found.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    return ClaudeReader(model=os.environ.get("SBOM_POLICY_MODEL", DEFAULT_MODEL))


@dataclass(frozen=True)
class PolicyText:
    """A security policy as found, and the page a person can read it on."""

    text: str
    source: str


@dataclass(frozen=True)
class PolicyFinder:
    """Finds a package's repository and its security policy, from public sources.

    Each base URL and ``transport`` exist so tests can answer without network access.
    A file that does not exist is an answer; any other failure is raised, so that it is
    tried again later rather than remembered as absent.
    """

    npm_url: str = NPM_REGISTRY
    pypi_url: str = PYPI_INDEX
    raw_url: str = RAW_GITHUB
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport, follow_redirects=True
        )

    async def repository(
        self, client: httpx.AsyncClient, name: str, ecosystem: str
    ) -> tuple[str, str] | None:
        """Return the GitHub repository a package names as its source, if any."""
        if ecosystem == NPM:
            response = await client.get(f"{self.npm_url}/{quote(name, safe='@')}/latest")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            declared = response.json().get("repository")
            url = declared.get("url") if isinstance(declared, dict) else declared
            return github_repository(url)

        response = await client.get(f"{self.pypi_url}/pypi/{quote(name, safe='')}/json")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        info = response.json().get("info") or {}
        for url in [*(info.get("project_urls") or {}).values(), info.get("home_page")]:
            found = github_repository(url)
            if found:
                return found
        return None

    async def policy_file(
        self, client: httpx.AsyncClient, owner: str, repo: str
    ) -> PolicyText | None:
        """Return the security policy a repository holds itself, if it holds one."""
        for path in POLICY_FILES:
            response = await client.get(f"{self.raw_url}/{owner}/{repo}/HEAD/{path}")
            if response.status_code == 404:
                continue
            response.raise_for_status()
            return PolicyText(response.text, f"{GITHUB}/{owner}/{repo}/blob/HEAD/{path}")
        return None

    async def latest_version(
        self, client: httpx.AsyncClient, name: str, ecosystem: str
    ) -> str | None:
        """Return the newest published version of a package."""
        if ecosystem == NPM:
            response = await client.get(f"{self.npm_url}/{quote(name, safe='@')}/latest")
            response.raise_for_status()
            return response.json().get("version")
        response = await client.get(f"{self.pypi_url}/pypi/{quote(name, safe='')}/json")
        response.raise_for_status()
        return (response.json().get("info") or {}).get("version")


def github_repository(url: Any) -> tuple[str, str] | None:
    """Read a GitHub repository out of the many ways a registry writes one.

    ``git+https://github.com/lodash/lodash.git``, ``github:isaacs/rimraf`` and the
    shorthand ``isaacs/rimraf`` all name a repository; anything not on GitHub does not.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip().removeprefix("github:")
    if re.fullmatch(r"[\w.-]+/[\w.-]+", url):
        owner, _, repo = url.partition("/")
        return owner, repo.removesuffix(".git")
    match = _GITHUB_REPOSITORY.search(url)
    return (match.group(1), match.group(2)) if match else None


def mentions_a_policy(text: str) -> bool:
    """Say whether a text could state supported versions at all."""
    return bool(_MENTIONS_SUPPORT.search(text) and _MENTIONS_VERSIONS.search(text))


@dataclass(frozen=True)
class PolicyAgent:
    """Finds and reads support policies, and answers from what it has found.

    ``discover`` does the slow part, a model included, and belongs in submitted work.
    ``find_support`` only reads what was found, and is safe to call from a report.
    ``reader`` is None when no model is configured, which leaves ``discover`` with
    nothing to do.
    """

    cache: ExpiringCache
    reader: ClaudeReader | None = None
    finder: PolicyFinder = field(default_factory=PolicyFinder)
    clock: Callable[[], datetime] = utc_now

    async def find_support(self, dependencies: Sequence[Dependency]) -> dict[str, Support]:
        """Return the support status each dependency's own policy gives it.

        A policy is used even after its lifetime, since its retrieval time is reported
        with it; a newer copy replaces it when the next lookup runs.
        """
        today = self.clock().date()
        found: dict[str, Support] = {}
        policies: list[tuple[Dependency, Policy, Stored]] = []
        for dependency in dependencies:
            if dependency.ecosystem not in (NPM, PYPI):
                continue
            stored = self.cache.get(_package_key(dependency.name, dependency.ecosystem))
            if stored is None or not stored.document.get("policy"):
                continue
            policy = Policy.from_dict(stored.document["policy"])
            if policy.kind != NONE:
                policies.append((dependency, policy, stored))

        newest = await self._newest_versions(
            {(d.name, d.ecosystem) for d, policy, _ in policies if policy.kind != VERSIONS}
        )
        for dependency, policy, stored in policies:
            judged = judge(policy, dependency.version, newest.get(
                (dependency.name, dependency.ecosystem)), today)
            if judged is None:
                continue
            line, status, phase, until = judged
            found[dependency.purl] = Support(
                line=line,
                status=status,
                phase=phase,
                active_support_until=None,
                support_until=until,
                basis=EXTRACTED,
                source=stored.document["source"],
                retrieved_at=stored.retrieved_at.isoformat(timespec="seconds"),
            )
        return found

    def unexamined(self, dependencies: Sequence[Dependency]) -> list[list[str]]:
        """Return the packages among these whose policy has not been looked up lately.

        They come back as name and ecosystem pairs, each once, ready to be handed to
        ``discover`` as submitted work.
        """
        now = self.clock()
        unexamined: dict[tuple[str, str], None] = {}
        for dependency in dependencies:
            if dependency.ecosystem not in (NPM, PYPI):
                continue
            stored = self.cache.get(_package_key(dependency.name, dependency.ecosystem))
            if stored is None or not self.cache.is_fresh(stored, now):
                unexamined[(dependency.name, dependency.ecosystem)] = None
        return [list(package) for package in unexamined]

    async def discover(self, packages: Sequence[Sequence[str]]) -> None:
        """Find and read the policies of packages not looked up recently.

        ``packages`` are pairs of name and ecosystem. A package whose lookup fails is
        left unrecorded, so that it is tried again by the next lookup.
        """
        if self.reader is None:
            return
        now = self.clock()
        limit = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
        async with self.finder.client() as client:

            async def one(name: str, ecosystem: str) -> None:
                async with limit:
                    try:
                        await self._discover_one(client, name, ecosystem, now)
                    except (httpx.HTTPError, anthropic.APIError, PolicyUnreadable, ValueError):
                        # One package failing to be read must not stop the others.
                        return

            pairs = {(name, ecosystem) for name, ecosystem in packages if ecosystem in (NPM, PYPI)}
            await asyncio.gather(*(one(name, ecosystem) for name, ecosystem in sorted(pairs)))

    async def _discover_one(
        self, client: httpx.AsyncClient, name: str, ecosystem: str, now: datetime
    ) -> None:
        key = _package_key(name, ecosystem)
        stored = self.cache.get(key)
        if stored is not None and self.cache.is_fresh(stored, now):
            return

        repository = await self.finder.repository(client, name, ecosystem)
        found = await self._policy_text(client, repository, now) if repository else None
        if found is None or len(found.text) > MAX_TEXT or not mentions_a_policy(found.text):
            self.cache.put(key, Stored({"policy": None, "source": None}, now))
            return

        assert self.reader is not None
        policy = await self.reader.read(name, found.text)
        self.cache.put(key, Stored({"policy": asdict(policy), "source": found.source}, now))

    async def _policy_text(
        self, client: httpx.AsyncClient, repository: tuple[str, str], now: datetime
    ) -> PolicyText | None:
        """Return a repository's own policy, or else the one its organisation shares."""
        owner, repo = repository
        return await self._file(client, owner, repo, now) or await self._file(
            client, owner, SHARED_REPOSITORY, now
        )

    async def _file(
        self, client: httpx.AsyncClient, owner: str, repo: str, now: datetime
    ) -> PolicyText | None:
        """Return a repository's policy file, fetching it once per cache lifetime.

        Packages from one repository, and repositories of one organisation, share the
        lookup, so a shared policy is fetched once however many packages use it.
        """
        key = f"repository/{owner}/{repo}".lower()
        stored = self.cache.get(key)
        if stored is None or not self.cache.is_fresh(stored, now):
            found = await self.finder.policy_file(client, owner, repo)
            document = asdict(found) if found else {"text": None, "source": None}
            stored = Stored(document, now)
            self.cache.put(key, stored)
        if not stored.document.get("text"):
            return None
        return PolicyText(stored.document["text"], stored.document["source"])

    async def _newest_versions(self, packages: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
        """Return the newest version of each package whose policy is relative to it."""
        if not packages:
            return {}
        newest: dict[tuple[str, str], str] = {}
        async with self.finder.client() as client:

            async def one(name: str, ecosystem: str) -> None:
                try:
                    version = await self.finder.latest_version(client, name, ecosystem)
                except (httpx.HTTPError, ValueError):
                    return
                if version:
                    newest[(name, ecosystem)] = version

            await asyncio.gather(*(one(name, ecosystem) for name, ecosystem in packages))
        return newest


def _package_key(name: str, ecosystem: str) -> str:
    if ecosystem == PYPI:
        name = re.sub(r"[-_.]+", "-", name).lower()
    return f"package/{ecosystem}/{name}"


def judge(
    policy: Policy, version: str, newest: str | None, today: date
) -> tuple[str, str, str | None, str | None] | None:
    """Work out what a policy gives one version: its line, status, phase and end date.

    Returns None when the policy says nothing about the version, such as a release
    older than any line a table lists, or a relative policy whose newest version could
    not be found.
    """
    if policy.kind == VERSIONS:
        for rule in policy.rules:
            if _covers(rule.versions, version):
                return rule.versions, *_status(rule, today), rule.until
        return None

    if newest is None:
        return None
    if policy.kind == LATEST_RELEASE:
        return version, SUPPORTED if version == newest else END_OF_LIFE, None, None

    # The newest minor line is its first two numbers; the newest major line, its first.
    depth = {LATEST_MINOR: 2, LATEST_MAJOR: 1}.get(policy.kind)
    if depth is None:
        return None
    own = _numbers(version)[:depth]
    status = SUPPORTED if own == _numbers(newest)[:depth] else END_OF_LIFE
    return ".".join(str(number) for number in own), status, None, None


def _covers(versions: str, version: str) -> bool:
    try:
        return bool(satisfies(version, versions, loose=True))
    except Exception:  # pylint: disable=broad-exception-caught
        # A range the matcher cannot parse covers nothing it can vouch for.
        return False


def _status(rule: Rule, today: date) -> tuple[str, str | None]:
    """Turn a rule into a status, counting an end date that has already passed."""
    if rule.status == RULE_UNSUPPORTED or _has_passed(rule.until, today):
        return END_OF_LIFE, None
    if rule.status == RULE_SECURITY_ONLY:
        return LIMITED, "Security fixes only"
    return SUPPORTED, None


def _has_passed(until: str | None, today: date) -> bool:
    if not until:
        return False
    try:
        return date.fromisoformat(until) <= today
    except ValueError:
        return False


def _numbers(version: str) -> tuple[int, ...]:
    match = _LEADING_NUMBERS.match(version)
    return tuple(int(part) for part in match.group().split(".")) if match else ()
