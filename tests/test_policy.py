"""Tests for finding and reading security policies, and judging versions by them.

Registries, GitHub and the model are all stood in for, so nothing here touches the
network or costs anything.
"""

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from sbom_security.cache import ExpiringCache
from sbom_security.models import EXTRACTED, END_OF_LIFE, LIMITED, SUPPORTED, PackageRef
from sbom_security.policy import (
    LATEST_MAJOR,
    LATEST_MINOR,
    LATEST_RELEASE,
    NONE,
    VERSIONS,
    ClaudeReader,
    Policy,
    PolicyAgent,
    PolicyFinder,
    PolicyUnreadable,
    Rule,
    github_repository,
    judge,
    mentions_a_policy,
)
from sbom_security.purl import to_dependency

TODAY = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)

LODASH_POLICY = """# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 4.x   | :white_check_mark:   |
| 3.x   | :x:                  |
"""

SHARED_POLICY = """## Supported Versions

Typically only the most recent version of a library is supported for fixing
security vulnerabilities.
"""

REPORTING_ONLY = """# Reporting a vulnerability

Please email security@example.org with the details.
"""

TABLE = Policy(
    kind=VERSIONS,
    rules=(Rule("4.x", "supported"), Rule("3.x", "unsupported")),
    evidence="| 4.x | :white_check_mark: |",
)
LATEST = Policy(kind=LATEST_RELEASE, evidence="only the most recent version")

# What the registries and GitHub hold in these tests.
NPM = {
    "lodash": {"version": "4.17.21", "repository": {"url": "git+https://github.com/lodash/lodash.git"}},
    "minimatch": {"version": "10.0.3", "repository": "github:isaacs/minimatch"},
    "rimraf": {"version": "6.0.1", "repository": "isaacs/rimraf"},
    "quiet": {"version": "1.0.0", "repository": "https://github.com/someone/quiet"},
    "reporting": {"version": "1.0.0", "repository": "https://github.com/someone/reporting"},
    "flaky": {"version": "1.0.0", "repository": "https://github.com/someone/flaky"},
    "elsewhere": {"version": "1.0.0", "repository": "https://gitlab.com/someone/elsewhere"},
}
FILES = {
    "lodash/lodash/HEAD/SECURITY.md": LODASH_POLICY,
    "isaacs/.github/HEAD/SECURITY.md": SHARED_POLICY,
    "someone/reporting/HEAD/.github/SECURITY.md": REPORTING_ONLY,
}


class World:
    """Answers registry and GitHub requests, and records what was asked."""

    def __init__(self):
        self.paths: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(f"{request.url.host}{request.url.path}")
        if request.url.host == "registry.test":
            name = request.url.path.split("/")[1]
            return httpx.Response(200, json=NPM[name]) if name in NPM else httpx.Response(404)
        path = request.url.path.lstrip("/")
        if path.startswith("someone/flaky/"):
            return httpx.Response(503)
        return httpx.Response(200, text=FILES[path]) if path in FILES else httpx.Response(404)

    def finder(self) -> PolicyFinder:
        return PolicyFinder(
            npm_url="https://registry.test",
            raw_url="https://raw.test",
            transport=httpx.MockTransport(self),
        )


class FakeReader:
    """Stands in for the model, answering every text with one policy."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.read_for: list[str] = []

    async def read(self, package: str, _text: str) -> Policy:
        self.read_for.append(package)
        return self.policy


def agent(tmp_path: Path, world: World, reader=None, now: datetime = TODAY) -> PolicyAgent:
    return PolicyAgent(
        cache=ExpiringCache(tmp_path),
        reader=reader,
        finder=world.finder(),
        clock=lambda: now,
    )


# --- finding the repository and the text ------------------------------------------------


@pytest.mark.parametrize(
    "written",
    [
        "git+https://github.com/lodash/lodash.git",
        "https://github.com/lodash/lodash",
        "git@github.com:lodash/lodash.git",
        "github:lodash/lodash",
        "lodash/lodash",
        "https://github.com/lodash/lodash/tree/main/packages/x",
    ],
)
def test_a_repository_is_read_however_the_registry_writes_it(written: str):
    assert github_repository(written) == ("lodash", "lodash")


def test_a_repository_elsewhere_is_not_github():
    assert github_repository("https://gitlab.com/someone/elsewhere") is None
    assert github_repository(None) is None


def test_reporting_instructions_are_not_a_policy():
    assert mentions_a_policy(LODASH_POLICY)
    assert not mentions_a_policy(REPORTING_ONLY)


async def test_reads_a_repositorys_own_policy(tmp_path: Path):
    world, reader = World(), FakeReader(TABLE)

    await agent(tmp_path, world, reader).discover([("lodash", "npm")])

    assert reader.read_for == ["lodash"]


async def test_falls_back_on_the_policy_an_organisation_shares(tmp_path: Path):
    world, reader = World(), FakeReader(LATEST)

    await agent(tmp_path, world, reader).discover([("minimatch", "npm")])

    assert reader.read_for == ["minimatch"]
    assert "raw.test/isaacs/.github/HEAD/SECURITY.md" in world.paths


async def test_a_shared_policy_is_fetched_once_for_all_who_share_it(tmp_path: Path):
    world, reader = World(), FakeReader(LATEST)

    await agent(tmp_path, world, reader).discover([("minimatch", "npm"), ("rimraf", "npm")])

    assert world.paths.count("raw.test/isaacs/.github/HEAD/SECURITY.md") == 1
    assert sorted(reader.read_for) == ["minimatch", "rimraf"]


async def test_reporting_instructions_are_never_sent_to_the_model(tmp_path: Path):
    world, reader = World(), FakeReader(TABLE)

    await agent(tmp_path, world, reader).discover([("reporting", "npm"), ("quiet", "npm")])

    assert reader.read_for == []


async def test_a_package_without_a_policy_is_not_looked_up_again(tmp_path: Path):
    world, reader = World(), FakeReader(TABLE)

    await agent(tmp_path, world, reader).discover([("quiet", "npm")])
    asked = len(world.paths)
    await agent(tmp_path, world, reader, TODAY + timedelta(days=29)).discover([("quiet", "npm")])

    assert len(world.paths) == asked


async def test_a_failed_lookup_is_not_remembered_as_absent(tmp_path: Path):
    world, reader = World(), FakeReader(TABLE)

    await agent(tmp_path, world, reader).discover([("flaky", "npm")])

    assert not any(tmp_path.glob("package%2Fnpm%2Fflaky*"))


async def test_a_repository_outside_github_has_no_policy_to_find(tmp_path: Path):
    world, reader = World(), FakeReader(TABLE)

    await agent(tmp_path, world, reader).discover([("elsewhere", "npm")])

    assert reader.read_for == []


async def test_nothing_is_looked_up_without_a_model(tmp_path: Path):
    world = World()

    await agent(tmp_path, world, reader=None).discover([("lodash", "npm")])

    assert world.paths == []


# --- reading a policy with Claude ---------------------------------------------------------


class FakeAnthropic:
    """Answers one request as the Messages API would, and records it."""

    def __init__(self, answer: dict | None = None, stop_reason: str = "end_turn"):
        self.request: dict = {}
        blocks = [SimpleNamespace(type="thinking", thinking="")]
        if answer is not None:
            blocks.append(SimpleNamespace(type="text", text=json.dumps(answer)))
        self.response = SimpleNamespace(stop_reason=stop_reason, content=blocks)
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **request):
        self.request = request
        return self.response


async def test_the_model_is_asked_for_rules_in_a_fixed_shape():
    answer = {
        "applies": True,
        "kind": "versions",
        "rules": [{"versions": "7.x", "status": "security_only", "until": "2027-06-30"}],
        "evidence": "| 7.x | until 2027-06-30 |",
    }
    client = FakeAnthropic(answer)

    policy = await ClaudeReader(client=client).read("@babel/traverse", LODASH_POLICY)

    assert policy.rules == (Rule("7.x", "security_only", "2027-06-30"),)
    assert client.request["model"] == "claude-opus-5-5"
    assert client.request["fallbacks"] == "default"
    assert client.request["output_config"]["format"]["type"] == "json_schema"
    assert "Package: @babel/traverse" in client.request["messages"][0]["content"]


async def test_a_text_that_does_not_apply_gives_no_policy():
    answer = {"applies": False, "kind": "none", "rules": [], "evidence": ""}

    policy = await ClaudeReader(client=FakeAnthropic(answer)).read("esprima", SHARED_POLICY)

    assert policy.kind == NONE


async def test_a_declined_request_is_not_taken_for_an_answer():
    with pytest.raises(PolicyUnreadable):
        await ClaudeReader(client=FakeAnthropic(stop_reason="refusal")).read("x", "text")


# --- judging a version by a policy --------------------------------------------------------

DAY = date(2026, 10, 12)


def test_a_table_gives_each_line_its_status():
    assert judge(TABLE, "4.17.21", None, DAY) == ("4.x", SUPPORTED, None, None)
    assert judge(TABLE, "3.10.1", None, DAY) == ("3.x", END_OF_LIFE, None, None)


def test_a_version_on_no_listed_line_gets_no_answer():
    assert judge(TABLE, "2.4.2", None, DAY) is None


@pytest.mark.parametrize(
    ("versions", "inside", "outside"),
    [(">=2.4.0", "2.5.1", "2.3.9"), ("^3.0.1", "3.4.0", "3.0.0"), ("<=12.x", "12.3.0", "13.0.0")],
)
def test_ranges_are_read_as_npm_reads_them(versions: str, inside: str, outside: str):
    policy = Policy(kind=VERSIONS, rules=(Rule(versions, "supported"),))

    assert judge(policy, inside, None, DAY)[1] == SUPPORTED
    assert judge(policy, outside, None, DAY) is None


def test_security_fixes_until_a_date_are_limited_support_until_then():
    policy = Policy(kind=VERSIONS, rules=(Rule("7.x", "security_only", "2027-06-30"),))

    assert judge(policy, "7.24.0", None, DAY) == ("7.x", LIMITED, "Security fixes only", "2027-06-30")
    assert judge(policy, "7.24.0", None, date(2027, 6, 30))[1] == END_OF_LIFE


def test_only_the_latest_release_is_supported_under_such_a_policy():
    assert judge(LATEST, "10.0.3", "10.0.3", DAY) == ("10.0.3", SUPPORTED, None, None)
    assert judge(LATEST, "9.0.5", "10.0.3", DAY)[1] == END_OF_LIFE


def test_a_latest_minor_or_major_policy_covers_the_whole_line():
    minor = Policy(kind=LATEST_MINOR)
    major = Policy(kind=LATEST_MAJOR)

    assert judge(minor, "0.57.1", "0.57.2", DAY) == ("0.57", SUPPORTED, None, None)
    assert judge(minor, "0.56.0", "0.57.2", DAY)[1] == END_OF_LIFE
    assert judge(major, "10.0.1", "10.4.0", DAY) == ("10", SUPPORTED, None, None)


def test_a_relative_policy_needs_the_newest_version():
    assert judge(LATEST, "10.0.3", None, DAY) is None


# --- answering from what was found ------------------------------------------------------


async def test_support_comes_from_the_policy_found(tmp_path: Path):
    world = World()
    await agent(tmp_path, world, FakeReader(TABLE)).discover([("lodash", "npm")])
    dependency = to_dependency(PackageRef("lodash", "4.17.21"))

    found = await agent(tmp_path, world).find_support([dependency])

    support = found[dependency.purl]
    assert (support.line, support.status, support.basis) == ("4.x", SUPPORTED, EXTRACTED)
    assert support.source == "https://github.com/lodash/lodash/blob/HEAD/SECURITY.md"
    assert support.retrieved_at == "2026-10-12T12:00:00+00:00"


async def test_a_relative_policy_is_judged_against_the_newest_release(tmp_path: Path):
    world = World()
    await agent(tmp_path, world, FakeReader(LATEST)).discover([("minimatch", "npm")])
    old = to_dependency(PackageRef("minimatch", "9.0.5"))
    newest = to_dependency(PackageRef("minimatch", "10.0.3"))

    found = await agent(tmp_path, world).find_support([old, newest])

    assert found[old.purl].status == END_OF_LIFE
    assert found[newest.purl].status == SUPPORTED


async def test_a_package_never_looked_up_gets_no_answer(tmp_path: Path):
    dependency = to_dependency(PackageRef("lodash", "4.17.21"))

    assert await agent(tmp_path, World()).find_support([dependency]) == {}


async def test_a_published_lifecycle_outranks_a_projects_own_policy(tmp_path: Path, support_source):
    from sbom_security.support import SupportSources  # pylint: disable=import-outside-toplevel

    NPM["express"] = {"version": "4.21.2", "repository": "github:expressjs/express"}
    FILES["expressjs/express/HEAD/SECURITY.md"] = LODASH_POLICY
    world = World()
    extracted = agent(tmp_path / "policies", world, FakeReader(TABLE))
    await extracted.discover([("express", "npm")])
    express = to_dependency(PackageRef("express", "4.18.0"))

    found = await SupportSources(published=support_source, extracted=extracted).find_support([express])

    assert found[express.purl].basis == "published"


class Recorder:
    """Records what a report hands on for looking up later."""

    def __init__(self, fail: bool = False):
        self.handed: list[list[list[str]]] = []
        self.fail = fail

    async def __call__(self, packages):
        self.handed.append(packages)
        if self.fail:
            raise ConnectionError("no queue")


async def test_what_a_report_cannot_answer_is_handed_on_to_be_looked_up(tmp_path: Path, support_source):
    from sbom_security.support import SupportSources  # pylint: disable=import-outside-toplevel

    pending = Recorder()
    sources = SupportSources(
        published=support_source, extracted=agent(tmp_path / "policies", World()), pending=pending
    )
    express = to_dependency(PackageRef("express", "4.18.0"))
    lodash = to_dependency(PackageRef("lodash", "4.17.21"))

    await sources.find_support([express, lodash])

    # express has a published lifecycle; only lodash is left to look up.
    assert pending.handed == [[["lodash", "npm"]]]


async def test_a_package_looked_up_lately_is_not_handed_on_again(tmp_path: Path, support_source):
    from sbom_security.support import SupportSources  # pylint: disable=import-outside-toplevel

    world = World()
    extracted = agent(tmp_path / "policies", world, FakeReader(TABLE))
    await extracted.discover([("quiet", "npm")])
    pending = Recorder()
    sources = SupportSources(published=support_source, extracted=extracted, pending=pending)

    await sources.find_support([to_dependency(PackageRef("quiet", "1.0.0"))])

    assert pending.handed == []


async def test_a_report_does_not_fail_when_nothing_can_take_the_lookup(tmp_path: Path, support_source):
    from sbom_security.support import SupportSources  # pylint: disable=import-outside-toplevel

    sources = SupportSources(
        published=support_source,
        extracted=agent(tmp_path / "policies", World()),
        pending=Recorder(fail=True),
    )

    found = await sources.find_support([to_dependency(PackageRef("lodash", "4.17.21"))])

    assert found == {}
