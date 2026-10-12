"""Tests for the support-policy measurement, and the cases it measures against.

The runner lives beside the other evaluations rather than in the package, so it is
loaded here from its file.
"""

import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from sbom_security.policy import VERSIONS, Policy, Rule

EVALUATION = Path(__file__).parent.parent / "evaluation"
CASES = sorted((EVALUATION / "support-policies" / "cases").glob("*.json"))

PINNED = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/blob/[0-9a-f]{40}/\S+")
OUTCOME = re.compile(r"(?:supported|limited)(?: until \d{4}-\d{2}-\d{2})?|eol")
KINDS = {"versions", "latest_release", "latest_minor", "latest_major", "none"}


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EVALUATION / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up while being defined
    spec.loader.exec_module(module)
    return module


load("evaluate")  # what the measurement shares with the CVE runner
policies = load("policies")


def case_from(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", CASES, ids=lambda path: path.stem)
def test_each_case_is_pinned_and_complete(path: Path):
    case = case_from(path)

    assert PINNED.fullmatch(case["policy"]), "a policy is linked at a commit"
    assert case["category"] in {"happy", "unhappy", "edge"}
    assert case["reading"]["kind"] in KINDS
    date.fromisoformat(case["date"])
    assert case["expected"], "a case checks at least one version"
    assert all(value is None or OUTCOME.fullmatch(value) for value in case["expected"].values())
    assert case["notes"]


@pytest.mark.parametrize("path", CASES, ids=lambda path: path.stem)
def test_what_each_case_expects_follows_from_its_reading(path: Path):
    # The expected statuses are written by hand. Judging the reading beside them the
    # way reports judge must give exactly those, or one of the two is wrong.
    case = case_from(path)

    checks, invented = policies.score(case, Policy.from_dict(case["reading"]))

    assert [check for check in checks if not check.passed] == []
    assert invented == []


def test_reading_nothing_passes_only_the_cases_that_state_nothing():
    for path in CASES:
        case = case_from(path)

        checks, invented = policies.score(case, None)

        assert all(check.passed for check in checks) == (case["reading"]["kind"] == "none")
        assert invented == []


def test_the_cases_cover_every_category():
    assert {case_from(path)["category"] for path in CASES} == {"happy", "unhappy", "edge"}


def test_reads_the_text_of_a_file_shown_on_github():
    page = "https://github.com/isaacs/.github/blob/f3ec95b/docs/SECURITY.md"

    assert policies.text_address(page) == (
        "https://raw.githubusercontent.com/isaacs/.github/f3ec95b/docs/SECURITY.md"
    )


def test_refuses_a_link_that_is_not_a_file():
    with pytest.raises(ValueError):
        policies.text_address("https://github.com/isaacs/.github")


def test_gives_the_end_of_support_only_where_it_still_matters():
    policy = Policy(
        VERSIONS,
        (
            Rule("8.x", "supported"),
            Rule("7.x", "security_only", "2027-06-30"),
            Rule("6.x", "supported", "2020-01-01"),
        ),
    )
    today = date(2026, 10, 12)

    assert policies.outcome(policy, "8.0.7", "8.0.7", today) == "supported"
    assert policies.outcome(policy, "7.29.10", "8.0.7", today) == "limited until 2027-06-30"
    assert policies.outcome(policy, "6.26.0", "8.0.7", today) == "eol"
    assert policies.outcome(policy, "5.0.0", "8.0.7", today) is None
    assert policies.outcome(None, "8.0.7", "8.0.7", today) is None


def test_counts_support_given_where_the_policy_states_none_as_invented():
    case = {
        "package": "express-fileupload",
        "date": "2026-10-12",
        "newest": "1.5.2",
        "reading": {"kind": "versions", "rules": []},
        "expected": {"1.5.2": None, "1.3.1": "supported"},
    }
    generous = Policy(VERSIONS, (Rule(">=1.2.1", "supported"),))

    checks, invented = policies.score(case, generous)

    assert [check.passed for check in checks] == [True, False, True]
    assert invented == ["express-fileupload@1.5.2: supported"]


COMMIT = "a" * 40
CASE = {
    "package": "pug",
    "policy": f"https://github.com/pugjs/pug/blob/{COMMIT}/SECURITY.md",
    "newest": "3.0.4",
    "date": "2026-10-12",
    "reading": {
        "kind": "versions",
        "rules": [
            {"versions": "^3.0.1", "status": "supported", "until": None},
            {"versions": "<3.0.1", "status": "unsupported", "until": None},
        ],
    },
    "expected": {"3.0.4": "supported", "3.0.0": "eol"},
    "category": "happy",
    "notes": "",
}
TEXT_ADDRESS = f"https://raw.githubusercontent.com/pugjs/pug/{COMMIT}/SECURITY.md"
POLICY_TEXT = """## Supported Versions

| Version | Supported |
| ------- | --------- |
| ^3.0.1  | yes       |
| <3.0.1  | no        |
"""


class FakeReader:
    """Answers every policy with the same reading, and records what it was given."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.given: list[tuple[str, str]] = []

    async def read(self, package: str, text: str) -> Policy:
        self.given.append((package, text))
        return self.policy


def serving(texts: dict[str, str]) -> httpx.AsyncClient:
    def handle(request: httpx.Request) -> httpx.Response:
        text = texts.get(str(request.url))
        return httpx.Response(404) if text is None else httpx.Response(200, text=text)

    return httpx.AsyncClient(transport=httpx.MockTransport(handle))


async def test_reads_each_policy_at_its_pinned_commit():
    reader = FakeReader(Policy.from_dict(CASE["reading"]))

    async with serving({TEXT_ADDRESS: POLICY_TEXT}) as client:
        [result] = await policies.evaluate([("pug", CASE)], reader, client)

    assert reader.given == [("pug", POLICY_TEXT)]
    assert result.passed == len(result.checks) == 3
    assert result.error is None


async def test_a_policy_that_cannot_be_fetched_fails_every_check():
    nothing_stated = {**CASE, "reading": {"kind": "none", "rules": []}, "expected": {"3.0.4": None}}

    async with serving({}) as client:
        [result] = await policies.evaluate(
            [("pug", nothing_stated)], FakeReader(Policy("none")), client
        )

    assert result.error
    assert result.passed == 0


async def test_a_text_that_mentions_no_versions_is_not_read():
    reader = FakeReader(Policy(VERSIONS, (Rule("*", "supported"),)))
    nothing_stated = {**CASE, "reading": {"kind": "none", "rules": []}, "expected": {"3.0.4": None}}

    async with serving({TEXT_ADDRESS: "Report vulnerabilities to us by email."}) as client:
        [result] = await policies.evaluate([("pug", nothing_stated)], reader, client)

    assert reader.given == []
    assert result.passed == len(result.checks) == 2


def test_spells_out_every_miss():
    result = policies.CaseResult(
        "ethers",
        "edge",
        checks=[
            policies.compare("kind", "ethers", "versions", "versions"),
            policies.compare("versions", "ethers@6.17.0", "supported", None),
        ],
    )

    text = policies.report([result], policies.summary([result], policies.FIELDS))

    assert "ethers@6.17.0: expected supported, answered nothing" in text
    assert "1/2" in text and "50%" in text


def test_asks_for_a_key_rather_than_failing_every_case(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert policies.main([]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
