#!/usr/bin/env python3
"""Measure how security policies are read, against policies with known answers.

Each case is a package, its security policy pinned to the commit it was checked at,
and what a report should say about some of the package's versions. The policy is read
the way the service reads it, and each version judged the way a report judges it, so
what is measured is what reports would carry rather than how the model writes its
rules: ">=5" and ">=5.0.0" are the same answer.

    ANTHROPIC_API_KEY=... python3 evaluation/policies.py
    ANTHROPIC_API_KEY=... python3 evaluation/policies.py --model claude-sonnet-5-5

A status given to a version the policy says nothing about is also counted apart as
invented, because a report would then claim support nobody promised.
"""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import anthropic
import httpx
from evaluate import CaseResult, Check, add_result_options, conclude, summary, totals_report

from sbom_security.models import END_OF_LIFE
from sbom_security.policy import (
    DEFAULT_MODEL,
    GITHUB,
    NONE,
    RAW_GITHUB,
    ClaudeReader,
    Policy,
    PolicyUnreadable,
    judge,
    read_policy,
)

DATASET = Path(__file__).parent / "support-policies"

# The fields compared, in the order a summary lists them.
FIELDS = ("kind", "versions")

# What a case that could not be read is recorded as having answered.
NO_ANSWER = "no answer"

Case = dict[str, Any]


@dataclass(frozen=True)
class Comparison(Check):
    """A check that keeps what was expected and what was answered, to show a miss."""

    expected: str | None = None
    answered: str | None = None


def compare(field: str, subject: str, expected: str | None, answered: str | None) -> Comparison:
    return Comparison(field, subject, expected == answered, expected, answered)


def text_address(page: str) -> str:
    """Return where the text of a file shown on GitHub is served from.

    Cases link the page, which is what a person checking them opens. The commit is in
    both, so the text never changes under a case.
    """
    parts = page.removeprefix(f"{GITHUB}/").split("/")
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError(f"not a file on GitHub: {page}")
    owner, repository, _, commit, *path = parts
    return f"{RAW_GITHUB}/{owner}/{repository}/{commit}/{'/'.join(path)}"


def outcome(policy: Policy | None, version: str, newest: str, today: date) -> str | None:
    """Say what a report gives a version, written the way cases write it.

    That is the status, followed by the date support ends where one is given, as in
    ``limited until 2027-06-30``. A line already past its end has no date that matters.
    None is a report with no support status.
    """
    judged = judge(policy, version, newest, today) if policy else None
    if judged is None:
        return None
    _, status, _, until = judged
    return f"{status} until {until}" if until and status != END_OF_LIFE else status


def score(case: Case, policy: Policy | None) -> tuple[list[Comparison], list[str]]:
    """Compare what a reading gives with what the case expects.

    The kind of policy is checked once, then each version the case lists. A version
    given a status where the case expects none is also returned as invented.
    """
    package = case["package"]
    today = date.fromisoformat(case["date"])
    answered_kind = policy.kind if policy else NONE
    checks = [compare("kind", package, case["reading"]["kind"], answered_kind)]
    invented = []
    for version, expected in case["expected"].items():
        answered = outcome(policy, version, case["newest"], today)
        checks.append(compare("versions", f"{package}@{version}", expected, answered))
        if expected is None and answered is not None:
            invented.append(f"{package}@{version}: {answered}")
    return checks, invented


def load(dataset: Path) -> list[tuple[str, Case]]:
    """Return the cases in a dataset, by name."""
    return [
        (path.stem, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted((dataset / "cases").glob("*.json"))
    ]


async def evaluate(
    cases: Iterable[tuple[str, Case]], reader: ClaudeReader, client: httpx.AsyncClient
) -> list[CaseResult]:
    """Have every case's policy read, and score each reading."""

    async def one(name: str, case: Case) -> CaseResult:
        result = CaseResult(case=name, category=case["category"])
        try:
            response = await client.get(text_address(case["policy"]))
            response.raise_for_status()
            policy = await read_policy(reader, case["package"], response.text)
        except (httpx.HTTPError, anthropic.APIError, PolicyUnreadable) as failure:
            # Every check fails, including those that reading nothing would pass by
            # accident, so that failing never scores better than reading wrongly.
            checks, _ = score(case, None)
            result.checks = [
                compare(check.field, check.subject, check.expected, NO_ANSWER) for check in checks
            ]
            result.error = str(failure) or type(failure).__name__
        else:
            result.checks, result.invented = score(case, policy)
        return result

    return list(await asyncio.gather(*(one(name, case) for name, case in cases)))


def report(results: list[CaseResult], totals: dict[str, Any]) -> str:
    """Lay the results out for reading in a terminal, with every miss spelled out."""
    lines = []
    for result in results:
        status = f"{result.passed}/{len(result.checks)}"
        if result.error:
            detail = f"no answer: {result.error}"
        else:
            detail = "all correct" if result.passed == len(result.checks) else ""
        lines.append(f"{result.case:20} {result.category:8} {status:>5}  {detail}".rstrip())
        if not result.error:
            lines.extend(
                f"{'':37}{check.subject}: expected {_said(check.expected)}, "
                f"answered {_said(check.answered)}"
                for check in result.checks
                if not check.passed
            )
    return "\n".join(lines + totals_report(totals))


def _said(value: str | None) -> str:
    return "nothing" if value is None else value


async def _measure(dataset: Path, model: str) -> list[CaseResult]:
    reader = ClaudeReader(model=model, client=anthropic.AsyncAnthropic())
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        return await evaluate(load(dataset), reader, client)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--model", default=DEFAULT_MODEL, help="the model to read policies with")
    parser.add_argument("--dataset", type=Path, default=DATASET, help="the dataset to use")
    add_result_options(parser)
    options = parser.parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Reading policies needs ANTHROPIC_API_KEY.", file=sys.stderr)
        return 2

    results = asyncio.run(_measure(options.dataset, options.model))
    totals = summary(results, FIELDS)
    print(f"{options.model}\n")
    print(report(results, totals))
    return conclude(options, results, totals, model=options.model)


if __name__ == "__main__":
    sys.exit(main())
