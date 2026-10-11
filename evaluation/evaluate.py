#!/usr/bin/env python3
"""Measure a CVE extraction tool against the cases in a dataset.

A tool under test reads one CVE record and answers with the structured data it found
in it. It is reached either as a command, given the record on standard input and
expected to write its answer to standard output, or as a URL the record is posted to.
Either way it can be written in anything, which is why this file needs nothing beyond
Python's standard library.

    python3 evaluate.py --command "python3 fields_only.py"
    python3 evaluate.py --url http://localhost:8000/extract

Every answer is compared with the expected one field by field. Anything the tool states
that the record does not, such as a product the record never names, is also counted
apart as invented, because a wrong answer does more harm than a missing one.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

DATASET = Path(__file__).parent / "cve-extraction"
TIMEOUT = 60.0

# The fields compared, in the order a summary lists them.
FIELDS = ("status", "replaced_by", "affected", "purl", "versions", "cwe")

Answer = dict[str, Any]
Tool = Callable[[bytes], Answer]


class ToolFailed(Exception):
    """The tool under test gave no usable answer."""


@dataclass(frozen=True)
class Check:
    """One comparison: which field, about what, and whether the answer got it right."""

    field: str
    subject: str
    passed: bool


@dataclass
class CaseResult:
    """How a tool did on one case."""

    case: str
    category: str
    checks: list[Check] = field(default_factory=list)
    invented: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def passed(self) -> int:
        return sum(check.passed for check in self.checks)


def score(expected: Answer, answer: Answer) -> tuple[list[Check], list[str]]:
    """Compare an answer with the expected one, returning the checks and what was invented.

    Each expected product has to be found, by Package URL where it has one and by name
    otherwise; then its Package URL and its affected versions, ranges and individual
    versions together, are compared exactly. A product that is not found fails all three
    checks, so that answering nothing never scores better than answering wrongly. A
    replacement is checked only for a record that names one.
    """
    checks = [Check("status", "record", answer.get("status") == expected["status"])]
    invented: list[str] = []

    if expected.get("replaced_by"):
        checks.append(
            Check("replaced_by", "record", answer.get("replaced_by") == expected["replaced_by"])
        )
    elif answer.get("replaced_by"):
        invented.append(f"a replacement, {answer['replaced_by']}, for a record that names none")

    remaining = [item for item in answer.get("affected") or [] if isinstance(item, dict)]
    for wanted in expected["affected"]:
        subject = wanted["purl"] or wanted["product"]
        found = _take_match(wanted, remaining)
        if found is None:
            checks.extend(Check(name, subject, False) for name in ("affected", "purl", "versions"))
            continue
        checks.append(Check("affected", subject, True))
        checks.append(Check("purl", subject, _purl(found.get("purl")) == _purl(wanted["purl"])))
        if wanted["purl"] is None and found.get("purl"):
            invented.append(
                f"a Package URL, {found['purl']}, for {wanted['product']}, which has none"
            )
        checks.append(Check("versions", subject, _versions(found) == _versions(wanted)))
    for extra in remaining:
        named = extra.get("purl") or extra.get("product")
        invented.append(f"a product the expected answer does not list: {named}")

    expected_cwe = _weaknesses(expected["cwe"])
    answered_cwe = _weaknesses(answer.get("cwe"))
    checks.append(Check("cwe", "record", answered_cwe == expected_cwe))
    invented.extend(
        f"a weakness the record does not give: {cwe}" for cwe in sorted(answered_cwe - expected_cwe)
    )
    return checks, invented


def _take_match(wanted: Answer, candidates: list[Answer]) -> Answer | None:
    """Remove and return the answered product matching an expected one, if there is one.

    A product matches by Package URL, or by a name containing the expected one as a
    whole word: "debug node module" is debug. Only in that direction, or "babel" would
    match @babel/traverse.
    """
    for candidate in candidates:
        same_package = wanted["purl"] and _purl(candidate.get("purl")) == _purl(wanted["purl"])
        if same_package or _names_it(candidate.get("product"), wanted["product"]):
            candidates.remove(candidate)
            return candidate
    return None


def _names_it(answered: Any, expected: str) -> bool:
    """Say whether an answered name contains the expected one as a whole word."""
    pattern = rf"(?<![\w@/.-]){re.escape(_name(expected))}(?![\w@/.-])"
    return re.search(pattern, _name(answered)) is not None


def _purl(text: Any) -> str | None:
    """Reduce a Package URL to the package it names, however it is spelled.

    ``pkg:npm/@babel/traverse`` and ``pkg:npm/%40babel/traverse@7.0.0`` name the same
    package, so the version, qualifiers and percent-encoding are set aside.
    """
    if not text:
        return None
    base = str(text).split("#", 1)[0].split("?", 1)[0]
    head, slash, last = base.rpartition("/")
    return unquote(f"{head}{slash}{last.split('@', 1)[0]}").lower()


def _name(text: Any) -> str:
    return str(text or "").strip().casefold()


def _versions(entry: Answer) -> tuple[frozenset, frozenset]:
    """Return which versions an entry says are affected, in a form that compares.

    Ranges and individual versions are one statement written two ways, so they are
    compared together, and neither depends on order.
    """
    ranges = frozenset(
        (
            str(item.get("introduced") or "0"),
            item.get("fixed") and str(item["fixed"]),
            item.get("last_affected") and str(item["last_affected"]),
        )
        for item in entry.get("ranges") or []
        if isinstance(item, dict)
    )
    return ranges, frozenset(str(version) for version in entry.get("versions") or [])


def _weaknesses(values: Any) -> set[str]:
    return {str(value).strip().upper() for value in values or []}


def command_tool(command: str, timeout: float = TIMEOUT) -> Tool:
    """Reach a tool as a command, given the record on standard input."""
    arguments = shlex.split(command)

    def run(document: bytes) -> Answer:
        try:
            completed = subprocess.run(
                arguments, input=document, capture_output=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as failure:
            raise ToolFailed(str(failure)) from failure
        if completed.returncode != 0:
            lines = completed.stderr.decode(errors="replace").strip().splitlines()
            raise ToolFailed(lines[-1] if lines else f"exited with {completed.returncode}")
        return _parsed(completed.stdout)

    return run


def url_tool(url: str, timeout: float = TIMEOUT) -> Tool:
    """Reach a tool over HTTP, posting the record as JSON."""

    def run(document: bytes) -> Answer:
        request = urllib.request.Request(
            url, data=document, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
        except (urllib.error.URLError, OSError) as failure:
            raise ToolFailed(str(failure)) from failure
        return _parsed(body)

    return run


def _parsed(raw: bytes) -> Answer:
    try:
        answer = json.loads(raw)
    except ValueError as failure:
        raise ToolFailed("the answer is not JSON") from failure
    if not isinstance(answer, dict):
        raise ToolFailed("the answer is not a JSON object")
    return answer


def evaluate(dataset: Path, tool: Tool) -> list[CaseResult]:
    """Put every case in a dataset to the tool, and score each answer."""
    results = []
    for case in sorted(path for path in (dataset / "cases").iterdir() if path.is_dir()):
        expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
        result = CaseResult(case=case.name, category=expected["category"])
        try:
            answer = tool((case / "document.json").read_bytes())
        except ToolFailed as failure:
            # Every check the case holds counts as failed, including those an empty
            # answer would pass by accident, such as a record that gives no weakness.
            checks, _ = score(expected, {})
            result.checks = [Check(check.field, check.subject, False) for check in checks]
            result.error = str(failure)
        else:
            result.checks, result.invented = score(expected, answer)
        results.append(result)
    return results


def summary(results: Iterable[CaseResult]) -> dict[str, Any]:
    """Total the results: overall, per field and per category."""
    results = list(results)
    checks = [check for result in results for check in result.checks]

    def share(selected: list[Check]) -> dict[str, Any]:
        passed = sum(check.passed for check in selected)
        rate = passed / len(selected) if selected else None
        return {"passed": passed, "total": len(selected), "score": rate}

    return {
        "overall": share(checks),
        "fields": {name: share([c for c in checks if c.field == name]) for name in FIELDS},
        "categories": {
            category: share([c for r in results if r.category == category for c in r.checks])
            for category in sorted({result.category for result in results})
        },
        "invented": sum(len(result.invented) for result in results),
        "failed_to_answer": sum(result.error is not None for result in results),
    }


def report(results: list[CaseResult], totals: dict[str, Any]) -> str:
    """Lay the results out for reading in a terminal."""
    lines = []
    for result in results:
        failed = sorted({check.field for check in result.checks if not check.passed})
        status = f"{result.passed}/{len(result.checks)}"
        if result.error:
            detail = f"no answer: {result.error}"
        else:
            detail = ", ".join(failed) or "all correct"
        invented = f"  invented {len(result.invented)}" if result.invented else ""
        lines.append(f"{result.case:16} {result.category:8} {status:>6}  {detail}{invented}")
        lines.extend(f"{'':26}invented {item}" for item in result.invented)

    def line(label: str, share: dict[str, Any]) -> str:
        if not share["total"]:
            return f"  {label:12} -"
        return f"  {label:12} {share['passed']:>3}/{share['total']:<3} {share['score']:.0%}"

    lines.append("")
    lines.append("By field")
    lines.extend(line(name, share) for name, share in totals["fields"].items())
    lines.append("By category")
    lines.extend(line(name, share) for name, share in totals["categories"].items())
    lines.append("")
    lines.append(line("Overall", totals["overall"]).strip())
    lines.append(f"Invented: {totals['invented']}   No answer: {totals['failed_to_answer']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    tool = parser.add_mutually_exclusive_group(required=True)
    tool.add_argument("--command", help="run this, giving it the record on standard input")
    tool.add_argument("--url", help="post the record to this URL")
    parser.add_argument("--dataset", type=Path, default=DATASET, help="the dataset to use")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="seconds per case")
    parser.add_argument("--report", type=Path, help="also write the full results here, as JSON")
    parser.add_argument(
        "--min-score", type=float, help="exit with 1 if the overall score is below this, 0 to 1"
    )
    options = parser.parse_args(argv)

    run = (
        command_tool(options.command, options.timeout)
        if options.command
        else url_tool(options.url, options.timeout)
    )
    results = evaluate(options.dataset, run)
    totals = summary(results)
    print(report(results, totals))

    if options.report:
        details = [
            {
                "case": result.case,
                "category": result.category,
                "checks": [vars(check) for check in result.checks],
                "invented": result.invented,
                "error": result.error,
            }
            for result in results
        ]
        options.report.write_text(
            json.dumps({"summary": totals, "cases": details}, indent=2) + "\n", encoding="utf-8"
        )

    overall = totals["overall"]["score"] or 0
    return 1 if options.min_score is not None and overall < options.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
