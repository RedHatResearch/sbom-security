# Support policy dataset

Test cases for reading a project's security policy: which versions of a package it says
still receive security fixes. Each case pairs a policy, as published, with what a report
should say about some of the package's versions once the policy has been read.

## Layout

```
cases/<name>.json    one case: where the policy is, how it reads, and what a report should say
```

The policies themselves are not copied here: each is under its own project's license.
A case links its policy at the commit it was checked at, so the text it is measured on
never changes.

## A case

Shortened:

```json
{
  "package": "ethers",
  "policy": "https://github.com/ethers-io/ethers.js/blob/faa556c1e5f727105ec6cdc5ed25de30095108d6/SECURITY.md",
  "newest": "6.17.0",
  "date": "2026-10-12",
  "reading": {
    "kind": "versions",
    "rules": [
      {"versions": "6.x", "status": "supported", "until": null},
      {"versions": "5.x", "status": "security_only", "until": null},
      {"versions": "<5", "status": "unsupported", "until": null}
    ]
  },
  "expected": {"6.17.0": "supported", "5.8.0": "limited", "4.0.49": "eol"},
  "category": "edge",
  "notes": "Rows are written 6.0.x and 5.0.x, but each gives the first release of a major line, ..."
}
```

| Field | Meaning |
| ----- | ------- |
| `package` | The npm package the policy is read for. A policy shared across an organisation, or by a monorepo, covers many |
| `policy` | The policy file on GitHub, at a commit |
| `newest` | The newest version on the registry when the case was written. Policies such as "only the latest release" are judged against it |
| `date` | The day the case is judged on, so that end dates compare the same way whenever it is run |
| `reading` | The policy as a careful reader states it, in the rules the service uses. A model can write its rules differently and still be right, so only `kind` is compared with it directly |
| `expected` | Versions of the package, each with what a report should give it: `supported`, `limited` or `eol`, followed by `until` and a date where support ends on one; `null` where the policy says nothing about that version |
| `category` | `happy`, `unhappy` or `edge`; see below |
| `notes` | Why the answer is what it is, where that is not obvious |

## How the answers were decided

- **What the text states, and nothing more.** A version the policy does not cover gets
  no status, even where the project plainly still maintains it: `express-fileupload`'s
  table stops at 1.3.x, so 1.5.2 has none.
- **Support is per line**, as it is for endoflife.date's data. Where a policy patches
  only the last minor of a line, as Babel's does, an older minor still counts as in the
  line: the fix is reached by updating within it.
- **A row means what the text around it says it means.** ethers writes its major lines
  as `6.0.x`, and the text says the latest major is the one maintained, so 6.17.0 is
  supported.
- **Security fixes only, or a line winding down to a date, is `limited`.** That is what
  a report says for it, and what SPDX calls `limitedSupport`.

| Category | Means |
| -------- | ----- |
| `happy` | A table, a range or a rule that says plainly which versions are supported |
| `unhappy` | A policy that states nothing for the package: one about other products, one that only explains how to report, one that promises fixes without saying for which versions |
| `edge` | A policy whose literal reading and plain reading differ, or that keeps GitHub's template wording around real values |

## What is not covered yet

- **GitHub's template with its example values left in.** Of twenty package repositories
  whose policy keeps the template's wording, none kept its example versions, so no real
  case was found. The model's instructions still cover it.
- **PyPI packages.** Every case is an npm package. Reading does not depend on the
  ecosystem; finding the newest version for a relative rule does.
- **Policies anywhere but SECURITY.md**, such as a page on the project's website.
