# Attributions

Third-party work this project builds on, recorded at the time it is adopted rather
than retroactively.

This project is licensed under Apache-2.0. Reused components must carry a compatible
license: Apache-2.0 and MIT are compatible, AGPL is not.

The complete set of installed dependencies is declared in `pyproject.toml`. This file
records what was deliberately taken and what it replaces, which the dependency list
alone does not convey.

## Data sources

| Source | Where | License | Used for |
| ------ | ----- | ------- | -------- |
| OSV.dev | https://osv.dev | Records carry their upstream licenses; see osv.dev | The vulnerability database and its schema. Aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability database and around twenty further feeds, so this project does not maintain a vulnerability database of its own. |
| deps.dev | https://deps.dev | See deps.dev | Resolved dependency graphs per package version. A package declares version ranges, and turning those into exact versions means reimplementing part of npm's resolver; deps.dev has already done it. |

## Libraries

| Component | Where | License | Used for |
| --------- | ----- | ------- | -------- |
| packageurl-python | https://github.com/package-url/packageurl-python | MIT | Building and parsing Package URLs, rather than reimplementing the specification |
| arq | https://github.com/python-arq/arq | MIT | The work queue. Chosen over Celery because it is built for asyncio, which the rest of this project already uses, and because the work here is uniform and parallel rather than orchestrated. It is confined to `queue.py` and `worker.py`; the work itself has no knowledge of it. |

## Designs adopted without reusing code

The components identified as reusable during the competitor analysis are written in Go
or Ruby and cannot be imported into a Python project. Their designs carried over
instead:

- **Syft and Grype** (Apache-2.0, Go) — separating "produce the inventory" from
  "analyze the inventory", which is why parsing and matching are distinct here.
- **Dependabot** (MIT, Ruby) — one self-contained parser per ecosystem behind a common
  interface.
- **OWASP Dependency-Check** (Apache-2.0, Java) — a counter-example: its CPE-based
  matching is the documented source of its false positives, which is why this project
  matches on Package URLs instead.
