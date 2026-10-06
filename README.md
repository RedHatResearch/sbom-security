# sbom-security

[![tests](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml)

Report the dependencies of a package or repository, together with the known
vulnerabilities affecting them. Covers npm and Python.

## Quick start

```bash
git clone https://github.com/RedHatResearch/sbom-security.git
cd sbom-security
docker compose up -d
```

Scan a real repository:

```bash
curl 'http://127.0.0.1:8010/reports/github?owner=OWASP&repo=NodeGoat&limit=3000'
```

That returns every dependency in the project and the CVEs affecting them. On OWASP
NodeGoat that is 1091 packages, 130 of them vulnerable, in a few seconds.

Interactive API documentation: **http://127.0.0.1:8010/docs**

## Endpoints

| Endpoint | Purpose |
| -------- | ------- |
| `GET /reports/github?owner=&repo=` | Scan a public GitHub repository |
| `POST /reports/npm-lockfile` | Scan a `package-lock.json` sent as the body |
| `GET /reports/npm-package?name=&version=` | Scan a package and its dependencies |
| `POST /jobs/npm-package?name=&version=` | Hand a scan to a worker, collect it later |
| `GET /jobs/{id}` | Status and result of submitted work |
| `GET /queue` | How much work is waiting, and what is running |
| `GET /health` | Liveness check |

## Usage

**A public repository.** Nothing is cloned, no package manager runs, and no code from
the repository is executed — only its dependency files are read.

```bash
curl 'http://127.0.0.1:8010/reports/github?owner=OWASP&repo=NodeGoat'
```

The repository is read from whichever of these it has, in order:

| File | Ecosystem | Versions |
| ---- | --------- | -------- |
| `package-lock.json` | npm | Already exact |
| `package.json` | npm | Ranges, resolved against the registry |
| `requirements.txt` | Python | Pins or ranges, resolved against PyPI |

**A lockfile you already have.**

```bash
curl -X POST http://127.0.0.1:8010/reports/npm-lockfile \
  -H 'Content-Type: application/json' \
  --data-binary @package-lock.json
```

**A package, with no lockfile anywhere.** The whole dependency tree is walked unless
`depth` asks for less.

```bash
curl 'http://127.0.0.1:8010/reports/npm-package?name=express&version=4.18.0'
curl 'http://127.0.0.1:8010/reports/npm-package?name=express&version=4.18.0&depth=1'
```

`version` may also be a range, or left out entirely:

| Asked for | Gets |
| --------- | ---- |
| `version=4.18.0` | that exact version |
| `version=^4.0.0` | the newest that does not cross a major boundary |
| *omitted* | the newest release |

The report always names the version it settled on, never the range — so a scan of
`express` records `express@5.0.0`, and `generated_at` says when that was what newest
meant. That way a package can be asked about once rather than re-registered at every
release.

A walk runs to the bottom of the tree, bounded by a ceiling on how many packages one
request may examine. Depth cannot be predicted from outside, but the amount of work a
single request causes can be — and a walk stopped by that ceiling is marked
`"truncated": true`.

### The report

```json
{
  "schema_version": "1.1",
  "tool": "sbom-security",
  "generated_at": "2026-09-28T09:15:00+00:00",
  "target": {
    "name": "OWASP/NodeGoat@HEAD",
    "ecosystem": "npm",
    "source": "lockfile"
  },
  "summary": { "dependencies": 1091, "vulnerable": 130, "vulnerabilities": 187 },
  "dependencies": [
    { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "ecosystem": "npm" }
  ],
  "findings": [
    {
      "dependency": { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "ecosystem": "npm" },
      "vulnerabilities": [
        {
          "id": "GHSA-rv95-896h-c2vc",
          "aliases": ["CVE-2024-29041"],
          "summary": "Express.js Open Redirect in malformed URLs",
          "severity": "MODERATE",
          "fixed_version": "4.19.2",
          "url": "https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc"
        }
      ]
    }
  ],
  "truncated": false,
  "unresolved": []
}
```

**`target.source` says which question the report answers**, and the answers differ:

| Source | Versions are | Answers |
| ------ | ------------ | ------- |
| `lockfile` | exactly what is installed | *What does this project have?* |
| `manifest` | declared ranges resolved to the newest match | *What would this project get if it installed today?* |
| `package` | what a released version declares | *What does this package pull in?* |

This matters when reading a result. A `manifest` scan showing no findings does not mean
the project is safe — it means the *current* versions of its dependencies are clean.
What the project actually runs may well be older, and a `lockfile` scan of the same
project will often find more.

**Completeness is reported, never implied.** `truncated` means a limit stopped the scan
short. `unresolved` names dependencies that could not be resolved at all — a local path,
a git dependency, an unpublished package, a `-r other.txt` that was not followed. A scan
examines 500 dependencies by default; raise it with `&limit=3000`.

`generated_at` matters because vulnerability data changes daily: an undated report
cannot be compared against a later one.

## Submitting work instead of waiting

A large tree can take longer to resolve than a caller wants to hold a connection open.
Hand it to a worker instead:

```bash
curl -X POST 'http://127.0.0.1:8010/jobs/npm-package?name=express&version=4.18.0'
```

That returns an identifier immediately. Collect the result from it:

```bash
curl 'http://127.0.0.1:8010/jobs/pkg:npm/express@4.18.0@depth=3'
```

Status is `queued`, `in_progress`, then `complete` with the report attached. Submitting
the same request again while the first is still running returns the same identifier
rather than repeating the work.

To be told when it finishes rather than asking, pass an address to post the report to:

```bash
curl -X POST 'http://127.0.0.1:8010/jobs/npm-package?name=express&version=4.18.0&callback_url=https://example.com/done'
```

## Running it

**Everything together** — API, a worker and Redis, on port 8010:

```bash
docker compose up -d
docker compose up -d --scale worker=4    # more workers
```

**API only**, on port 8000:

```bash
docker build -t sbom-security .
docker run --rm -p 8000:8000 sbom-security
```

Without Redis the scan endpoints work as normal; only the submitted-work endpoints
report themselves unavailable.

**From source**, for development:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn sbom_security.api:app --reload
pytest && pylint src/
```

Requires Python 3.12 or newer, and outbound network access to reach OSV.dev and
deps.dev.

## How it works

```
input  ->  resolve dependencies  ->  normalize to PURL  ->  match against OSV.dev  ->  report
```

Matching is done on Package URLs (`pkg:npm/express@4.18.0`) against the OSV schema's
version ranges, which are ecosystem-native and therefore precise.

Dependency versions come from lockfiles where one exists, and otherwise from resolved
graphs published by [deps.dev](https://deps.dev), so nothing has to be installed.

Each version's direct dependencies are cached on disk, one file per version, under
`.cache` (override with `SBOM_CACHE_DIR`). Those entries never expire: a published
version cannot change what it depends on, so a package depended on by fifty others is
resolved once rather than fifty times. Vulnerability data is deliberately not cached —
a package that is clean today can be vulnerable tomorrow.

## Conventions

Commits follow [Conventional Commits](https://www.conventionalcommits.org):
`feat:`, `fix:`, `build:`, `docs:`, `chore:`, `ci:`.

- A `fix:` commit includes the test that failed before the fix and passes after it.
- A `feat:` commit is verified by a full test-suite pass.
- Writing `Resolves #N` in a commit closes that issue when it reaches `main`.

Reused third-party code is recorded in [ATTRIBUTIONS.md](ATTRIBUTIONS.md) at the time
it is added.

## License

Apache-2.0. See [LICENSE](LICENSE).
