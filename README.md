# sbom-security

[![tests](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml)

Report the dependencies of an npm package or repository, together with the known
vulnerabilities affecting them.

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
| `GET /health` | Liveness check |

## Usage

**A public repository.** Only `package-lock.json` is fetched — nothing is cloned, no
package manager runs, and no code from the repository is executed.

```bash
curl 'http://127.0.0.1:8010/reports/github?owner=OWASP&repo=NodeGoat'
```

**A lockfile you already have.**

```bash
curl -X POST http://127.0.0.1:8010/reports/npm-lockfile \
  -H 'Content-Type: application/json' \
  --data-binary @package-lock.json
```

**A package, with no lockfile anywhere.** `depth` controls how many levels are walked.

```bash
curl 'http://127.0.0.1:8010/reports/npm-package?name=express&version=4.18.0&depth=3'
```

### The response

```json
{
  "target": "example-project",
  "dependencies": [
    { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0" }
  ],
  "findings": [
    {
      "dependency": { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0" },
      "vulnerabilities": [
        {
          "id": "GHSA-rv95-896h-c2vc",
          "aliases": ["CVE-2024-29041"],
          "summary": "Express.js Open Redirect in malformed URLs",
          "severity": "MODERATE",
          "fixed_version": "4.19.2"
        }
      ]
    }
  ],
  "truncated": false
}
```

Every dependency is listed; `findings` covers only those with known vulnerabilities.
`truncated` says a limit stopped the scan short, so a partial result is never mistaken
for a clean one. A scan examines 500 dependencies by default — raise it with
`&limit=3000`.

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
