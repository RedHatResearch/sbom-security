# Test images

Syft's output for real public images, recorded so that tests exercise real image
contents without Syft, a registry or the network. This is the test dataset #23 asks for.

| File | Image, pinned by digest | What it exercises |
| ---- | ----------------------- | ----------------- |
| `ubi-minimal.syft.json` | `registry.access.redhat.com/ubi9/ubi-minimal@sha256:5ed244b62bbf4095080144d9d35eb8fcd3d39a9801f94aadd63b9d10978a01ae` | RPM packages only (RHEL 9.8), some with an epoch |
| `python-3.12-slim.syft.json` | `docker.io/library/python@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f` | Debian packages, one Python package, binaries without a Package URL |
| `node-22-alpine.syft.json` | `docker.io/library/node@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402` | npm packages, scoped and repeated; Alpine packages; the Node.js binary |
| `juice-shop.syft.json` | `docker.io/bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` | A real application: about 700 npm entries, many installed more than once |

Recorded with Syft 1.54.1 on 2026-10-07, for `linux/amd64`:

```bash
syft registry:<image> -o syft-json
```

Each file keeps only the fields this project reads, to keep the repository small:

```bash
jq '{descriptor: {name: .descriptor.name, version: .descriptor.version},
     source: {type: .source.type,
              metadata: {userInput: .source.metadata.userInput,
                         repoDigests: .source.metadata.repoDigests,
                         architecture: .source.metadata.architecture}},
     distro: {id: .distro.id, versionID: .distro.versionID, prettyName: .distro.prettyName},
     artifacts: [.artifacts[] | {name, version, type, purl}]}'
```

To refresh a file, run Syft against the pinned reference above rather than a tag, so
that the expected contents stay the same.
