# Build:  docker build -t sbom-security .
# Run:    docker run --rm -p 8000:8000 sbom-security
#
# The service listens on port 8000 inside the container and needs outbound network
# access to reach the OSV.dev API.

FROM python:3.12-slim

WORKDIR /app

# Install dependencies before copying the source, so that editing code does not
# invalidate the cached dependency layer.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Syft finds the packages inside container images. It is copied from its official
# image pinned by digest, so every build gets exactly the binary that was reviewed
# rather than whatever the tag points at today.
COPY --from=docker.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa /syft /usr/local/bin/syft
ENV SYFT_CHECK_FOR_APP_UPDATE=false

# Run as an unprivileged user rather than root. The cache directory is created here
# so that a volume mounted over it inherits this ownership: Docker seeds an empty
# named volume from the image, and without this the directory would arrive owned by
# root and be unwritable by the user the process runs as.
RUN useradd --create-home --uid 1001 app \
    && mkdir -p /cache \
    && chown app:app /cache
USER app

EXPOSE 8000

CMD ["uvicorn", "sbom_security.api:app", "--host", "0.0.0.0", "--port", "8000"]
