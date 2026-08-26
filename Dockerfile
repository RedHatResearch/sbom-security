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
