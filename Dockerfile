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

# Run as an unprivileged user rather than root.
RUN useradd --create-home --uid 1001 app
USER app

EXPOSE 8000

CMD ["uvicorn", "sbom_security.api:app", "--host", "0.0.0.0", "--port", "8000"]
