# DEEPLINK X — container image. Static analysis, REST API and dashboard.
# Dynamic testing needs an emulator; point it at a host/side-car adb server with ADB_SERVER_SOCKET (see docs/docker.md).
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="DEEPLINK X" \
      org.opencontainers.image.description="Android deep link and entry point security auditor" \
      org.opencontainers.image.authors="Karndeep Baror" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEEPLINKX_HOME=/data
RUN apt-get update && apt-get install -y --no-install-recommends android-tools-adb && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 dlx && mkdir /data /work && chown dlx /data /work
COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm /tmp/*.whl
USER dlx
WORKDIR /work
VOLUME ["/data", "/work"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=4s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8787/api/v1/health', timeout=3)" || exit 1
ENTRYPOINT ["deeplinkx"]
CMD ["serve", "--host", "0.0.0.0"]
