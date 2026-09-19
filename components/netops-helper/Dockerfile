FROM python:3.13.15-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

ARG APP_UID=65532
ARG APP_GID=65532
ARG COMPONENT_DIR=.
ARG CORE_PACKAGE_DIR=src/netops_core

LABEL org.opencontainers.image.title="netops-helper" \
      org.opencontainers.image.source="https://github.com/radek-cerny-soukr/netops" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN groupadd --gid "${APP_GID}" netops \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --home-dir /nonexistent --shell /usr/sbin/nologin netops

RUN set -eu \
    && apt-get update \
    && apt-get install --yes --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/netops-helper/certs
COPY ${COMPONENT_DIR}/config/container/tls-pins.json /etc/netops-helper/tls-pins.json
COPY ${COMPONENT_DIR}/config/container/certs/ /etc/netops-helper/certs/
COPY ${COMPONENT_DIR}/config/container/ca/ /usr/local/share/ca-certificates/netops-helper/
RUN update-ca-certificates

WORKDIR /app
COPY ${COMPONENT_DIR}/requirements.lock ./
COPY ${COMPONENT_DIR}/src ./src
COPY ${CORE_PACKAGE_DIR} ./src/netops_core
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip uninstall -y pip

RUN mkdir -p /var/lib/netops-helper \
    && chown -R "${APP_UID}:${APP_GID}" /var/lib/netops-helper /app

USER ${APP_UID}:${APP_GID}
CMD ["python", "-m", "netops_helper.idle"]
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-m", "netops_helper.selftest"]
