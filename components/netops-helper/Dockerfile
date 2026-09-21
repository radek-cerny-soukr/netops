FROM python:3.14.7-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

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
    && apt-get upgrade --yes \
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
RUN install --mode=0755 --owner=root --group=root \
    /app/src/netops_core/askpass.py /usr/local/bin/netops-askpass
ENV NETOPS_ASKPASS_PROGRAM=/usr/local/bin/netops-askpass
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip uninstall -y pip

RUN mkdir -p /var/lib/netops-helper \
    && chown -R "${APP_UID}:${APP_GID}" /var/lib/netops-helper /app

USER ${APP_UID}:${APP_GID}
CMD ["python", "-m", "netops_helper.idle"]
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-m", "netops_helper.selftest"]
