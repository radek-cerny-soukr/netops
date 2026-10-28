FROM python:3.14.9-alpine3.24@sha256:dbeb11d16bb95c3a7e3c25c842cb9f20cbc8c18f8be0461a4a0dcc861ad386a0 AS base
LABEL org.opencontainers.image.title="netops" \
      org.opencontainers.image.version="1.0.4" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NETOPS_ASKPASS_PROGRAM=/usr/local/bin/netops-askpass
RUN apk upgrade --no-cache && apk add --no-cache openssh-client \
    && addgroup -g 51000 -S netops-gateway \
    && adduser -u 51000 -S -D -H -G netops-gateway netops-gateway \
    && addgroup -g 51001 -S netops-helper \
    && adduser -u 51001 -S -D -H -G netops-helper netops-helper \
    && addgroup -g 51002 -S netops-auditor \
    && adduser -u 51002 -S -D -H -G netops-auditor netops-auditor \
    && addgroup -g 51003 -S netops-admin \
    && adduser -u 51003 -S -D -H -G netops-admin netops-admin
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN umask 022 && python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /app/requirements.lock && python -m pip check

FROM base AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY build-requirements.lock /build/build-requirements.lock
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r /build/build-requirements.lock && python -m pip check
COPY pyproject.toml LICENSE /build/
COPY src/netops /build/src/netops
COPY components/netops-core/src/netops_core /build/components/netops-core/src/netops_core
COPY components/netops-helper/src/netops_helper /build/components/netops-helper/src/netops_helper
COPY components/netops-auditor/src/netops_auditor /build/components/netops-auditor/src/netops_auditor
COPY components/netops-admin/src/netops_admin /build/components/netops-admin/src/netops_admin
RUN find /build -type d -exec chmod 0755 {} + \
    && find /build -type f -exec chmod 0644 {} + \
    && python -m pip wheel --no-deps --no-build-isolation --wheel-dir /dist /build

COPY release/start.c /build/start.c
RUN cc -Os -static -s -Wall -Wextra -Werror -o /dist/netops-start /build/start.c

FROM base AS runtime
COPY --from=builder /dist /dist
RUN umask 022 && python -m pip install --no-deps --no-index --no-compile /dist/netops-1.0.4-py3-none-any.whl \
    && python -m pip check \
    && cp /usr/local/lib/python3.14/site-packages/netops_core/askpass.py /usr/local/bin/netops-askpass \
    && cp /dist/netops-start /usr/local/bin/netops-start \
    && chmod 0755 /usr/local/bin/netops-askpass /usr/local/bin/netops-start \
    && python -m pip uninstall --yes pip \
    && rm -rf /dist
COPY tests/v1 /opt/netops/tests
RUN find /opt/netops -type d -exec chmod 0755 {} + \
    && find /opt/netops -type f -exec chmod 0644 {} +
USER 0:0
ENTRYPOINT ["netops-start"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["netops", "health"]
