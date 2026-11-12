ARG NETOPS_TEST_IMAGE=netops-test-image-required
FROM python:3.14.10-alpine3.24@sha256:a18b20ad69e74df6cf6d2e1b1a260d7a1ecf5380fd83b310f83ba88c461cf894 AS netops-test-image-required
RUN echo 'NETOPS_TEST_IMAGE is required: build with --build-arg NETOPS_TEST_IMAGE=<complete production image reference>' >&2 && exit 1
FROM ${NETOPS_TEST_IMAGE}
USER 0:0
RUN python -m venv --system-site-packages /testenv
COPY requirements-test.lock /test-requirements.lock
RUN --mount=type=secret,id=extra_ca,required=false --mount=type=tmpfs,target=/run/netops-ca \
    if [ -s /run/secrets/extra_ca ]; then cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /run/netops-ca/ca.pem && export PIP_CERT=/run/netops-ca/ca.pem SSL_CERT_FILE=/run/netops-ca/ca.pem; fi \
    && /testenv/bin/python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /test-requirements.lock && /testenv/bin/python -m pip check
COPY components /repo/components
COPY docs /repo/docs
COPY scripts /repo/scripts
COPY tests /repo/tests
COPY release/engine_regression.py release/notes-1.0.7.md /repo/release/
COPY README.md CHANGELOG.md SECURITY.md LICENSE pyproject.toml requirements.lock requirements.in /repo/
RUN chmod -R a+rX,go-w /repo \
    && mkdir -p /opt/netops-test-fixtures \
    && printf '{}\n' > /opt/netops-test-fixtures/owner-only \
    && chmod 0600 /opt/netops-test-fixtures/owner-only
ENV HOME=/repo TMPDIR=/tmp NETOPS_REQUIRE_RUNTIME_TESTS=1
USER 51000:51000
HEALTHCHECK NONE
ENTRYPOINT ["/testenv/bin/python", "-B", "/repo/release/engine_regression.py"]
