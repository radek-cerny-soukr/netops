ARG NETOPS_TEST_IMAGE
FROM ${NETOPS_TEST_IMAGE}
USER 0:0
RUN python -m venv --system-site-packages /testenv
COPY requirements-test.lock /test-requirements.lock
RUN /testenv/bin/python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /test-requirements.lock && /testenv/bin/python -m pip check
COPY components /repo/components
COPY docs /repo/docs
COPY scripts /repo/scripts
COPY tests /repo/tests
COPY release/engine_regression.py /repo/release/
COPY README.md CHANGELOG.md SECURITY.md LICENSE pyproject.toml requirements.lock requirements.in /repo/
RUN chmod -R a+rX,go-w /repo \
    && mkdir -p /opt/netops-test-fixtures \
    && printf '{}\n' > /opt/netops-test-fixtures/owner-only \
    && chmod 0600 /opt/netops-test-fixtures/owner-only
ENV HOME=/repo TMPDIR=/tmp NETOPS_REQUIRE_RUNTIME_TESTS=1
USER 51000:51000
HEALTHCHECK NONE
ENTRYPOINT ["/testenv/bin/python", "-B", "/repo/release/engine_regression.py"]
