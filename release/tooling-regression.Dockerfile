ARG NETOPS_ENGINE_IMAGE=netops-engine-tests
FROM ${NETOPS_ENGINE_IMAGE}
USER 0:0
# Release tests execute the candidate Bash block, Compose config and private
# local PowerShell containers. No production dependency is changed.
RUN apk add --no-cache bash git sed coreutils openssl docker-cli docker-cli-compose
COPY release/requirements-sbom.lock /tooling-requirements.lock
RUN /testenv/bin/python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tooling-requirements.lock \
    && /testenv/bin/python -m pip check
ENV PATH=/testenv/bin:$PATH
USER 51000:51000
