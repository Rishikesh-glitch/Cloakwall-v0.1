# Cloakwall on top of LiteLLM. One container, no sidecars.
#
#   docker build -t cloakwall .
#   docker run -p 4000:4000 -e LITELLM_MASTER_KEY=sk-... -e OPENAI_API_KEY=sk-... cloakwall
FROM python:3.12-slim

# Installs the published package, the same thing customers pip install.
# LiteLLM is pinned: releases 1.82.7, 1.82.8 and 1.107.0 were hijacked in 2026.
# Bump deliberately, after checking the release is clean.
ARG CLOAKWALL_VERSION=0.2.0
ARG LITELLM_VERSION=1.106.0
RUN pip install --no-cache-dir "litellm[proxy]==${LITELLM_VERSION}" "cloakwall==${CLOAKWALL_VERSION}" \
 && useradd -r -u 65532 -s /usr/sbin/nologin cloakwall \
 && mkdir -p /var/log/cloakwall && chown cloakwall:cloakwall /var/log/cloakwall

COPY examples/config.yaml /app/config.yaml

USER 65532:65532
WORKDIR /app
EXPOSE 4000
# LITELLM_MASTER_KEY must be set at run time; LiteLLM will not start without it.
CMD ["litellm", "--config", "/app/config.yaml", "--port", "4000", "--host", "0.0.0.0"]
