# Cloakwall on top of LiteLLM. One container, no sidecars.
#
#   docker build -t cloakwall .
#   docker run -p 4000:4000 -e LITELLM_MASTER_KEY=sk-... -e OPENAI_API_KEY=sk-... cloakwall
FROM python:3.12-slim

# Installs the published package, the same thing customers pip install.
ARG CLOAKWALL_VERSION=0.1.0
RUN pip install --no-cache-dir "litellm[proxy]" "cloakwall==${CLOAKWALL_VERSION}" \
 && useradd -r -u 65532 -s /usr/sbin/nologin cloakwall \
 && mkdir -p /var/log/cloakwall && chown cloakwall:cloakwall /var/log/cloakwall

COPY examples/config.yaml /app/config.yaml

USER 65532:65532
WORKDIR /app
EXPOSE 4000
# LITELLM_MASTER_KEY must be set at run time; LiteLLM will not start without it.
CMD ["litellm", "--config", "/app/config.yaml", "--port", "4000", "--host", "0.0.0.0"]
