# Cloakwall on top of LiteLLM. One container, no sidecars.
FROM python:3.12-slim

RUN pip install --no-cache-dir "litellm[proxy]" \
 && useradd -r -u 65532 -s /usr/sbin/nologin cloakwall \
 && mkdir -p /var/log/cloakwall && chown cloakwall:cloakwall /var/log/cloakwall

COPY cloakwall/ /app/cloakwall/
COPY examples/config.yaml /app/config.yaml
ENV PYTHONPATH=/app

USER 65532:65532
WORKDIR /app
EXPOSE 4000
CMD ["litellm", "--config", "/app/config.yaml", "--port", "4000", "--host", "0.0.0.0"]
