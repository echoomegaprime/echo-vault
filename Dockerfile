FROM python:3.12.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ECHO_VAULT_ENV=production \
    ECHO_VAULT_DATA_DIR=/var/lib/echo-vault \
    ECHO_VAULT_KEYS_FILE=/run/secrets/echo_vault_keys \
    ECHO_VAULT_CLIENTS_FILE=/run/secrets/echo_vault_clients \
    ECHO_VAULT_HOST=0.0.0.0 \
    ECHO_VAULT_PORT=8080

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade pip==25.1.1 && \
    python -m pip install . && \
    addgroup --system --gid 65532 vault && \
    adduser --system --uid 65532 --ingroup vault --home /nonexistent --no-create-home vault && \
    install -d -o vault -g vault -m 0700 /var/lib/echo-vault

USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/echo-vault"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

ENTRYPOINT ["echo-vault"]
CMD ["serve"]
