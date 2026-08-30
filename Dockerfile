FROM python:3.14.7-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ECHO_VAULT_ENV=production \
    ECHO_VAULT_DATA_DIR=/var/lib/echo-vault \
    ECHO_VAULT_KEYS_SOURCE=/run/secrets/echo_vault_keys \
    ECHO_VAULT_CLIENTS_SOURCE=/run/secrets/echo_vault_clients \
    ECHO_VAULT_KEYS_FILE=/tmp/echo-vault-runtime/keys.json \
    ECHO_VAULT_CLIENTS_FILE=/tmp/echo-vault-runtime/clients.json \
    ECHO_VAULT_AUDIT_ANCHOR_FILE=/var/lib/echo-vault-audit/audit.anchor \
    ECHO_VAULT_HOST=0.0.0.0 \
    ECHO_VAULT_PORT=8080

WORKDIR /app
COPY pyproject.toml constraints.txt README.md LICENSE ./
COPY src ./src
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN python -m pip install --upgrade pip==25.1.1 && \
    python -m pip install -c constraints.txt . && \
    python -m pip check && \
    addgroup --system --gid 65532 vault && \
    adduser --system --uid 65532 --ingroup vault --home /nonexistent --no-create-home vault && \
    install -d -o vault -g vault -m 0700 /var/lib/echo-vault /var/lib/echo-vault-audit && \
    chmod 0555 /usr/local/bin/docker-entrypoint.sh

USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/echo-vault", "/var/lib/echo-vault-audit"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2)"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
