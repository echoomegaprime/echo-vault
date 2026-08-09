#!/bin/sh
set -eu

if [ "${1:-}" = "init" ]; then
  exec echo-vault "$@"
fi

runtime_dir=/tmp/echo-vault-runtime
umask 077
mkdir -p "$runtime_dir"

copy_secret() {
  source_path="$1"
  target_path="$2"
  if [ ! -r "$source_path" ]; then
    echo "Required runtime secret is unreadable: $source_path" >&2
    exit 1
  fi
  cp "$source_path" "$target_path"
  chmod 0600 "$target_path"
}

copy_secret "${ECHO_VAULT_KEYS_SOURCE:-/run/secrets/echo_vault_keys}" \
  "${ECHO_VAULT_KEYS_FILE:-$runtime_dir/keys.json}"
copy_secret "${ECHO_VAULT_CLIENTS_SOURCE:-/run/secrets/echo_vault_clients}" \
  "${ECHO_VAULT_CLIENTS_FILE:-$runtime_dir/clients.json}"

exec echo-vault "$@"
