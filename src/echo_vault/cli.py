"""Operator CLI and signed HTTP client."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx

from .auth import create_client_manifest, decode_client_secret, sign_headers
from .config import Settings
from .crypto import create_key_ring


def _client_identity() -> tuple[str, bytes]:
    client_id = os.getenv("ECHO_VAULT_CLIENT_ID", "")
    encoded_secret = os.getenv("ECHO_VAULT_CLIENT_SECRET", "")
    if not client_id or not encoded_secret:
        raise SystemExit("ECHO_VAULT_CLIENT_ID and ECHO_VAULT_CLIENT_SECRET are required")
    return client_id, decode_client_secret(encoded_secret)


def _base_url() -> str:
    value = os.getenv("ECHO_VAULT_URL", "http://127.0.0.1:8080").rstrip("/")
    parsed = urlsplit(value)
    if parsed.username or parsed.password or not parsed.hostname:
        raise SystemExit("ECHO_VAULT_URL must not contain credentials")
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    insecure_override = os.getenv("ECHO_VAULT_ALLOW_INSECURE_HTTP") == "1"
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and (loopback or insecure_override)
    ):
        raise SystemExit("remote ECHO_VAULT_URL must use HTTPS")
    return value


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            if not value.endswith("\n"):
                handle.write("\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _request(method: str, path: str, *, query: str = "", payload: object | None = None) -> object:
    client_id, secret = _client_identity()
    body = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if payload is not None
        else b""
    )
    headers = sign_headers(client_id, secret, method, path, query=query, body=body)
    if body:
        headers["Content-Type"] = "application/json"
    url = f"{_base_url()}{path}"
    if query:
        url = f"{url}?{query}"
    with httpx.Client(timeout=15.0, follow_redirects=False) as client:
        response = client.request(method, url, content=body or None, headers=headers)
    if response.is_error:
        detail = response.json().get("detail", "request failed")
        raise SystemExit(f"HTTP {response.status_code}: {detail}")
    return response.json()


def _read_secret(args: argparse.Namespace) -> str:
    if args.stdin:
        value = sys.stdin.read()
    else:
        import getpass

        value = getpass.getpass("Secret: ")
    if not value:
        raise SystemExit("secret value cannot be empty")
    return value


def command_init(args: argparse.Namespace) -> None:
    directory = Path(args.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    create_key_ring(directory / "keys.json")
    one_time_secret = create_client_manifest(directory / "clients.json")
    (directory / "data").mkdir(mode=0o700, exist_ok=True)
    print(f"Created ECHO Vault material in {directory}")
    print("Client ID: local-admin")
    if args.print_client_secret:
        print(f"One-time client secret: {one_time_secret}")
        print("Store this value securely; it will not be printed again by ECHO Vault.")
    else:
        secret_path = directory / "bootstrap-client.secret"
        _write_private(secret_path, one_time_secret)
        print(f"Bootstrap client secret written to {secret_path}")
        print("Move it into a protected secret store, then remove the bootstrap file.")


def command_serve(_: argparse.Namespace) -> None:
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run("echo_vault.app:create_app", factory=True, host=settings.host, port=settings.port)


def command_put(args: argparse.Namespace) -> None:
    payload = {
        "secret": _read_secret(args),
        "username": args.username,
        "metadata": {},
        "tags": args.tag,
    }
    result = _request("POST", f"/v1/secrets/{args.namespace}/{args.name}", payload=payload)
    print(json.dumps(result, indent=2, sort_keys=True))


def command_update(args: argparse.Namespace) -> None:
    payload = {
        "secret": _read_secret(args),
        "username": args.username,
        "metadata": {},
        "tags": args.tag,
        "expected_version": args.expected_version,
    }
    result = _request("PATCH", f"/v1/secrets/{args.namespace}/{args.name}", payload=payload)
    print(json.dumps(result, indent=2, sort_keys=True))


def command_get(args: argparse.Namespace) -> None:
    result = _request("GET", f"/v1/secrets/{args.namespace}/{args.name}")
    if args.json:
        rendered = json.dumps(result, indent=2, sort_keys=True)
    else:
        assert isinstance(result, dict)
        rendered = str(result["secret"])
    if args.show:
        print(rendered)
    else:
        _write_private(Path(args.output).resolve(), rendered)
        print(f"Secret written to {Path(args.output).resolve()}")


def command_list(args: argparse.Namespace) -> None:
    query = urlencode({"namespace": args.namespace})
    result = _request("GET", "/v1/secrets", query=query)
    print(json.dumps(result, indent=2, sort_keys=True))


def command_delete(args: argparse.Namespace) -> None:
    result = _request(
        "DELETE",
        f"/v1/secrets/{args.namespace}/{args.name}",
        payload={"expected_version": args.expected_version},
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def command_audit(_: argparse.Namespace) -> None:
    result = _request("GET", "/v1/audit/verify")
    print(json.dumps(result, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="echo-vault", description="ECHO Vault operator CLI")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create key and client manifests")
    init.add_argument("--directory", default=".echo-vault")
    init.add_argument(
        "--print-client-secret",
        action="store_true",
        help="explicitly print the bootstrap client secret to stdout",
    )
    init.set_defaults(handler=command_init)

    serve = commands.add_parser("serve", help="start the API server")
    serve.set_defaults(handler=command_serve)

    for name, handler in (("put", command_put), ("update", command_update)):
        item = commands.add_parser(name, help=f"{name} a secret")
        item.add_argument("namespace")
        item.add_argument("name")
        item.add_argument("--stdin", action="store_true", help="read the secret from stdin")
        item.add_argument("--username")
        item.add_argument("--tag", action="append", default=[])
        if name == "update":
            item.add_argument("--expected-version", required=True, type=int)
        item.set_defaults(handler=handler)

    get = commands.add_parser("get", help="retrieve a secret")
    get.add_argument("namespace")
    get.add_argument("name")
    get.add_argument("--json", action="store_true")
    destination = get.add_mutually_exclusive_group(required=True)
    destination.add_argument(
        "--show", action="store_true", help="explicitly print the secret to stdout"
    )
    destination.add_argument("--output", help="write the secret to a new mode-0600 file")
    get.set_defaults(handler=command_get)

    listing = commands.add_parser("list", help="list non-secret metadata")
    listing.add_argument("namespace")
    listing.set_defaults(handler=command_list)

    delete = commands.add_parser("delete", help="soft-delete a secret")
    delete.add_argument("namespace")
    delete.add_argument("name")
    delete.add_argument("--expected-version", required=True, type=int)
    delete.set_defaults(handler=command_delete)

    audit = commands.add_parser("audit", help="verify the audit chain")
    audit.set_defaults(handler=command_audit)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
