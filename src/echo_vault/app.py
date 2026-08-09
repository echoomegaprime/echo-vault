"""FastAPI surface for ECHO Vault."""

import re
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import __version__
from .auth import Authenticator, ClientRegistry, Principal
from .config import Settings
from .crypto import KeyRing, VaultCryptoError
from .models import (
    AuditVerification,
    CreateSecret,
    DeleteSecret,
    MutationResult,
    SecretMetadata,
    SecretResult,
    UpdateSecret,
)
from .store import VaultConflictError, VaultNotFoundError, VaultStore

_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,126}[a-z0-9])?$")
_WEB_ROOT = Path(__file__).with_name("web")


def _validate_identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{label} must be lowercase and contain only letters, digits, dot, dash, or underscore",
        )
    return value


ScopeDependency = Callable[[Request], Coroutine[None, None, Principal]]


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        runtime_settings.validate()
        keyring = KeyRing.load(runtime_settings.keys_file)
        registry = ClientRegistry.load(runtime_settings.clients_file)
        store = VaultStore(
            runtime_settings.database_path,
            keyring,
            runtime_settings.audit_anchor_path,
        )
        await store.bootstrap()
        app.state.store = store
        app.state.authenticator = Authenticator(registry, runtime_settings)
        yield

    app = FastAPI(
        title="ECHO Vault",
        version=__version__,
        description="Self-hosted encrypted secrets management with scoped signed clients.",
        lifespan=lifespan,
        docs_url="/docs" if runtime_settings.environment != "production" else None,
        redoc_url=None,
    )

    def secure_response(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), clipboard-write=(self)"
        )
        if runtime_settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.middleware("http")
    async def secure_transport(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path.startswith("/v1"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError:
                    return secure_response(
                        JSONResponse({"detail": "invalid content length"}, status_code=400)
                    )
                if declared > runtime_settings.max_body_bytes:
                    return secure_response(
                        JSONResponse({"detail": "request body too large"}, status_code=413)
                    )
            body = await request.body()
            if len(body) > runtime_settings.max_body_bytes:
                return secure_response(
                    JSONResponse({"detail": "request body too large"}, status_code=413)
                )
            if request.url.path != "/v1/audit/verify":
                store: VaultStore = request.app.state.store
                checkpoint = await store.verify_audit_checkpoint()
                if not checkpoint["valid"]:
                    return secure_response(
                        JSONResponse(
                            {"detail": "audit integrity checkpoint failed"},
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        )
                    )
        response = await call_next(request)
        return secure_response(response)

    async def record_failed_operation(request: Request, outcome: str) -> None:
        principal = getattr(request.state, "vault_principal", None)
        store = getattr(request.app.state, "store", None)
        if principal is None or store is None:
            return
        try:
            route = request.scope.get("route")
            path_template = getattr(route, "path", "unmatched")
            await store.record_security_event(
                actor=principal.client_id,
                action="request.failed",
                outcome=outcome,
                details={
                    "method": request.method,
                    "path_template": path_template,
                },
            )
        except (OSError, RuntimeError, VaultCryptoError):
            return

    @app.exception_handler(VaultConflictError)
    async def conflict_handler(request: Request, exc: VaultConflictError) -> JSONResponse:
        await record_failed_operation(request, "conflict")
        return JSONResponse({"detail": str(exc)}, status_code=status.HTTP_409_CONFLICT)

    @app.exception_handler(VaultNotFoundError)
    async def not_found_handler(request: Request, __: VaultNotFoundError) -> JSONResponse:
        await record_failed_operation(request, "not_found")
        return JSONResponse({"detail": "resource not found"}, status_code=status.HTTP_404_NOT_FOUND)

    @app.exception_handler(VaultCryptoError)
    async def crypto_handler(_: Request, __: VaultCryptoError) -> JSONResponse:
        return JSONResponse(
            {"detail": "cryptographic verification failed"},
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    def require_scope(scope: str) -> ScopeDependency:
        async def dependency(request: Request) -> Principal:
            namespace_value = request.path_params.get("namespace")
            if namespace_value is None and scope == "read":
                namespace_value = request.query_params.get("namespace")
            namespace = str(namespace_value) if namespace_value is not None else None
            if namespace is not None:
                _validate_identifier(namespace, "namespace")
            store: VaultStore = request.app.state.store
            authenticator: Authenticator = request.app.state.authenticator
            principal = await authenticator.verify(request, store, scope=scope, namespace=namespace)
            request.state.vault_principal = principal
            return principal

        return dependency

    ReadPrincipal = Annotated[Principal, Depends(require_scope("read"))]
    WritePrincipal = Annotated[Principal, Depends(require_scope("write"))]
    DeletePrincipal = Annotated[Principal, Depends(require_scope("delete"))]
    AuditPrincipal = Annotated[Principal, Depends(require_scope("audit"))]
    AdminPrincipal = Annotated[Principal, Depends(require_scope("admin"))]

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> dict[str, str]:
        store: VaultStore = request.app.state.store
        ready = await store.ping()
        checkpoint = await store.verify_audit_checkpoint()
        if not ready or not checkpoint["valid"]:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "not ready")
        return {"status": "ready"}

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/console", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    @app.get("/console", include_in_schema=False, response_class=HTMLResponse)
    async def console() -> HTMLResponse:
        response = HTMLResponse((_WEB_ROOT / "console.html").read_text(encoding="utf-8"))
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/console/app.css", include_in_schema=False)
    async def console_css() -> Response:
        return Response(
            (_WEB_ROOT / "app.css").read_text(encoding="utf-8"),
            media_type="text/css",
        )

    @app.get("/console/app.js", include_in_schema=False)
    async def console_javascript() -> Response:
        return Response(
            (_WEB_ROOT / "app.js").read_text(encoding="utf-8"),
            media_type="text/javascript",
        )

    @app.post(
        "/v1/secrets/{namespace}/{name}",
        response_model=MutationResult,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_secret(
        namespace: str,
        name: str,
        body: CreateSecret,
        principal: WritePrincipal,
        request: Request,
    ) -> dict[str, object]:
        namespace = _validate_identifier(namespace, "namespace")
        name = _validate_identifier(name, "name")
        store: VaultStore = request.app.state.store
        payload = {"secret": body.secret, "username": body.username, "metadata": body.metadata}
        return await store.create(namespace, name, payload, body.tags, principal.client_id)

    @app.patch("/v1/secrets/{namespace}/{name}", response_model=MutationResult)
    async def update_secret(
        namespace: str,
        name: str,
        body: UpdateSecret,
        principal: WritePrincipal,
        request: Request,
    ) -> dict[str, object]:
        namespace = _validate_identifier(namespace, "namespace")
        name = _validate_identifier(name, "name")
        store: VaultStore = request.app.state.store
        payload = {"secret": body.secret, "username": body.username, "metadata": body.metadata}
        return await store.update(
            namespace,
            name,
            payload,
            body.tags,
            body.expected_version,
            principal.client_id,
        )

    @app.get("/v1/secrets/{namespace}/{name}", response_model=SecretResult)
    async def get_secret(
        namespace: str,
        name: str,
        principal: ReadPrincipal,
        request: Request,
    ) -> dict[str, object]:
        namespace = _validate_identifier(namespace, "namespace")
        name = _validate_identifier(name, "name")
        store: VaultStore = request.app.state.store
        return await store.get(namespace, name, principal.client_id)

    @app.get("/v1/secrets", response_model=list[SecretMetadata])
    async def list_secrets(
        namespace: str,
        principal: ReadPrincipal,
        request: Request,
    ) -> list[dict[str, object]]:
        namespace = _validate_identifier(namespace, "namespace")
        store: VaultStore = request.app.state.store
        return await store.list_metadata(namespace, principal.client_id)

    @app.get("/v1/secrets/{namespace}/{name}/versions")
    async def list_versions(
        namespace: str,
        name: str,
        principal: ReadPrincipal,
        request: Request,
    ) -> list[dict[str, object]]:
        namespace = _validate_identifier(namespace, "namespace")
        name = _validate_identifier(name, "name")
        store: VaultStore = request.app.state.store
        return await store.list_versions(namespace, name, principal.client_id)

    @app.delete("/v1/secrets/{namespace}/{name}")
    async def delete_secret(
        namespace: str,
        name: str,
        body: DeleteSecret,
        principal: DeletePrincipal,
        request: Request,
    ) -> dict[str, object]:
        namespace = _validate_identifier(namespace, "namespace")
        name = _validate_identifier(name, "name")
        store: VaultStore = request.app.state.store
        return await store.delete(namespace, name, body.expected_version, principal.client_id)

    @app.post("/v1/admin/rekey/{key_id}")
    async def rekey(
        key_id: str,
        principal: AdminPrincipal,
        request: Request,
    ) -> dict[str, object]:
        key_id = _validate_identifier(key_id, "key_id")
        store: VaultStore = request.app.state.store
        return await store.rekey_all(key_id, principal.client_id)

    @app.get("/v1/audit/verify", response_model=AuditVerification)
    async def verify_audit(_: AuditPrincipal, request: Request) -> dict[str, object]:
        store: VaultStore = request.app.state.store
        return await store.verify_audit_chain()

    return app


app = create_app()
