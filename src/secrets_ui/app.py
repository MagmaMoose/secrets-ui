"""The web app: sign-in routes, the JSON API the frontend calls, and the built frontend itself.

Every store call carries the signed-in person's own credential, and only for a store their
sign-in names. Writes need the session's CSRF token in X-CSRF-Token and this origin in
Origin, on top of the SameSite=Strict session cookie. Secret values travel only in request
and response bodies, never in a URL or a log line, and every API response is no-store.
"""

import hmac
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .config import Config
from .entra import Entra, EntraError
from .providers import CONTENT_TYPE, ENABLE, EXPIRY, RECOVER, Provider, ProviderError
from .providers.azure_keyvault import AzureKeyVault
from .session import Cookies, Sealer, TokenCache

log = logging.getLogger("secrets_ui")

LOGIN_SECONDS = 600
# The largest value any provider here takes: Azure Key Vault's 25 KB.
MAX_VALUE = 25 * 1024

CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


def _expiry(value: datetime | None) -> int | None:
    return None if value is None else int(value.timestamp())


class _Expiring(BaseModel):
    content_type: str | None = Field(default=None, max_length=255)
    expires: datetime | None = None

    @field_validator("expires")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires needs a time zone, such as 2027-01-31T00:00:00Z")
        return value


class NewVersion(_Expiring):
    value: str = Field(min_length=1, max_length=MAX_VALUE)


class NewSecret(NewVersion):
    name: str = Field(min_length=1, max_length=256)


class Attributes(_Expiring):
    enabled: bool | None = None


def _log(event: str, **fields: Any) -> None:
    log.info(json.dumps({"msg": event, **fields}))


def build_providers(cfg: Config, http: httpx.AsyncClient) -> dict[str, Provider]:
    providers: dict[str, Provider] = {}
    if cfg.azure_keyvault is not None:
        providers[AzureKeyVault.id] = AzureKeyVault(http, roles=cfg.azure_keyvault.roles, suffix=cfg.azure_keyvault.suffix)
    return providers


def create_app(cfg: Config, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    http = httpx.AsyncClient(transport=transport, follow_redirects=False)
    providers = build_providers(cfg, http)
    # Entra ID issues a token for one resource per request: the first provider that needs one
    # gets it at sign-in, the rest redeem the refresh token when they are first used.
    first = next((p for p in providers.values() if p.sign_in_scope), None)
    entra = Entra(cfg, http, scope=first.sign_in_scope if first else "")
    cookies = Cookies(Sealer(cfg.session_key), secure=cfg.secure_cookies)
    tokens = TokenCache()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await http.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        if cfg.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if path.startswith("/assets/"):
            # Vite names every asset by its content hash.
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path.startswith(("/api/", "/auth/")):
            response.headers["Cache-Control"] = "no-store"
        else:
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default echoes the submitted input back, which here could be a secret value.
        fields = [{"field": ".".join(str(p) for p in e.get("loc", ())[1:]), "message": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse({"error": "invalid_request", "message": "The request is not valid.", "fields": fields}, 422)

    @app.exception_handler(ProviderError)
    async def store_error(_: Request, exc: ProviderError) -> JSONResponse:
        status = exc.status if exc.status in (400, 403, 404, 409, 429) else 502
        return JSONResponse({"error": exc.code, "message": str(exc)}, status)

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, exc.status_code)

    # ── Sessions ──────────────────────────────────────────────────────────────────────

    def session(request: Request) -> dict[str, Any]:
        data = cookies.read_session(request)
        if data is None:
            raise HTTPException(401, "signed_out")
        return data

    Session = Annotated[dict[str, Any], Depends(session)]

    def writable(request: Request, data: Session) -> dict[str, Any]:
        origin = request.headers.get("origin", "").encode()
        token = request.headers.get("x-csrf-token", "").encode()
        if not hmac.compare_digest(origin, cfg.origin.encode()) or not hmac.compare_digest(token, str(data.get("csrf", "")).encode()):
            raise HTTPException(403, "csrf")
        return data

    Writable = Annotated[dict[str, Any], Depends(writable)]
    ProviderId = Annotated[str, Path(min_length=1, max_length=40)]
    StoreName = Annotated[str, Path(min_length=1, max_length=128)]
    SecretName = Annotated[str, Path(min_length=1, max_length=256)]

    def provider_for(provider: str, store: str, data: dict[str, Any]) -> Provider:
        found = providers.get(provider)
        if found is None:
            raise HTTPException(404, "unknown_provider")
        if store not in (data.get("stores") or {}).get(provider, []):
            raise HTTPException(403, "store_not_allowed")
        return found

    def require(found: Provider, feature: str) -> None:
        if feature not in found.features:
            raise HTTPException(400, f"{feature}_not_supported")

    async def credential(data: dict[str, Any], found: Provider, *, fresh: bool = False) -> str:
        key = f"{data['sid']}:{found.id}"
        token = None if fresh else tokens.get(key)
        if token is None:
            try:
                token, expires_at = await found.credential(entra, str(data["rt"]))
            except EntraError as err:
                _log("credential failed", user=data.get("oid"), provider=found.id, status=err.status, reason=str(err))
                signed_out = err.status == 401
                raise HTTPException(401 if signed_out else 502, "signed_out" if signed_out else "sign_in_unavailable") from err
            tokens.put(key, token, expires_at)
        return token

    async def call(data: dict[str, Any], found: Provider, operation, store: str, *args, **kwargs):
        """Run one store operation as the person; a 401 from the store gets one fresh credential."""
        try:
            return await operation(store, *args, await credential(data, found), **kwargs)
        except ProviderError as err:
            if err.status != 401:
                raise
        tokens.drop(f"{data['sid']}:{found.id}")
        try:
            return await operation(store, *args, await credential(data, found, fresh=True), **kwargs)
        except ProviderError as err:
            if err.status == 401:
                raise HTTPException(401, "signed_out") from err
            raise

    # ── Sign-in ───────────────────────────────────────────────────────────────────────

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/auth/login")
    async def login() -> Response:
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        response = RedirectResponse(entra.authorize_url(state=state, nonce=nonce, verifier=verifier), 302)
        cookies.write_login(response, {"state": state, "nonce": nonce, "verifier": verifier}, LOGIN_SECONDS)
        return response

    def _back(**query: str) -> Response:
        response = RedirectResponse("/" + (f"?{urlencode(query)}" if query else ""), 303)
        cookies.clear(response, cookies.login)
        return response

    @app.get("/auth/callback")
    async def callback(request: Request) -> Response:
        params = request.query_params
        if params.get("error"):
            reason = (params.get("error_description") or params["error"]).splitlines()[0][:300]
            _log("sign-in refused", reason=reason)
            return _back(auth_error=reason)
        flow = cookies.read_login(request)
        if flow is None or not hmac.compare_digest(params.get("state", "").encode(), str(flow.get("state", "")).encode()):
            return _back(auth_error="This sign-in expired or was not started here. Sign in again.")
        try:
            sign_in = await entra.redeem_code(code=params.get("code", ""), verifier=str(flow["verifier"]), nonce=str(flow["nonce"]))
        except EntraError as err:
            _log("sign-in failed", status=err.status, reason=str(err))
            return _back(auth_error=str(err))

        stores = {pid: list(p.stores(sign_in.roles)) for pid, p in providers.items()}
        sid = secrets.token_urlsafe(16)
        data = {
            "sid": sid,
            "rt": sign_in.refresh_token,
            "oid": sign_in.oid,
            "name": sign_in.name,
            "upn": sign_in.upn,
            "stores": stores,
            "csrf": secrets.token_urlsafe(32),
        }
        if first is not None and sign_in.access_token:
            tokens.put(f"{sid}:{first.id}", sign_in.access_token, sign_in.expires_at)
        response = _back()
        cookies.write_session(request, response, data, cfg.session_seconds)
        _log("signed in", user=sign_in.oid, stores={pid: len(names) for pid, names in stores.items()})
        return response

    @app.post("/auth/logout")
    async def logout(request: Request, data: Writable) -> Response:
        tokens.drop_session(str(data["sid"]))
        response = JSONResponse({"signed_out": True})
        cookies.clear_session(request, response)
        return response

    # ── API ───────────────────────────────────────────────────────────────────────────

    @app.get("/api/me")
    async def me(data: Session) -> dict[str, Any]:
        stores = data.get("stores") or {}
        return {
            "name": data.get("name", ""),
            "upn": data.get("upn", ""),
            "csrf": data.get("csrf", ""),
            "expires": data.get("exp"),
            "version": cfg.version,
            "providers": [p.describe() for p in providers.values()],
            "stores": [
                {"provider": pid, "name": name, "location": providers[pid].location(name)}
                for pid in providers
                for name in stores.get(pid, [])
            ],
        }

    base = "/api/stores/{provider}/{store}"

    @app.get(f"{base}/secrets")
    async def list_secrets(provider: ProviderId, store: StoreName, data: Session) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        return {"secrets": await call(data, found, found.list_secrets, store)}

    @app.get(f"{base}/deleted")
    async def list_deleted(provider: ProviderId, store: StoreName, data: Session) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        require(found, RECOVER)
        return {"secrets": await call(data, found, found.list_deleted, store)}

    def _check_fields(found: Provider, body: _Expiring) -> None:
        if body.expires is not None:
            require(found, EXPIRY)
        if body.content_type:
            require(found, CONTENT_TYPE)

    @app.post(f"{base}/secrets", status_code=201)
    async def create(provider: ProviderId, store: StoreName, body: NewSecret, data: Writable) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        _check_fields(found, body)
        if await call(data, found, found.exists, store, body.name):
            raise HTTPException(409, "exists")
        await call(data, found, found.set_secret, store, body.name, value=body.value, content_type=body.content_type, expires=_expiry(body.expires))
        _log("secret created", user=data.get("oid"), provider=provider, store=store, secret=body.name)
        return {"name": body.name}

    @app.post(f"{base}/secrets/{{name}}/versions", status_code=201)
    async def new_version(provider: ProviderId, store: StoreName, name: SecretName, body: NewVersion, data: Writable) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        _check_fields(found, body)
        await call(data, found, found.set_secret, store, name, value=body.value, content_type=body.content_type, expires=_expiry(body.expires))
        _log("secret version added", user=data.get("oid"), provider=provider, store=store, secret=name)
        return {"name": name}

    @app.patch(f"{base}/secrets/{{name}}")
    async def update(provider: ProviderId, store: StoreName, name: SecretName, body: Attributes, data: Writable) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        changes: dict[str, Any] = {}
        if "enabled" in body.model_fields_set and body.enabled is not None:
            require(found, ENABLE)
            changes["enabled"] = body.enabled
        if "expires" in body.model_fields_set:
            require(found, EXPIRY)
            changes["expires"] = _expiry(body.expires)
        if "content_type" in body.model_fields_set:
            require(found, CONTENT_TYPE)
            changes["content_type"] = body.content_type
        if not changes:
            raise HTTPException(400, "nothing_to_change")
        item = await call(data, found, found.update, store, name, **changes)
        _log("secret updated", user=data.get("oid"), provider=provider, store=store, secret=name, fields=sorted(changes))
        return {"secret": item}

    @app.delete(f"{base}/secrets/{{name}}")
    async def delete(provider: ProviderId, store: StoreName, name: SecretName, data: Writable) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        await call(data, found, found.delete, store, name)
        _log("secret deleted", user=data.get("oid"), provider=provider, store=store, secret=name)
        return {"name": name}

    @app.post(f"{base}/deleted/{{name}}/recover")
    async def recover(provider: ProviderId, store: StoreName, name: SecretName, data: Writable) -> dict[str, Any]:
        found = provider_for(provider, store, data)
        require(found, RECOVER)
        await call(data, found, found.recover, store, name)
        _log("secret recovered", user=data.get("oid"), provider=provider, store=store, secret=name)
        return {"name": name}

    @app.post(f"{base}/secrets/{{name}}/reveal")
    async def reveal(provider: ProviderId, store: StoreName, name: SecretName, data: Writable) -> dict[str, Any]:
        # POST, not GET: a value never sits in a URL, a history entry or a prefetch.
        found = provider_for(provider, store, data)
        value = await call(data, found, found.get_value, store, name)
        _log("secret revealed", user=data.get("oid"), provider=provider, store=store, secret=name)
        return {"value": value}

    if cfg.static_dir is not None:
        app.mount("/", StaticFiles(directory=cfg.static_dir, html=True), name="frontend")

    return app
