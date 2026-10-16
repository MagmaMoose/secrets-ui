"""Signing in with Entra ID, as a confidential client (the flow itself is in oidc.py).

The app's credential is a workload identity token (AZURE_FEDERATED_TOKEN_FILE, which Entra
trusts through a federated credential on the app registration) or a client secret. The
sign-in asks for delegated access only (for Azure Key Vault, `user_impersonation`), so every
store call runs as the person, the store's own access control decides what they may do, and
its audit log names them. A person's roles are the app roles in their ID token.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .config import Config
from .oidc import OIDC, SignIn, SignInError

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class Entra(OIDC):
    name = "Microsoft"
    refresh_scope = "openid profile offline_access"

    def __init__(self, cfg: Config, http: httpx.AsyncClient, *, scope: str = ""):
        # The one resource scope asked for at sign-in (Entra ID issues a token for one resource
        # per request); other resources are reached later through the refresh token.
        base = f"{cfg.authority}/{cfg.tenant_id}"
        super().__init__(
            http,
            client_id=cfg.client_id,
            redirect_uri=cfg.redirect_uri,
            scope=" ".join(["openid", "profile", "offline_access", *([scope] if scope else [])]),
            endpoints={"authorize": f"{base}/oauth2/v2.0/authorize", "token": f"{base}/oauth2/v2.0/token", "jwks": f"{base}/discovery/v2.0/keys"},
            issuers=(f"{base}/v2.0",),
        )
        self._cfg = cfg
        self._resource = bool(scope)

    def _credential(self) -> dict[str, str]:
        if self._cfg.federated_token_file is None:
            return {"client_secret": self._cfg.client_secret or ""}
        try:
            # Read on every use: the kubelet rotates the projected token in place.
            assertion = self._cfg.federated_token_file.read_text().strip()
        except OSError as err:
            raise SignInError(f"cannot read the workload identity token: {err.__class__.__name__}", status=500) from err
        return {"client_assertion_type": _ASSERTION_TYPE, "client_assertion": assertion}

    def _check_claims(self, claims: dict[str, Any]) -> None:
        if str(claims.get("tid", "")).lower() != self._cfg.tenant_id or not claims.get("oid"):
            raise SignInError("that account belongs to another tenant", status=401)

    async def _sign_in(self, body: dict[str, Any], claims: dict[str, Any]) -> SignIn:
        if not body.get("refresh_token") or (self._resource and not body.get("access_token")):
            raise SignInError("Microsoft returned no refresh or access token; has the app been granted offline_access and the store's scope?")
        return SignIn(
            oid=str(claims["oid"]).lower(),
            name=str(claims.get("name") or "")[:120],
            upn=str(claims.get("preferred_username") or "")[:120],
            roles=claims.get("roles") or [],
            access_token=str(body.get("access_token") or ""),
            expires_at=time.time() + int(body.get("expires_in") or 3600),
            refresh_token=str(body["refresh_token"]),
        )
