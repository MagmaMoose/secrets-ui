"""Signing in with Entra ID: authorization code flow with PKCE, as a confidential client.

The app's credential is a workload identity token (AZURE_FEDERATED_TOKEN_FILE, which Entra
trusts through a federated credential on the app registration) or a client secret. The
sign-in asks for delegated access only (for Azure Key Vault, `user_impersonation`), so every
store call runs as the person, the store's own access control decides what they may do, and
its audit log names them. The refresh token stays with the person's session; each provider
redeems it for the token it needs.

The ID token is verified against the tenant's published keys although it arrives straight
from the token endpoint over TLS (OIDC Core 3.1.3.7 would allow skipping that): issuer,
audience, expiry, nonce, tenant and object id all have to hold.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from .config import Config

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_JWKS_TTL = 3600.0
_JWKS_COOLDOWN = 30.0


class EntraError(Exception):
    def __init__(self, message: str, *, status: int = 502):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class SignIn:
    oid: str
    name: str
    upn: str
    roles: list[Any]
    access_token: str
    expires_at: float
    refresh_token: str


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _reason(body: Any) -> str:
    """Entra's own reason, trimmed to the AADSTS line a person can search for."""
    if not isinstance(body, dict):
        return "unknown error"
    return str(body.get("error_description") or body.get("error") or "unknown error").splitlines()[0][:300]


class Entra:
    def __init__(self, cfg: Config, http: httpx.AsyncClient, *, scope: str = ""):
        self._cfg = cfg
        self._http = http
        # The one resource scope asked for at sign-in (Entra ID issues a token for one resource
        # per request); other resources are reached later through the refresh token.
        self._scope = " ".join(["openid", "profile", "offline_access", *([scope] if scope else [])])
        self._resource = bool(scope)
        base = f"{cfg.authority}/{cfg.tenant_id}"
        self._authorize = f"{base}/oauth2/v2.0/authorize"
        self._token = f"{base}/oauth2/v2.0/token"
        self._jwks_url = f"{base}/discovery/v2.0/keys"
        self._issuer = f"{base}/v2.0"
        self._keys: dict[str, jwt.PyJWK] = {}
        self._keys_at = float("-inf")

    def authorize_url(self, *, state: str, nonce: str, verifier: str) -> str:
        query = {
            "client_id": self._cfg.client_id,
            "response_type": "code",
            "response_mode": "query",
            "redirect_uri": self._cfg.redirect_uri,
            "scope": self._scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        return f"{self._authorize}?{urlencode(query)}"

    def _credential(self) -> dict[str, str]:
        if self._cfg.federated_token_file is None:
            return {"client_secret": self._cfg.client_secret or ""}
        try:
            # Read on every use: the kubelet rotates the projected token in place.
            assertion = self._cfg.federated_token_file.read_text().strip()
        except OSError as err:
            raise EntraError(f"cannot read the workload identity token: {err.__class__.__name__}", status=500) from err
        return {"client_assertion_type": _ASSERTION_TYPE, "client_assertion": assertion}

    async def _redeem(self, fields: dict[str, str]) -> dict[str, Any]:
        data = {**fields, "client_id": self._cfg.client_id, **self._credential()}
        try:
            response = await self._http.post(self._token, data=data, headers={"Accept": "application/json"}, timeout=15)
        except httpx.HTTPError as err:
            raise EntraError(f"cannot reach Microsoft sign-in: {err.__class__.__name__}") from err
        try:
            body = response.json()
        except ValueError as err:
            raise EntraError(f"Microsoft sign-in answered HTTP {response.status_code} without JSON") from err
        if response.status_code != 200 or not isinstance(body, dict):
            grant = isinstance(body, dict) and body.get("error") in ("invalid_grant", "interaction_required")
            raise EntraError(f"Microsoft refused the sign-in: {_reason(body)}", status=401 if grant else 502)
        return body

    async def redeem_code(self, *, code: str, verifier: str, nonce: str) -> SignIn:
        body = await self._redeem(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._cfg.redirect_uri,
                "code_verifier": verifier,
                "scope": self._scope,
            }
        )
        claims = await self.verify_id_token(str(body.get("id_token") or ""), nonce=nonce)
        if not body.get("refresh_token") or (self._resource and not body.get("access_token")):
            raise EntraError("Microsoft returned no refresh or access token; has the app been granted offline_access and the store's scope?")
        return SignIn(
            oid=str(claims["oid"]).lower(),
            name=str(claims.get("name") or "")[:120],
            upn=str(claims.get("preferred_username") or "")[:120],
            roles=claims.get("roles") or [],
            access_token=str(body.get("access_token") or ""),
            expires_at=time.time() + int(body.get("expires_in") or 3600),
            refresh_token=str(body["refresh_token"]),
        )

    async def refresh(self, refresh_token: str, *, scope: str) -> tuple[str, float]:
        """A fresh access token for `scope` from a session's refresh token, and when it expires."""
        body = await self._redeem({"grant_type": "refresh_token", "refresh_token": refresh_token, "scope": f"offline_access {scope}"})
        if not body.get("access_token"):
            raise EntraError("Microsoft returned no access token", status=401)
        return str(body["access_token"]), time.time() + int(body.get("expires_in") or 3600)

    async def id_token(self, refresh_token: str) -> tuple[str, float]:
        """A fresh ID token from a session's refresh token, for a store that signs people in with it
        (HashiCorp Vault's JWT auth): audience this app, the person's roles in it."""
        body = await self._redeem({"grant_type": "refresh_token", "refresh_token": refresh_token, "scope": "openid profile offline_access"})
        if not body.get("id_token"):
            raise EntraError("Microsoft returned no ID token", status=401)
        return str(body["id_token"]), time.time() + int(body.get("expires_in") or 3600)

    async def _signing_key(self, kid: str) -> jwt.PyJWK:
        now = time.monotonic()
        stale = now - self._keys_at > _JWKS_TTL
        unknown = kid not in self._keys and now - self._keys_at > _JWKS_COOLDOWN
        if stale or unknown:
            try:
                response = await self._http.get(self._jwks_url, timeout=15)
                response.raise_for_status()
                keys = {}
                for data in response.json().get("keys", []):
                    try:
                        keys[str(data.get("kid"))] = jwt.PyJWK(data)
                    except jwt.PyJWKError:
                        continue
                self._keys, self._keys_at = keys, now
            except (httpx.HTTPError, ValueError, AttributeError) as err:
                raise EntraError(f"cannot read the tenant's signing keys: {err.__class__.__name__}") from err
        if kid not in self._keys:
            raise EntraError("the ID token is signed with a key the tenant does not publish", status=401)
        return self._keys[kid]

    async def verify_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        try:
            kid = str(jwt.get_unverified_header(id_token).get("kid") or "")
            key = await self._signing_key(kid)
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=["RS256"],
                audience=self._cfg.client_id,
                issuer=self._issuer,
                leeway=60,
                options={"require": ["exp", "iat", "iss", "aud", "nonce"]},
            )
        except jwt.PyJWTError as err:
            raise EntraError(f"the ID token did not verify: {err.__class__.__name__}", status=401) from err
        if not hmac.compare_digest(str(claims.get("nonce")).encode(), nonce.encode()):
            raise EntraError("the ID token belongs to another sign-in", status=401)
        if str(claims.get("tid", "")).lower() != self._cfg.tenant_id or not claims.get("oid"):
            raise EntraError("that account belongs to another tenant", status=401)
        return claims
