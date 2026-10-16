"""Signing in with Google, as a confidential client (the flow itself is in oidc.py), for accounts
in the operator's Workspace domains only: the ID token's verified `hd` claim decides.

A person's roles are the Google Groups they are a direct member of, read once at sign-in from
the Cloud Identity API with their own token (scope cloud-identity.groups.readonly), so the app
needs no directory access of its own. A group in one of the domains counts as the role named by
its local part: team-a-vault-dev@example.com names the store team-a-vault-dev.

Google hands out a refresh token only when the person consents, so every sign-in asks.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .config import Config
from .oidc import OIDC, SignIn, SignInError

GROUPS_SCOPE = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
_GROUPS = "https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups"
_MAX_PAGES = 20


class Google(OIDC):
    name = "Google"

    def __init__(self, cfg: Config, http: httpx.AsyncClient):
        super().__init__(
            http,
            client_id=cfg.client_id,
            redirect_uri=cfg.redirect_uri,
            scope=f"openid email profile {GROUPS_SCOPE}",
            endpoints={
                "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
                "token": "https://oauth2.googleapis.com/token",  # nosec B105
                "jwks": "https://www.googleapis.com/oauth2/v3/certs",
            },
            issuers=("https://accounts.google.com", "accounts.google.com"),
        )
        self._secret = cfg.client_secret or ""
        self._domains = cfg.google_domains

    def _authorize_extra(self) -> dict[str, str]:
        extra = {"access_type": "offline", "prompt": "consent"}
        if len(self._domains) == 1:
            # Only a hint for the account chooser; the hd claim is what is checked.
            extra["hd"] = self._domains[0]
        return extra

    def _credential(self) -> dict[str, str]:
        return {"client_secret": self._secret}

    def _check_claims(self, claims: dict[str, Any]) -> None:
        if claims.get("hd") not in self._domains or claims.get("email_verified") is not True or not claims.get("sub"):
            raise SignInError("that account is not in this organisation's Google Workspace", status=401)

    async def _sign_in(self, body: dict[str, Any], claims: dict[str, Any]) -> SignIn:
        if not body.get("refresh_token") or not body.get("access_token"):
            raise SignInError("Google returned no refresh or access token; the sign-in has to ask for consent and offline access")
        email = str(claims.get("email") or "")
        return SignIn(
            oid=str(claims["sub"]),
            name=str(claims.get("name") or "")[:120],
            upn=email[:120],
            roles=await self._groups(email, str(body["access_token"])),
            access_token=str(body["access_token"]),
            expires_at=time.time() + int(body.get("expires_in") or 3600),
            refresh_token=str(body["refresh_token"]),
        )

    async def _groups(self, email: str, token: str) -> list[str]:
        """The local parts of the person's direct groups in the Workspace domains."""
        member = email.replace("\\", "\\\\").replace("'", "\\'")
        roles: list[str] = []
        page = ""
        for _ in range(_MAX_PAGES):
            params = {"query": f"member_key_id == '{member}'", **({"pageToken": page} if page else {})}
            try:
                response = await self._http.get(_GROUPS, params=params, headers={"Authorization": f"Bearer {token}"}, timeout=15)
                body = response.json()
            except (httpx.HTTPError, ValueError) as err:
                raise SignInError(f"cannot read your Google groups: {err.__class__.__name__}") from err
            if response.status_code != 200 or not isinstance(body, dict):
                error = body.get("error") if isinstance(body, dict) else None
                message = error.get("message") if isinstance(error, dict) else f"HTTP {response.status_code}"
                raise SignInError(f"cannot read your Google groups: {str(message)[:300]}")
            for membership in body.get("memberships") or []:
                local, _, domain = str((membership.get("groupKey") or {}).get("id") or "").lower().partition("@")
                if local and domain in self._domains:
                    roles.append(local)
            page = str(body.get("nextPageToken") or "")
            if not page:
                break
        return roles
