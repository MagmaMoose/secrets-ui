"""Signed-in state, sealed into cookies with AES-256-GCM. The server keeps no session store.

Any replica can serve any request and a restart signs nobody out. The cookie carries the
refresh token, never an access token: an Azure access token lists the person's group ids and
outgrows a cookie. The refresh token is useless outside this app, because redeeming it takes
the app's own credential. Store credentials stay in each replica's memory (TokenCache).
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections import OrderedDict
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from starlette.responses import Response

# Browsers drop a cookie over 4096 bytes without a word, which shows up as a sign-in loop.
_CHUNK = 3800
_MAX_CHUNKS = 6


class Sealer:
    def __init__(self, key: bytes):
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"secrets-ui cookie v1").derive(key)
        self._aead = AESGCM(derived)

    def seal(self, purpose: str, data: dict[str, Any], ttl: int) -> str:
        body = json.dumps({**data, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        sealed = nonce + self._aead.encrypt(nonce, body, purpose.encode())
        return base64.urlsafe_b64encode(sealed).rstrip(b"=").decode()

    def open(self, purpose: str, token: str) -> dict[str, Any] | None:
        """The data, or None for anything forged, altered, sealed for another purpose or expired."""
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            body = json.loads(self._aead.decrypt(raw[:12], raw[12:], purpose.encode()))
        except (ValueError, TypeError, InvalidTag):
            return None
        if not isinstance(body, dict) or not isinstance(body.get("exp"), int) or body["exp"] <= time.time():
            return None
        return body


class Cookies:
    """Cookie names and attributes. `__Host-` pins a cookie to this exact host, https and path /."""

    def __init__(self, sealer: Sealer, secure: bool):
        self._sealer = sealer
        self._secure = secure
        prefix = "__Host-" if secure else ""
        self.session = f"{prefix}secrets-ui"
        self.login = f"{prefix}secrets-ui-login"

    def _set(self, response: Response, name: str, value: str, max_age: int, samesite: str) -> None:
        response.set_cookie(name, value, max_age=max_age, path="/", secure=self._secure, httponly=True, samesite=samesite)  # type: ignore[arg-type]

    def read_session(self, request: Request) -> dict[str, Any] | None:
        parts = []
        for i in range(_MAX_CHUNKS):
            part = request.cookies.get(f"{self.session}.{i}")
            if part is None:
                break
            parts.append(part)
        return self._sealer.open("session", "".join(parts)) if parts else None

    def write_session(self, request: Request, response: Response, data: dict[str, Any], ttl: int) -> None:
        token = self._sealer.seal("session", data, ttl)
        chunks = [token[i : i + _CHUNK] for i in range(0, len(token), _CHUNK)]
        if len(chunks) > _MAX_CHUNKS:
            raise ValueError("the session does not fit in cookies")
        for i, chunk in enumerate(chunks):
            # Strict: no other site can make the browser send it, which is half the CSRF defence.
            self._set(response, f"{self.session}.{i}", chunk, ttl, "strict")
        for i in range(len(chunks), _MAX_CHUNKS):
            if f"{self.session}.{i}" in request.cookies:
                self.clear(response, f"{self.session}.{i}")

    def clear_session(self, request: Request, response: Response) -> None:
        for i in range(_MAX_CHUNKS):
            if f"{self.session}.{i}" in request.cookies:
                self.clear(response, f"{self.session}.{i}")

    def read_login(self, request: Request) -> dict[str, Any] | None:
        return self._sealer.open("login", request.cookies.get(self.login, ""))

    def write_login(self, response: Response, data: dict[str, Any], ttl: int) -> None:
        # Lax, not strict: it has to come back on the top-level redirect from Microsoft.
        self._set(response, self.login, self._sealer.seal("login", data, ttl), ttl, "lax")

    def clear(self, response: Response, name: str) -> None:
        response.delete_cookie(name, path="/", secure=self._secure, httponly=True, samesite="lax")


class TokenCache:
    """Store credentials by session and provider, in this replica's memory only."""

    def __init__(self, size: int = 5000, margin: int = 120):
        self._tokens: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._size = size
        self._margin = margin

    def get(self, key: str) -> str | None:
        entry = self._tokens.get(key)
        if entry is None or entry[1] - self._margin <= time.time():
            self._tokens.pop(key, None)
            return None
        self._tokens.move_to_end(key)
        return entry[0]

    def put(self, key: str, token: str, expires_at: float) -> None:
        self._tokens[key] = (token, expires_at)
        self._tokens.move_to_end(key)
        while len(self._tokens) > self._size:
            self._tokens.popitem(last=False)

    def drop(self, key: str) -> None:
        self._tokens.pop(key, None)

    def drop_session(self, sid: str) -> None:
        for key in [k for k in self._tokens if k.startswith(f"{sid}:")]:
            del self._tokens[key]
