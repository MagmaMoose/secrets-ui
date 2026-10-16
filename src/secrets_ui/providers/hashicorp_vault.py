"""HashiCorp Vault: KV v2 secrets over the HTTP API, with a Vault token issued to the person.

The person's credential is their own Vault token. The app presents a fresh Entra ID token (aud:
this app, roles: their app roles) to Vault's JWT auth method, and Vault issues a token with the
policies its role and the person's groups give. Vault's policies decide what they may do, and its
audit log names them.

A store is a folder in a KV v2 mount, named by the operator; a person sees one when an app role
on their sign-in is its name. Its secrets are every key under that folder, sub-folders included,
by their path relative to it.

A KV v2 secret is a JSON object of keys and values, so a value here is that object as JSON text.
Values pass through here and nowhere else; write responses are read for errors only.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from . import RECOVER, VERSIONS, Provider, ProviderError

if TYPE_CHECKING:
    from ..entra import Entra

# A path segment Vault and a URL agree on; "." and ".." would walk out of the store's folder.
_SEGMENT = r"(?!\.\.?(?:/|$))[A-Za-z0-9._-]{1,128}"
PATH_RULE = rf"^{_SEGMENT}(?:/{_SEGMENT}){{0,15}}$"
_VERSION = re.compile(r"^[1-9][0-9]{0,9}$")
_FOLDERS = 200  # LIST calls per listing
_SECRETS = 1000
_PARALLEL = 8
_CODES = {400: "BadRequest", 403: "PermissionDenied", 404: "NotFound", 409: "Conflict", 429: "TooManyRequests"}


@dataclass(frozen=True)
class VaultStore:
    mount: str
    path: str = ""


def _epoch(value: Any) -> int | None:
    """Vault's RFC 3339 times, to the second; empty and unset are None."""
    try:
        return int(datetime.fromisoformat(str(value)[:19]).replace(tzinfo=UTC).timestamp())
    except ValueError:
        return None


def _deleted(version: dict[str, Any], now: float) -> int | None:
    # A deletion_time in the future is delete_version_after scheduling one, not a deletion.
    deleted = _epoch(version.get("deletion_time"))
    return deleted if deleted is not None and deleted <= now else None


class HashiCorpVault(Provider):
    id = "hashicorp-vault"
    label = "HashiCorp Vault"
    features = frozenset({RECOVER, VERSIONS})
    name_pattern = PATH_RULE
    name_hint = "Letters, digits, dots, hyphens and underscores; a / makes a folder."
    value_hint = 'A JSON object of keys and values, such as {"password": "…"}. Stored as a new version.'

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        address: str,
        auth_mount: str,
        auth_role: str,
        stores: dict[str, VaultStore],
        labels: dict[str, str] | None = None,
    ):
        super().__init__(labels)
        self._http = http
        self._address = address
        self._auth_mount = auth_mount
        self._auth_role = auth_role
        self._stores = dict(stores)

    async def credential(self, entra: Entra, refresh_token: str) -> tuple[str, float]:
        id_token, _ = await entra.id_token(refresh_token)
        body = await self._call("POST", self._api("auth", *self._auth_mount.split("/"), "login"), "", json={"role": self._auth_role, "jwt": id_token})
        auth = body.get("auth") or {}
        if not auth.get("client_token"):
            raise ProviderError(502, "NoToken", "Vault signed the person in but returned no token")
        return str(auth["client_token"]), time.time() + int(auth.get("lease_duration") or 3600)

    def stores(self, roles: Any) -> tuple[str, ...]:
        if not isinstance(roles, list):
            return ()
        return tuple(name for name in self._stores if name in roles)

    def location(self, store: str) -> str:
        s = self._stores[store]
        return f"{s.mount}/{s.path}".rstrip("/") + f" on {self._address}"

    def _check(self, name: str) -> None:
        if not re.fullmatch(PATH_RULE, name):
            raise ProviderError(400, "invalid_name", f"Not a secret path this UI takes. {self.name_hint}")

    def _api(self, *segments: str) -> str:
        return f"{self._address}/v1/" + "/".join(quote(s, safe="") for s in segments if s)

    def _kv(self, store: str, kind: str, name: str = "") -> str:
        """The URL of a secret (or folder) in a store, for one of KV v2's data, metadata or undelete."""
        s = self._stores[store]
        return self._api(*s.mount.split("/"), kind, *s.path.split("/"), *name.split("/"))

    async def _call(self, method: str, url: str, token: str, *, json: Any = None, params: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json", **({"X-Vault-Token": token} if token else {})}
        try:
            response = await self._http.request(method, url, json=json, params=params, headers=headers, timeout=20)
        except httpx.HTTPError as err:
            raise ProviderError(502, "Unreachable", f"cannot reach Vault: {err.__class__.__name__}") from err
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        if response.status_code >= 400:
            message = " ".join("; ".join(str(e) for e in body.get("errors") or [] if e).split())[:500]
            # An expired or revoked token is a 403 too; a 401 makes the app sign in to Vault again.
            status = 401 if response.status_code == 403 and "invalid token" in message else response.status_code
            raise ProviderError(status, _CODES.get(status, "VaultError"), message or f"Vault answered HTTP {response.status_code}")
        return body

    async def _metadata(self, store: str, name: str, token: str) -> dict[str, Any]:
        return (await self._call("GET", self._kv(store, "metadata", name), token)).get("data") or {}

    async def _keys(self, store: str, token: str) -> list[str]:
        """Every secret under the store's folder, by its path relative to it."""
        keys: list[str] = []
        folders = [""]
        for _ in range(_FOLDERS):
            folder = folders.pop(0)
            try:
                # A folder ends in a slash, as the vault CLI lists it, so a policy on folder/* covers it.
                body = await self._call("GET", self._kv(store, "metadata", folder) + "/", token, params={"list": "true"})
            except ProviderError as err:
                if err.status != 404:  # 404: an empty folder
                    raise
                body = {}
            for key in (body.get("data") or {}).get("keys") or []:
                if isinstance(key, str) and key:
                    (folders if key.endswith("/") else keys).append(folder + key)
            if len(keys) > _SECRETS:
                break
            if not folders:
                return keys
        raise ProviderError(502, "TooManySecrets", f"more than {_SECRETS} secrets or {_FOLDERS} folders here; point the store at a smaller folder")

    async def _items(self, store: str, token: str) -> list[dict[str, Any]]:
        names = await self._keys(store, token)
        limit = asyncio.Semaphore(_PARALLEL)

        async def one(name: str) -> dict[str, Any] | None:
            async with limit:
                try:
                    return {"name": name, **await self._metadata(store, name, token)}
                except ProviderError as err:
                    if err.status == 404:  # gone since the listing
                        return None
                    raise

        found = await asyncio.gather(*(one(n) for n in names), return_exceptions=True)
        for result in found:
            if isinstance(result, BaseException):
                raise result
        now = time.time()
        items = []
        for meta in found:
            if not isinstance(meta, dict):
                continue
            current = (meta.get("versions") or {}).get(str(meta.get("current_version"))) or {}
            items.append(
                {
                    "name": meta["name"],
                    "enabled": True,
                    "expires": None,
                    "created": _epoch(meta.get("created_time")),
                    "updated": _epoch(meta.get("updated_time")),
                    "content_type": None,
                    "managed": False,
                    "recoverable_days": None,
                    "deleted": _deleted(current, now),
                    "destroyed": bool(current.get("destroyed")),
                }
            )
        return sorted(items, key=lambda s: s["name"].lower())

    async def list_secrets(self, store: str, token: str) -> list[dict[str, Any]]:
        return [i for i in await self._items(store, token) if i["deleted"] is None and not i["destroyed"]]

    async def list_deleted(self, store: str, token: str) -> list[dict[str, Any]]:
        # A destroyed current version cannot come back, so it is not offered for recovery.
        return [{**i, "purge_at": None} for i in await self._items(store, token) if i["deleted"] is not None and not i["destroyed"]]

    async def get_value(self, store: str, name: str, token: str, version: str = "") -> str:
        self._check(name)
        if version and not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not a Vault secret version.")
        body = await self._call("GET", self._kv(store, "data", name), token, params={"version": version} if version else None)
        data = (body.get("data") or {}).get("data")
        if not isinstance(data, dict):
            raise ProviderError(404, "NotFound", "This version holds no data: it is deleted or destroyed.")
        return json.dumps(data, indent=2, ensure_ascii=False)

    async def exists(self, store: str, name: str, token: str) -> bool:
        self._check(name)
        try:
            await self._metadata(store, name, token)
        except ProviderError as err:
            if err.status == 404:
                return False
            raise
        return True

    async def set_secret(
        self, store: str, name: str, token: str, *, value: str, content_type: str | None, expires: int | None
    ) -> None:
        self._check(name)
        try:
            data = json.loads(value)
        except ValueError:
            data = None
        if not isinstance(data, dict) or not data:
            raise ProviderError(400, "invalid_value", f"Not a JSON object. {self.value_hint}")
        await self._call("POST", self._kv(store, "data", name), token, json={"data": data})

    async def update(self, store: str, name: str, token: str, **changes: Any) -> dict[str, Any]:
        raise ProviderError(400, "not_supported", "A Vault secret has no attributes to change here.")

    async def delete(self, store: str, name: str, token: str) -> None:
        """Deletes the current version, which `vault kv undelete` (or Recover) brings back."""
        self._check(name)
        await self._call("DELETE", self._kv(store, "data", name), token)

    async def recover(self, store: str, name: str, token: str) -> None:
        self._check(name)
        current = (await self._metadata(store, name, token)).get("current_version")
        await self._call("POST", self._kv(store, "undelete", name), token, json={"versions": [current]})

    async def restore(self, store: str, name: str, version: str, token: str) -> None:
        """What `vault kv rollback` does: the old data as a new version, refused if another write
        came first."""
        self._check(name)
        if not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not a Vault secret version.")
        body = await self._call("GET", self._kv(store, "data", name), token, params={"version": version})
        data = (body.get("data") or {}).get("data")
        if not isinstance(data, dict):
            raise ProviderError(404, "NotFound", "This version holds no data: it is deleted or destroyed.")
        current = (await self._metadata(store, name, token)).get("current_version")
        await self._call("POST", self._kv(store, "data", name), token, json={"data": data, "options": {"cas": current}})

    async def list_versions(self, store: str, name: str, token: str) -> list[dict[str, Any]]:
        self._check(name)
        meta = await self._metadata(store, name, token)
        now = time.time()
        versions = []
        for number, version in (meta.get("versions") or {}).items():
            if not isinstance(version, dict) or not str(number).isdigit():
                continue
            state = "destroyed" if version.get("destroyed") else "deleted" if _deleted(version, now) else "enabled"
            versions.append(
                {
                    "version": str(number),
                    "created": _epoch(version.get("created_time")),
                    "updated": None,
                    "expires": None,
                    "state": state,
                    "current": str(number) == str(meta.get("current_version")),
                }
            )
        return sorted(versions, key=lambda v: int(v["version"]), reverse=True)
