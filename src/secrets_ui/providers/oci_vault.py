"""OCI Vault: secrets over the OCI REST APIs, signed with a session token issued to the person.

The person's credential is an OCI user principal session token (UPST). The app presents a fresh
ID token from the sign-in (Entra ID or Google) to the OCI identity domain's token exchange, which
an Identity Propagation Trust maps to the person's own OCI user, so OCI's IAM policies decide
what they may do and its audit log names them. The token is bound to a key pair this replica
makes at startup and keeps in memory; every call is signed with it (keyId ST$<token>).

A store is one vault in one compartment, named by the operator; a person sees it when an app role
or group on their sign-in is its name. New secrets are encrypted with the store's master key.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..examples import env_key
from . import RECOVER, VERSIONS, Provider, ProviderError

if TYPE_CHECKING:
    from ..oidc import OIDC

_NAME_RULE = r"^[A-Za-z0-9._-]{1,255}$"
_VERSION = re.compile(r"^[1-9][0-9]{0,9}$")
_MAX_PAGES = 20
_GONE = {"PENDING_DELETION", "SCHEDULING_DELETION", "DELETING", "DELETED"}
# The token exchange's fixed fields (RFC 8693 names, not credentials).
_EXCHANGE = {
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "requested_token_type": "urn:oci:token-type:oci-upst",  # nosec B105
    "subject_token_type": "jwt",  # nosec B105
}


@dataclass(frozen=True)
class OciStore:
    compartment: str
    vault: str
    # The master encryption key new secrets in this vault are created with.
    key: str


def _epoch(value: Any) -> int | None:
    try:
        return int(datetime.fromisoformat(str(value)[:19]).replace(tzinfo=UTC).timestamp())
    except ValueError:
        return None


def sign(request: httpx.Request, key_id: str, key: rsa.RSAPrivateKey) -> None:
    """OCI's request signature: date, (request-target) and host, plus the body headers on a write."""
    request.headers["date"] = email.utils.formatdate(usegmt=True)
    names = ["date", "(request-target)", "host"]
    if request.method in ("POST", "PUT", "PATCH"):
        body = request.read()
        request.headers["content-type"] = request.headers.get("content-type", "application/json")
        request.headers["content-length"] = str(len(body))
        request.headers["x-content-sha256"] = base64.b64encode(hashlib.sha256(body).digest()).decode()
        names += ["content-length", "content-type", "x-content-sha256"]
    values = {"(request-target)": f"{request.method.lower()} {request.url.raw_path.decode()}", "host": request.url.netloc.decode()}
    signing = "\n".join(f"{n}: {values[n] if n in values else request.headers[n]}" for n in names)
    signature = base64.b64encode(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
    request.headers["authorization"] = f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",headers="{" ".join(names)}",signature="{signature}"'


class OciVault(Provider):
    id = "oci-vault"
    label = "OCI Vault"
    features = frozenset({RECOVER, VERSIONS})
    name_pattern = _NAME_RULE
    name_hint = "Letters, digits, dots, hyphens and underscores, up to 255."

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        region: str,
        domain: str,
        client_id: str,
        client_secret: str,
        stores: dict[str, OciStore],
        labels: dict[str, str] | None = None,
        secret_stores: dict[str, str] | None = None,
    ):
        super().__init__(labels, secret_stores)
        self._http = http
        self._vaults = f"https://vaults.{region}.oci.oraclecloud.com/20180608"
        self._bundles = f"https://secrets.vaults.{region}.oci.oraclecloud.com/20190301"
        self._domain = domain
        self._client = (client_id, client_secret)
        self._stores = dict(stores)
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    async def credential(self, idp: OIDC, refresh_token: str) -> tuple[str, float]:
        id_token, _ = await idp.id_token(refresh_token)
        public = self._key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        form = {**_EXCHANGE, "subject_token": id_token, "public_key": base64.b64encode(public).decode()}
        try:
            response = await self._http.post(f"{self._domain}/oauth2/v1/token", data=form, auth=self._client, timeout=15)
            body = response.json()
        except (httpx.HTTPError, ValueError) as err:
            raise ProviderError(502, "Unreachable", f"cannot reach the OCI identity domain: {err.__class__.__name__}") from err
        token = body.get("token") if isinstance(body, dict) else None
        if response.status_code != 200 or not token:
            reason = body.get("error_description") or body.get("error") if isinstance(body, dict) else None
            raise ProviderError(403, "TokenExchange", f"OCI refused the token exchange: {str(reason or response.status_code)[:300]}")
        # A session token lasts an hour; one OCI refuses sooner gets replaced on its 401 anyway.
        return str(token), time.time() + 3600

    def stores(self, roles: Any) -> tuple[str, ...]:
        if not isinstance(roles, list):
            return ()
        return tuple(name for name in self._stores if name in roles)

    def location(self, store: str) -> str:
        return self._stores[store].vault

    def _check(self, name: str) -> None:
        if not re.fullmatch(_NAME_RULE, name):
            raise ProviderError(400, "invalid_name", f"Not an OCI secret name. {self.name_hint}")

    def external_secret_source(self, store: str, name: str) -> dict[str, Any]:
        self._check(name)
        return {"data": [{"secretKey": env_key(name), "remoteRef": {"key": name}}]}

    async def _call(self, method: str, url: str, token: str, *, json: Any = None, params: dict[str, str] | None = None) -> tuple[Any, httpx.Headers]:
        request = self._http.build_request(method, url, json=json, params=params, headers={"accept": "application/json"}, timeout=20)
        sign(request, f"ST${token}", self._key)
        try:
            response = await self._http.send(request)
        except httpx.HTTPError as err:
            raise ProviderError(502, "Unreachable", f"cannot reach OCI: {err.__class__.__name__}") from err
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        if response.status_code >= 400:
            code = str(body.get("code") or "Unknown") if isinstance(body, dict) else "Unknown"
            message = str(body.get("message") or code)[:500] if isinstance(body, dict) else code
            raise ProviderError(response.status_code, code, message)
        return body, response.headers

    async def _secrets(self, store: str, token: str, name: str = "") -> list[dict[str, Any]]:
        s = self._stores[store]
        params = {"compartmentId": s.compartment, "vaultId": s.vault, "limit": "100", **({"name": name} if name else {})}
        found: list[dict[str, Any]] = []
        for _ in range(_MAX_PAGES):
            body, headers = await self._call("GET", f"{self._vaults}/secrets", token, params=params)
            if isinstance(body, list):
                found.extend(i for i in body if isinstance(i, dict))
            page = headers.get("opc-next-page")
            if not page:
                break
            params["page"] = page
        return found

    async def _find(self, store: str, name: str, token: str) -> dict[str, Any] | None:
        """The secret by its exact name; a name stays taken while its deletion is pending."""
        self._check(name)
        matches = [s for s in await self._secrets(store, token, name) if s.get("secretName") == name and s.get("lifecycleState") != "DELETED"]
        return matches[0] if matches else None

    async def _id(self, store: str, name: str, token: str) -> str:
        found = await self._find(store, name, token)
        if not found:
            raise ProviderError(404, "NotFound", f"No secret named {name} in this vault.")
        return str(found["id"])

    def _item(self, secret: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": str(secret.get("secretName") or ""),
            "enabled": True,
            "expires": _epoch(secret.get("timeOfCurrentVersionExpiry")),
            "created": _epoch(secret.get("timeCreated")),
            "updated": None,
            "content_type": None,
            "managed": False,
            "recoverable_days": None,
        }

    async def list_secrets(self, store: str, token: str) -> list[dict[str, Any]]:
        items = [self._item(s) for s in await self._secrets(store, token) if s.get("lifecycleState") not in _GONE]
        return sorted(items, key=lambda s: s["name"].lower())

    async def list_deleted(self, store: str, token: str) -> list[dict[str, Any]]:
        pending = [s for s in await self._secrets(store, token) if s.get("lifecycleState") == "PENDING_DELETION"]
        items = [{**self._item(s), "deleted": None, "purge_at": _epoch(s.get("timeOfDeletion"))} for s in pending]
        return sorted(items, key=lambda s: s["name"].lower())

    async def get_value(self, store: str, name: str, token: str, version: str = "") -> str:
        if version and not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not an OCI secret version.")
        secret_id = await self._id(store, name, token)
        body, _ = await self._call("GET", f"{self._bundles}/secretbundles/{quote(secret_id, safe='')}", token, params={"versionNumber": version} if version else None)
        content = (body.get("secretBundleContent") or {}).get("content") if isinstance(body, dict) else None
        try:
            return base64.b64decode(str(content or ""), validate=True).decode()
        except (ValueError, UnicodeDecodeError) as err:
            raise ProviderError(400, "binary_value", "This secret holds binary data, which this UI does not show.") from err

    async def exists(self, store: str, name: str, token: str) -> bool:
        return await self._find(store, name, token) is not None

    async def set_secret(
        self, store: str, name: str, token: str, *, value: str, content_type: str | None, expires: int | None
    ) -> None:
        content = {"contentType": "BASE64", "content": base64.b64encode(value.encode()).decode()}
        found = await self._find(store, name, token)
        if found:
            await self._call("PUT", f"{self._vaults}/secrets/{quote(str(found['id']), safe='')}", token, json={"secretContent": content})
            return
        s = self._stores[store]
        create = {"compartmentId": s.compartment, "vaultId": s.vault, "keyId": s.key, "secretName": name, "secretContent": content}
        await self._call("POST", f"{self._vaults}/secrets", token, json=create)

    async def update(self, store: str, name: str, token: str, **changes: Any) -> dict[str, Any]:
        raise ProviderError(400, "not_supported", "An OCI secret has no attributes to change here.")

    async def delete(self, store: str, name: str, token: str) -> None:
        """Schedules the deletion after OCI's default retention; Recover cancels it until then."""
        secret_id = quote(await self._id(store, name, token), safe="")
        await self._call("POST", f"{self._vaults}/secrets/{secret_id}/actions/scheduleDeletion", token, json={})

    async def recover(self, store: str, name: str, token: str) -> None:
        secret_id = quote(await self._id(store, name, token), safe="")
        await self._call("POST", f"{self._vaults}/secrets/{secret_id}/actions/cancelDeletion", token, json={})

    async def list_versions(self, store: str, name: str, token: str) -> list[dict[str, Any]]:
        secret_id = quote(await self._id(store, name, token), safe="")
        body, _ = await self._call("GET", f"{self._vaults}/secrets/{secret_id}/versions", token, params={"limit": "100"})
        versions = []
        for v in body if isinstance(body, list) else []:
            stages = v.get("stages") or []
            versions.append(
                {
                    "version": str(v.get("versionNumber")),
                    "created": _epoch(v.get("timeCreated")),
                    "updated": None,
                    "expires": _epoch(v.get("timeOfExpiry")),
                    "state": "deleted" if v.get("timeOfDeletion") else "enabled",
                    "current": "CURRENT" in stages,
                }
            )
        return sorted(versions, key=lambda v: int(v["version"]) if v["version"].isdigit() else 0, reverse=True)

    async def restore(self, store: str, name: str, version: str, token: str) -> None:
        """OCI points the secret back at the old version itself; no value moves."""
        if not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not an OCI secret version.")
        secret_id = quote(await self._id(store, name, token), safe="")
        await self._call("PUT", f"{self._vaults}/secrets/{secret_id}", token, json={"currentVersionNumber": int(version)})
