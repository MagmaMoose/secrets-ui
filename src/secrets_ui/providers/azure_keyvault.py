"""Azure Key Vault: the secrets data plane over REST, with the person's own delegated token.

The stores are vaults, named by the person's app roles: a role whose value is a valid vault
name AND matches the operator's pattern. Roles are signed by Entra ID, so this is not the
security boundary (Azure RBAC on each vault is); it decides which vaults the UI offers and
which hosts the server calls at all. The pattern is how a deployment keeps privileged vaults
out even if a role for one is assigned by mistake.

A vault's audit log is its diagnostic setting's AuditEvent records, read through the Log
Analytics API by the vault's resource id, again with the person's own token: Azure RBAC on the
vault's logs decides who sees them.

Values pass through here and nowhere else: get_value returns one to the caller, and nothing
logs, caches or keeps it. Write responses carry the value back; they are read for errors only.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from . import AUDIT, CONTENT_TYPE, ENABLE, EXPIRY, RECOVER, VERSIONS, Provider, ProviderError

API_VERSION = "7.5"
_MAX_PAGES = 40  # 1000 secrets at Key Vault's 25 per page
# Key Vault's own rule: 3-24 characters, letters, digits and single hyphens, starting with a
# letter and ending with a letter or digit. Lowercase only, so one vault has one name.
_VAULT_NAME = re.compile(r"^[a-z](?:[a-z0-9]|-(?!-))*[a-z0-9]$")
_NAME_RULE = r"^[0-9a-zA-Z-]{1,127}$"
_VERSION = re.compile(r"^[0-9a-f]{32}$")
# shortcut: the public cloud's Log Analytics host only, add a setting when a sovereign cloud needs it.
_LOGS = "https://api.loganalytics.azure.com"
# AuditEvent lands in AzureDiagnostics or AZKVAuditLogs, as the diagnostic setting chose. Listing
# is left out: every page view lists.
_AUDIT_QUERY = """
union isfuzzy=true
  (AzureDiagnostics
   | where Category == "AuditEvent"
   | project TimeGenerated, OperationName, ResultSignature,
       CallerIp = column_ifexists("CallerIPAddress", ""),
       Caller = coalesce(column_ifexists("identity_claim_upn_s", ""),
         column_ifexists("identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s", ""),
         column_ifexists("identity_claim_oid_g", ""), column_ifexists("identity_claim_appid_g", "")),
       Target = coalesce(column_ifexists("id_s", ""), column_ifexists("requestUri_s", ""))),
  (AZKVAuditLogs
   | project TimeGenerated, OperationName, ResultSignature, CallerIp = CallerIpAddress,
       Caller = coalesce(tostring(Identity.claim.upn), tostring(Identity.claim.oid), tostring(Identity.claim.appid)),
       Target = coalesce(Id, RequestUri))
| where OperationName startswith "Secret" and OperationName !startswith "SecretList"
| top 500 by TimeGenerated desc
"""


def is_vault_name(value: str) -> bool:
    return 3 <= len(value) <= 24 and bool(_VAULT_NAME.match(value))


def vaults_from_roles(roles: Any, allowed: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(roles, list):
        return ()
    return tuple(sorted({r for r in roles if isinstance(r, str) and is_vault_name(r) and allowed.fullmatch(r)}))


def _message(body: Any) -> tuple[str, str]:
    """Key Vault's error code and the lines worth showing: what failed, and for a 403 which action."""
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return "Unknown", "Key Vault returned an error without details"
    lines = [line.strip() for line in str(error.get("message") or "").splitlines() if line.strip()]
    keep = lines[:1] + [line for line in lines[1:] if line.startswith(("Action:", "Client address:"))]
    inner = error.get("innererror")
    code = str(inner.get("code") if isinstance(inner, dict) and inner.get("code") else error.get("code") or "Unknown")
    return code, " ".join(keep)[:500] or code


def _event(row: dict[str, Any]) -> dict[str, Any]:
    target = urlsplit(str(row.get("Target") or "")).path.strip("/").split("/")
    try:
        time = int(datetime.fromisoformat(str(row.get("TimeGenerated"))[:19]).replace(tzinfo=UTC).timestamp())
    except ValueError:
        time = None
    return {
        "time": time,
        "operation": str(row.get("OperationName") or ""),
        "result": str(row.get("ResultSignature") or ""),
        "caller": str(row.get("Caller") or ""),
        "ip": str(row.get("CallerIp") or ""),
        "secret": target[1] if len(target) > 1 and target[0] in ("secrets", "deletedsecrets") else "",
    }


def _item(item: dict[str, Any]) -> dict[str, Any]:
    attributes = item.get("attributes") or {}
    # An id is https://<vault>/secrets/<name>, with /<version> after it on a single secret.
    segments = urlsplit(str(item.get("id", ""))).path.strip("/").split("/")
    return {
        "name": segments[1] if len(segments) > 1 else "",
        "enabled": bool(attributes.get("enabled", True)),
        "expires": attributes.get("exp"),
        "created": attributes.get("created"),
        "updated": attributes.get("updated"),
        "content_type": item.get("contentType"),
        "managed": bool(item.get("managed", False)),
        "recoverable_days": attributes.get("recoverableDays"),
    }


class AzureKeyVault(Provider):
    id = "azure-keyvault"
    label = "Azure Key Vault"
    features = frozenset({EXPIRY, ENABLE, CONTENT_TYPE, RECOVER, VERSIONS, AUDIT})
    name_pattern = _NAME_RULE
    name_hint = "Letters, digits and hyphens, up to 127."

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        roles: re.Pattern[str],
        suffix: str,
        labels: dict[str, str] | None = None,
        resource_ids: dict[str, str] | None = None,
    ):
        super().__init__(labels)
        self._http = http
        self._roles = roles
        self._suffix = suffix
        self._resource_ids = dict(resource_ids or {})

    @property
    def sign_in_scope(self) -> str:
        return f"https://{self._suffix}/user_impersonation"

    def stores(self, roles: Any) -> tuple[str, ...]:
        return vaults_from_roles(roles, self._roles)

    @property
    def audit_scope(self) -> str:
        return "https://api.loganalytics.io/Data.Read"

    def has_audit(self, store: str) -> bool:
        return store in self._resource_ids

    def location(self, store: str) -> str:
        return f"https://{self._host(store)}"

    def _host(self, vault: str) -> str:
        return f"{vault}.{self._suffix}"

    def _check(self, name: str) -> None:
        if not re.fullmatch(_NAME_RULE, name):
            raise ProviderError(400, "invalid_name", f"Not a Key Vault secret name. {self.name_hint}")

    async def _call(self, method: str, url: str, token: str, *, json: Any = None, params: dict[str, str] | None = None) -> Any:
        try:
            response = await self._http.request(
                method,
                url,
                json=json,
                params=params if params is not None else None if "api-version=" in url else {"api-version": API_VERSION},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=20,
            )
        except httpx.HTTPError as err:
            raise ProviderError(502, "Unreachable", f"cannot reach {urlsplit(url).hostname}: {err.__class__.__name__}") from err
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        if response.status_code >= 400:
            code, message = _message(body)
            raise ProviderError(response.status_code, code, message)
        return body

    def _url(self, vault: str, *segments: str) -> str:
        return f"https://{self._host(vault)}/" + "/".join(quote(s, safe="") for s in segments)

    async def _pages(self, vault: str, token: str, *collection: str) -> list[dict[str, Any]]:
        url = self._url(vault, *collection) + f"?api-version={API_VERSION}&maxresults=25"
        items: list[dict[str, Any]] = []
        for _ in range(_MAX_PAGES):
            body = await self._call("GET", url, token)
            items.extend(i for i in body.get("value") or [] if isinstance(i, dict))
            url = body.get("nextLink") or ""
            if not url:
                break
            # nextLink comes from the vault, but a bearer token goes nowhere but the vault itself.
            parts = urlsplit(url)
            if parts.scheme != "https" or parts.hostname != self._host(vault):
                raise ProviderError(502, "BadNextLink", "the vault returned a page link to another host")
        return items

    async def list_secrets(self, store: str, token: str) -> list[dict[str, Any]]:
        return sorted((_item(i) for i in await self._pages(store, token, "secrets")), key=lambda s: s["name"].lower())

    async def list_deleted(self, store: str, token: str) -> list[dict[str, Any]]:
        items = []
        for raw in await self._pages(store, token, "deletedsecrets"):
            item = _item(raw)
            item["deleted"] = raw.get("deletedDate")
            item["purge_at"] = raw.get("scheduledPurgeDate")
            items.append(item)
        return sorted(items, key=lambda s: s["name"].lower())

    async def get_value(self, store: str, name: str, token: str, version: str = "") -> str:
        self._check(name)
        if version and not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not a Key Vault secret version.")
        # An empty last segment is the latest version, as the Key Vault SDKs ask for it.
        body = await self._call("GET", self._url(store, "secrets", name, version), token)
        return str(body.get("value", ""))

    async def restore(self, store: str, name: str, version: str, token: str) -> None:
        self._check(name)
        if not _VERSION.match(version):
            raise ProviderError(400, "invalid_version", "Not a Key Vault secret version.")
        old = await self._call("GET", self._url(store, "secrets", name, version), token)
        expires = (old.get("attributes") or {}).get("exp")
        # An expiry already past would leave the restored value expired; it is dropped instead.
        await self.set_secret(
            store,
            name,
            token,
            value=str(old.get("value", "")),
            content_type=old.get("contentType"),
            expires=expires if isinstance(expires, int) and expires > time.time() else None,
        )

    async def list_versions(self, store: str, name: str, token: str) -> list[dict[str, Any]]:
        self._check(name)
        versions = []
        for raw in await self._pages(store, token, "secrets", name, "versions"):
            item = _item(raw)
            segments = urlsplit(str(raw.get("id", ""))).path.strip("/").split("/")
            versions.append(
                {
                    "version": segments[2] if len(segments) > 2 else "",
                    "created": item["created"],
                    "updated": item["updated"],
                    "expires": item["expires"],
                    "state": "enabled" if item["enabled"] else "disabled",
                }
            )
        # The current version is the newest one; the list comes in no particular order.
        versions.sort(key=lambda v: v["created"] or 0, reverse=True)
        return [{**v, "current": i == 0} for i, v in enumerate(versions)]

    async def exists(self, store: str, name: str, token: str) -> bool:
        self._check(name)
        try:
            await self._call("GET", self._url(store, "secrets", name, ""), token)
        except ProviderError as err:
            if err.status == 404:
                return False
            raise
        return True

    async def set_secret(
        self, store: str, name: str, token: str, *, value: str, content_type: str | None, expires: int | None
    ) -> None:
        self._check(name)
        body: dict[str, Any] = {"value": value, "attributes": {"enabled": True}}
        if content_type:
            body["contentType"] = content_type
        if expires is not None:
            body["attributes"]["exp"] = expires
        await self._call("PUT", self._url(store, "secrets", name), token, json=body)

    async def update(self, store: str, name: str, token: str, **changes: Any) -> dict[str, Any]:
        self._check(name)
        attributes: dict[str, Any] = {}
        if "enabled" in changes:
            attributes["enabled"] = bool(changes["enabled"])
        if "expires" in changes:
            attributes["exp"] = changes["expires"]
        body: dict[str, Any] = {"attributes": attributes}
        if "content_type" in changes:
            body["contentType"] = changes["content_type"] or ""
        return _item(await self._call("PATCH", self._url(store, "secrets", name, ""), token, json=body))

    async def delete(self, store: str, name: str, token: str) -> None:
        self._check(name)
        await self._call("DELETE", self._url(store, "secrets", name), token)

    async def recover(self, store: str, name: str, token: str) -> None:
        self._check(name)
        await self._call("POST", self._url(store, "deletedsecrets", name, "recover"), token)

    async def audit(self, store: str, token: str) -> list[dict[str, Any]]:
        if store not in self._resource_ids:
            raise ProviderError(400, "audit_not_configured", "No audit log is set up for this vault.")
        url = f"{_LOGS}/v1{self._resource_ids[store]}/query"
        body = await self._call("POST", url, token, json={"query": _AUDIT_QUERY, "timespan": "P30D"}, params={})
        tables = body.get("tables") or [{}]
        columns = [str(c.get("name")) for c in tables[0].get("columns") or []]
        return [_event(dict(zip(columns, row, strict=False))) for row in tables[0].get("rows") or []]
