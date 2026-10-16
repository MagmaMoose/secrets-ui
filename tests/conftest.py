"""Fake Entra ID, Key Vault, Log Analytics and HashiCorp Vault behind one httpx MockTransport, and
an app wired to them."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from secrets_ui.app import create_app
from secrets_ui.config import load_config

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ORIGIN = "https://kv.example.test"
AUTHORITY = "https://login.example.test"
ASSERTION = "header.workload-identity-token.signature"


@dataclass
class FakeEntra:
    key: Any = field(default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))
    roles: list[str] = field(default_factory=list)
    challenge: str = ""
    nonce: str = ""
    tid: str = TENANT
    token_requests: list[dict[str, list[str]]] = field(default_factory=list)
    refreshed: int = 0
    refuse_refresh: bool = False
    # A scope the tenant has not consented to: refreshing for it fails like AADSTS65001.
    refuse_scope: str = ""

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [{**jwk, "kid": "test-key", "use": "sig", "alg": "RS256"}]}

    def id_token(self) -> str:
        now = int(time.time())
        claims = {
            "iss": f"{AUTHORITY}/{TENANT}/v2.0",
            "aud": CLIENT,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "nonce": self.nonce,
            "tid": self.tid,
            "oid": "99999999-8888-7777-6666-555555555555",
            "name": "Ada Lovelace",
            "preferred_username": "ada@example.test",
            "roles": self.roles,
        }
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})

    def token(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        self.token_requests.append(form)
        grant = form["grant_type"][0]
        if grant == "authorization_code":
            verifier = form["code_verifier"][0]
            digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if form["code"][0] != "good-code" or digest != self.challenge:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "AADSTS70008: bad code"})
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "access_token": "at-1",
                    "refresh_token": "rt-1",
                    "id_token": self.id_token(),
                },
            )
        if grant == "refresh_token":
            if self.refuse_refresh or form["refresh_token"][0] != "rt-1":
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "AADSTS700082: expired"})
            if self.refuse_scope and self.refuse_scope in form["scope"][0]:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "AADSTS65001: The user or administrator has not consented"})
            self.refreshed += 1
            body = {"expires_in": 3600, "access_token": f"at-{self.refreshed + 1}"}
            if "openid" in form["scope"][0].split():
                body["id_token"] = self.id_token()
            return httpx.Response(200, json=body)
        return httpx.Response(400, json={"error": "unsupported_grant_type"})


@dataclass
class FakeVault:
    """One vault's secrets. `valid` is the set of bearer tokens it accepts."""

    secrets: dict[str, dict[str, Any]] = field(default_factory=dict)
    deleted: dict[str, dict[str, Any]] = field(default_factory=dict)
    valid: set[str] = field(default_factory=lambda: {"at-1", "at-2", "at-3"})
    forbidden: bool = False

    def bundle(self, host: str, name: str, secret: dict[str, Any], with_value: bool) -> dict[str, Any]:
        body = {
            "id": f"https://{host}/secrets/{name}/{secret['version']:032x}",
            "attributes": {k: secret[k] for k in ("enabled", "exp", "created", "updated") if secret.get(k) is not None},
            "contentType": secret.get("contentType"),
        }
        if with_value:
            body["value"] = secret["value"]
        return body


@dataclass
class FakeHashiVault:
    """A KV v2 mount at `secret` and JWT auth at `jwt` (role secrets-ui) that trusts FakeEntra's ID
    tokens. A token may touch the folders `folders` gives the roles it signed in with."""

    entra: FakeEntra
    folders: dict[str, str] = field(default_factory=dict)
    # {path: [{"data", "created_time", "deletion_time", "destroyed"}, ...]}, oldest version first.
    kv: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    tokens: dict[str, list[str]] = field(default_factory=dict)
    logins: list[dict[str, Any]] = field(default_factory=list)

    def put(self, path: str, data: dict[str, Any]) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S.123456789Z", time.gmtime())
        self.kv.setdefault(path, []).append({"data": data, "created_time": stamp, "deletion_time": "", "destroyed": False})

    def metadata(self, path: str) -> dict[str, Any]:
        versions = self.kv[path]
        return {
            "created_time": versions[0]["created_time"],
            "updated_time": versions[-1]["created_time"],
            "current_version": len(versions),
            "versions": {str(i + 1): {k: v for k, v in version.items() if k != "data"} for i, version in enumerate(versions)},
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")
        if path == "auth/jwt/login":
            body = json.loads(request.content)
            try:
                claims = jwt.decode(body["jwt"], self.entra.key.public_key(), algorithms=["RS256"], audience=CLIENT, issuer=f"{AUTHORITY}/{TENANT}/v2.0")
            except jwt.PyJWTError as err:
                return httpx.Response(400, json={"errors": [f"error validating token: {err}"]})
            if body.get("role") != "secrets-ui":
                return httpx.Response(400, json={"errors": [f'role "{body.get("role")}" could not be found']})
            token = f"hvs.{len(self.tokens) + 1}"
            self.tokens[token] = list(claims.get("roles") or [])
            self.logins.append(body)
            return httpx.Response(200, json={"auth": {"client_token": token, "lease_duration": 3600, "renewable": True}})
        roles = self.tokens.get(request.headers.get("x-vault-token", ""))
        if roles is None:
            return httpx.Response(403, json={"errors": ["2 errors occurred:\n\t* permission denied\n\t* invalid token\n\n"]})
        mount, _, rest = path.partition("/")
        kind, _, key = rest.partition("/")
        if mount != "secret" or kind not in ("data", "metadata", "undelete"):
            return httpx.Response(404, json={"errors": ["no handler for route"]})
        if not any(f"{key.rstrip('/')}/".startswith(self.folders[r]) for r in roles if r in self.folders):
            return httpx.Response(403, json={"errors": ["permission denied"]})
        method = request.method
        if kind == "metadata" and request.url.params.get("list") == "true":
            prefix = key if key.endswith("/") else f"{key}/"
            keys = sorted({p[len(prefix) :].split("/")[0] + ("/" if "/" in p[len(prefix) :] else "") for p in self.kv if p.startswith(prefix)})
            return httpx.Response(200, json={"data": {"keys": keys}}) if keys else httpx.Response(404, json={"errors": []})
        if kind == "data" and method == "POST":
            self.put(key, json.loads(request.content)["data"])
            return httpx.Response(200, json={"data": {"version": len(self.kv[key])}})
        if key not in self.kv:
            return httpx.Response(404, json={"errors": []})
        versions = self.kv[key]
        if kind == "metadata" and method == "GET":
            return httpx.Response(200, json={"data": self.metadata(key)})
        if kind == "data" and method == "GET":
            version = versions[int(request.url.params.get("version") or len(versions)) - 1]
            if version["deletion_time"] or version["destroyed"]:
                return httpx.Response(404, json={"data": {"data": None, "metadata": {}}})
            return httpx.Response(200, json={"data": {"data": version["data"], "metadata": {}}})
        if kind == "data" and method == "DELETE":
            versions[-1]["deletion_time"] = time.strftime("%Y-%m-%dT%H:%M:%S.5Z", time.gmtime())
            return httpx.Response(204)
        if kind == "undelete" and method == "POST":
            for number in json.loads(request.content)["versions"]:
                versions[int(number) - 1]["deletion_time"] = ""
            return httpx.Response(204)
        return httpx.Response(405, json={"errors": ["unsupported operation"]})


@dataclass
class World:
    entra: FakeEntra
    vaults: dict[str, FakeVault]
    requests: list[httpx.Request] = field(default_factory=list)
    # What the Log Analytics API answers any audit query with, in the query's column order.
    audit_rows: list[list[Any]] = field(default_factory=list)
    hashi: FakeHashiVault | None = None

    def vault_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host.endswith(".vault.azure.net")]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "login.example.test":
            if path == f"/{TENANT}/discovery/v2.0/keys":
                return httpx.Response(200, json=self.entra.jwks())
            if path == f"/{TENANT}/oauth2/v2.0/token":
                return self.entra.token(request)
            return httpx.Response(404)
        if host == "vault.example.test" and self.hashi is not None:
            return self.hashi.handle(request)
        if host == "api.loganalytics.azure.com":
            if not request.headers.get("authorization", "").startswith("Bearer at-"):
                return httpx.Response(401, json={"error": {"code": "AuthorizationRequired", "message": "Valid authentication was not provided"}})
            columns = ["TimeGenerated", "OperationName", "ResultSignature", "CallerIp", "Caller", "Target"]
            return httpx.Response(200, json={"tables": [{"name": "PrimaryResult", "columns": [{"name": c} for c in columns], "rows": self.audit_rows}]})
        name = host.removesuffix(".vault.azure.net")
        vault = self.vaults.get(name)
        if vault is None:
            raise httpx.ConnectError("no such host", request=request)
        if request.url.params.get("api-version") != "7.5":
            return httpx.Response(400, json={"error": {"code": "BadParameter", "message": "api-version"}})
        auth = request.headers.get("authorization", "")
        if auth.removeprefix("Bearer ") not in vault.valid:
            return httpx.Response(401, json={"error": {"code": "Unauthorized", "message": "AKV10000: Request is missing a Bearer or PoP token."}})
        if vault.forbidden:
            message = "Caller is not authorized to perform action on resource.\r\nCaller: appid=x;oid=y\r\nAction: 'Microsoft.KeyVault/vaults/secrets/getSecret/action'\r\nResource: 'z'"
            return httpx.Response(403, json={"error": {"code": "Forbidden", "message": message, "innererror": {"code": "ForbiddenByRbac"}}})
        return self.vault(host, vault, request)

    def vault(self, host: str, vault: FakeVault, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.lstrip("/").split("/")
        method = request.method
        now = int(time.time())
        if parts == ["secrets"] and method == "GET":
            items = [{**vault.bundle(host, n, s, False), "id": f"https://{host}/secrets/{n}"} for n, s in sorted(vault.secrets.items())]
            # Two pages, to exercise nextLink.
            if "$skiptoken" not in request.url.params and len(items) > 1:
                return httpx.Response(200, json={"value": items[:1], "nextLink": f"https://{host}/secrets?api-version=7.5&$skiptoken=p2&maxresults=25"})
            return httpx.Response(200, json={"value": items[1:] if "$skiptoken" in request.url.params else items, "nextLink": None})
        if parts == ["deletedsecrets"] and method == "GET":
            items = [
                {**vault.bundle(host, n, s, False), "id": f"https://{host}/secrets/{n}", "deletedDate": now, "scheduledPurgeDate": now + 7776000}
                for n, s in sorted(vault.deleted.items())
            ]
            return httpx.Response(200, json={"value": items})
        if len(parts) == 3 and parts[0] == "deletedsecrets" and parts[2] == "recover" and method == "POST":
            if parts[1] not in vault.deleted:
                return httpx.Response(404, json={"error": {"code": "SecretNotFound", "message": "Deleted Secret not found"}})
            vault.secrets[parts[1]] = vault.deleted.pop(parts[1])
            return httpx.Response(200, json=vault.bundle(host, parts[1], vault.secrets[parts[1]], False))
        if parts[0] != "secrets" or len(parts) < 2:
            return httpx.Response(404, json={"error": {"code": "NotFound", "message": "no route"}})
        name = parts[1]
        if method == "PUT" and len(parts) == 2:
            if name in vault.deleted:
                return httpx.Response(409, json={"error": {"code": "Conflict", "message": f"Secret {name} is currently in a deleted but recoverable state."}})
            body = json.loads(request.content)
            old = vault.secrets.get(name, {"version": 0, "created": now})
            history = [*old.get("history", []), {k: v for k, v in old.items() if k != "history"}] if name in vault.secrets else []
            vault.secrets[name] = {
                "value": body["value"],
                "contentType": body.get("contentType"),
                "enabled": body.get("attributes", {}).get("enabled", True),
                "exp": body.get("attributes", {}).get("exp"),
                "created": old["created"],
                "updated": now,
                "version": old["version"] + 1,
                "history": history,
            }
            return httpx.Response(200, json=vault.bundle(host, name, vault.secrets[name], True))
        if name not in vault.secrets:
            return httpx.Response(404, json={"error": {"code": "SecretNotFound", "message": f"A secret with (name/id) {name} was not found in this key vault."}})
        secret = vault.secrets[name]
        if method == "GET" and len(parts) == 3 and parts[2] == "":
            return httpx.Response(200, json=vault.bundle(host, name, secret, True))
        # Older versions were created when they were last updated; the newest one, on its update.
        versions = [*secret.get("history", []), secret]
        if method == "GET" and parts[2:] == ["versions"]:
            return httpx.Response(200, json={"value": [{**vault.bundle(host, name, {**v, "created": v["updated"]}, False)} for v in versions]})
        if method == "GET" and len(parts) == 3:
            match = [v for v in versions if f"{v['version']:032x}" == parts[2]]
            if not match:
                return httpx.Response(404, json={"error": {"code": "SecretNotFound", "message": "no such version"}})
            return httpx.Response(200, json=vault.bundle(host, name, match[0], True))
        if method == "PATCH" and len(parts) == 3 and parts[2] == "":
            body = json.loads(request.content)
            for key, value in body.get("attributes", {}).items():
                secret[key] = value
            if "contentType" in body:
                secret["contentType"] = body["contentType"]
            secret["updated"] = now
            return httpx.Response(200, json=vault.bundle(host, name, secret, False))
        if method == "DELETE" and len(parts) == 2:
            vault.deleted[name] = vault.secrets.pop(name)
            return httpx.Response(200, json={"recoveryId": f"https://{host}/deletedsecrets/{name}"})
        return httpx.Response(405)


@pytest.fixture
def world() -> World:
    return World(
        entra=FakeEntra(roles=["team-a-kv-dev", "team-b-kv-dev", "privileged-kv-prd", "Not_A_Vault", "admin", "team-a-vault-dev"]),
        vaults={
            "team-a-kv-dev": FakeVault(
                secrets={"db-password": {"value": "s3cr3t-db", "contentType": "text/plain", "enabled": True, "exp": None, "created": 1, "updated": 2, "version": 1}}
            ),
            "team-b-kv-dev": FakeVault(forbidden=True),
            "privileged-kv-prd": FakeVault(),
        },
    )


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    token = tmp_path / "azure-identity-token"
    token.write_text(ASSERTION + "\n")
    return {
        "AZURE_TENANT_ID": TENANT,
        "AZURE_CLIENT_ID": CLIENT,
        "AZURE_AUTHORITY_HOST": AUTHORITY,
        "AZURE_FEDERATED_TOKEN_FILE": str(token),
        "SECRETS_UI_PUBLIC_ORIGIN": ORIGIN,
        "SECRETS_UI_SESSION_KEY": "k" * 48,
        "SECRETS_UI_AZURE_KEYVAULT_ROLES": r"^team-[a-z]+-kv-(dev|prd)$",
        "SECRETS_UI_STATIC_DIR": str(tmp_path / "no-frontend"),
    }


def make_client(world: World, env: dict[str, str]) -> TestClient:
    app = create_app(load_config(env), transport=httpx.MockTransport(world.handler))
    return TestClient(app, base_url=ORIGIN, follow_redirects=False)


@pytest.fixture
def client(world: World, env: dict[str, str]) -> TestClient:
    return make_client(world, env)


def sign_in(client: TestClient, world: World) -> dict[str, Any]:
    """The whole browser round trip: /auth/login, Microsoft, /auth/callback. Returns /api/me."""
    login = client.get("/auth/login")
    assert login.status_code == 302
    query = parse_qs(urlsplit(login.headers["location"]).query)
    world.entra.challenge = query["code_challenge"][0]
    world.entra.nonce = query["nonce"][0]
    callback = client.get("/auth/callback", params={"code": "good-code", "state": query["state"][0]})
    assert callback.status_code == 303, callback.text
    assert callback.headers["location"] == "/"
    me = client.get("/api/me")
    assert me.status_code == 200, me.text
    return me.json()


def write_headers(me: dict[str, Any], origin: str = ORIGIN) -> dict[str, str]:
    return {"Origin": origin, "X-CSRF-Token": me["csrf"]}


def cookie_attributes(response: httpx.Response, name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        if re.match(rf"^{re.escape(name)}=", header):
            return header
    raise AssertionError(f"{name} was not set")
