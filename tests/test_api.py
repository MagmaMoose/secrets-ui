import json
import logging

from conftest import ORIGIN, make_client, sign_in, write_headers

VAULT_ID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/team-a-kv-dev"
WITH_AUDIT = {"SECRETS_UI_AZURE_KEYVAULT_STORES": json.dumps([{"name": "team-a-kv-dev", "resource_id": VAULT_ID}])}


def test_api_needs_a_session(client):
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets").status_code == 401


def test_list_secrets_as_the_signed_in_person(client, world):
    sign_in(client, world)
    world.vaults["team-a-kv-dev"].secrets["api-key"] = {"value": "k", "enabled": False, "exp": 2000000000, "created": 1, "updated": 3, "version": 1}
    response = client.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    secrets = response.json()["secrets"]
    assert [s["name"] for s in secrets] == ["api-key", "db-password"]
    assert secrets[0]["enabled"] is False and secrets[0]["expires"] == 2000000000
    assert all("value" not in s for s in secrets)
    calls = world.vault_requests()
    assert len(calls) == 2  # two pages, through nextLink
    assert all(c.headers["authorization"] == "Bearer at-1" for c in calls)


def test_the_theme_carries_the_operators_colours(world, env):
    client = make_client(world, {**env, "SECRETS_UI_BRAND_ACCENT": "#1D4ED8", "SECRETS_UI_BRAND_ACCENT_TEXT": "#ffffff", "SECRETS_UI_BRAND_ACCENT_DARK": "#93b4ff"})
    response = client.get("/theme.css")
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/css")
    assert "default-src 'none'" in response.headers["content-security-policy"]
    light, dark = response.text.splitlines()
    assert light.startswith("html:root{--accent:#1d4ed8;") and "--accent-text:#ffffff" in light
    assert dark.startswith("@media (prefers-color-scheme: dark){html:root{--accent:#93b4ff;") and "--accent-text:#ffffff" in dark


def test_without_colours_the_theme_is_empty(client):
    response = client.get("/theme.css")
    assert response.status_code == 200 and response.text == ""


def test_an_unknown_provider_is_not_found(client, world):
    sign_in(client, world)
    assert client.get("/api/stores/gcp/team-a-kv-dev/secrets").status_code == 404
    assert world.vault_requests() == []


def test_a_vault_outside_the_session_is_refused_before_any_call(client, world):
    sign_in(client, world)
    for path in ("/api/stores/azure-keyvault/privileged-kv-prd/secrets", "/api/stores/azure-keyvault/team-z-kv-dev/deleted"):
        response = client.get(path)
        assert response.status_code == 403
        assert response.json()["error"] == "store_not_allowed"
    assert world.vault_requests() == []


def test_a_refused_vault_says_which_action(client, world):
    sign_in(client, world)
    response = client.get("/api/stores/azure-keyvault/team-b-kv-dev/secrets")
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "ForbiddenByRbac"
    assert "getSecret" in body["message"] and "oid=" not in body["message"]


def test_reveal_returns_the_value_only_to_a_same_origin_csrf_protected_post(client, world, caplog):
    me = sign_in(client, world)
    path = "/api/stores/azure-keyvault/team-a-kv-dev/secrets/db-password/reveal"
    assert client.get(path).status_code == 405
    assert client.post(path).status_code == 403
    assert client.post(path, headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post(path, headers=write_headers(me, origin="https://evil.example")).status_code == 403
    assert world.vault_requests() == []

    with caplog.at_level(logging.DEBUG):
        response = client.post(path, headers=write_headers(me))
    assert response.status_code == 200
    assert response.json() == {"value": "s3cr3t-db"}
    assert response.headers["cache-control"] == "no-store"

    (call,) = world.vault_requests()
    assert call.method == "GET"
    assert call.url.path == "/secrets/db-password/"
    assert call.headers["authorization"] == "Bearer at-1"
    assert all("s3cr3t" not in str(r.url) for r in world.requests)
    assert "s3cr3t" not in caplog.text
    assert "secret revealed" in caplog.text


def test_reveal_is_refused_for_a_vault_outside_the_session(client, world):
    me = sign_in(client, world)
    response = client.post("/api/stores/azure-keyvault/privileged-kv-prd/secrets/x/reveal", headers=write_headers(me))
    assert response.status_code == 403
    assert world.vault_requests() == []


def test_create_refuses_an_existing_name_and_writes_a_new_one(client, world, caplog):
    me = sign_in(client, world)
    url = "/api/stores/azure-keyvault/team-a-kv-dev/secrets"
    taken = client.post(url, headers=write_headers(me), json={"name": "db-password", "value": "x"})
    assert taken.status_code == 409
    with caplog.at_level(logging.INFO):
        created = client.post(
            url, headers=write_headers(me), json={"name": "smtp", "value": "hunter2", "content_type": "password", "expires": "2030-01-01T00:00:00Z"}
        )
    assert created.status_code == 201
    stored = world.vaults["team-a-kv-dev"].secrets["smtp"]
    assert stored["value"] == "hunter2" and stored["contentType"] == "password" and stored["exp"] == 1893456000
    put = [r for r in world.vault_requests() if r.method == "PUT"][0]
    assert put.url.path == "/secrets/smtp"
    assert "hunter2" not in caplog.text


def test_create_needs_csrf(client, world):
    sign_in(client, world)
    response = client.post("/api/stores/azure-keyvault/team-a-kv-dev/secrets", json={"name": "x", "value": "y"})
    assert response.status_code == 403
    assert "x" not in world.vaults["team-a-kv-dev"].secrets


def test_a_rejected_request_does_not_echo_the_value(client, world):
    me = sign_in(client, world)
    response = client.post("/api/stores/azure-keyvault/team-a-kv-dev/secrets", headers=write_headers(me), json={"name": "bad name!", "value": "do-not-echo"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_name"
    assert "do-not-echo" not in response.text
    too_long = client.post("/api/stores/azure-keyvault/team-a-kv-dev/secrets", headers=write_headers(me), json={"name": "ok", "value": "do-not-echo" * 3000})
    assert too_long.status_code == 422 and "do-not-echo" not in too_long.text
    naive = client.post("/api/stores/azure-keyvault/team-a-kv-dev/secrets", headers=write_headers(me), json={"name": "ok", "value": "v", "expires": "2030-01-01T00:00:00"})
    assert naive.status_code == 422


def test_new_version_expiry_and_enable(client, world):
    me = sign_in(client, world)
    vault = world.vaults["team-a-kv-dev"]
    base = "/api/stores/azure-keyvault/team-a-kv-dev/secrets/db-password"
    assert client.post(f"{base}/versions", headers=write_headers(me), json={"value": "rotated"}).status_code == 201
    assert vault.secrets["db-password"]["value"] == "rotated" and vault.secrets["db-password"]["version"] == 2

    set_expiry = client.patch(base, headers=write_headers(me), json={"expires": "2031-06-01T12:00:00+02:00"})
    assert set_expiry.status_code == 200
    assert vault.secrets["db-password"]["exp"] == 1938074400

    cleared = client.patch(base, headers=write_headers(me), json={"expires": None})
    assert cleared.status_code == 200
    patch = [r for r in world.vault_requests() if r.method == "PATCH"][-1]
    assert patch.url.path == "/secrets/db-password/"
    assert json.loads(patch.content) == {"attributes": {"exp": None}}
    assert vault.secrets["db-password"]["exp"] is None

    disabled = client.patch(base, headers=write_headers(me), json={"enabled": False})
    assert disabled.json()["secret"]["enabled"] is False
    assert client.patch(base, headers=write_headers(me), json={}).status_code == 400


def test_older_versions_are_listed_newest_first_and_revealed_one_at_a_time(client, world, caplog):
    me = sign_in(client, world)
    base = "/api/stores/azure-keyvault/team-a-kv-dev/secrets/db-password"
    assert client.post(f"{base}/versions", headers=write_headers(me), json={"value": "rotated"}).status_code == 201
    versions = client.get(f"{base}/versions").json()["versions"]
    assert [(v["current"], v["state"]) for v in versions] == [(True, "enabled"), (False, "enabled")]
    assert all("value" not in v for v in versions)

    old = versions[1]["version"]
    assert client.post(f"{base}/reveal", json={"version": old}).status_code == 403
    with caplog.at_level(logging.INFO):
        response = client.post(f"{base}/reveal", headers=write_headers(me), json={"version": old})
    assert response.status_code == 200 and response.json() == {"value": "s3cr3t-db"}
    assert world.vault_requests()[-1].url.path == f"/secrets/db-password/{old}"
    assert "s3cr3t" not in caplog.text and old in caplog.text

    bad = client.post(f"{base}/reveal", headers=write_headers(me), json={"version": "../keys"})
    assert bad.status_code == 400 and world.vault_requests()[-1].url.path == f"/secrets/db-password/{old}"


def test_an_older_version_is_restored_as_a_new_current_one(client, world, caplog):
    me = sign_in(client, world)
    vault = world.vaults["team-a-kv-dev"]
    base = "/api/stores/azure-keyvault/team-a-kv-dev/secrets/db-password"
    assert client.post(f"{base}/versions", headers=write_headers(me), json={"value": "rotated", "content_type": "text/x-new"}).status_code == 201
    old = client.get(f"{base}/versions").json()["versions"][1]["version"]
    assert client.post(f"{base}/restore", json={"version": old}).status_code == 403
    with caplog.at_level(logging.INFO):
        response = client.post(f"{base}/restore", headers=write_headers(me), json={"version": old})
    assert response.status_code == 200, response.text
    assert vault.secrets["db-password"]["value"] == "s3cr3t-db" and vault.secrets["db-password"]["version"] == 3
    assert vault.secrets["db-password"]["contentType"] == "text/plain"
    assert "s3cr3t" not in caplog.text and "secret version restored" in caplog.text
    assert client.post(f"{base}/restore", headers=write_headers(me), json={"version": ""}).status_code == 422
    assert client.post(f"{base}/restore", headers=write_headers(me), json={"version": "../x"}).json()["error"] == "invalid_version"


def test_the_audit_log_is_the_vaults_own_read_with_the_persons_token(world, env):
    client = make_client(world, {**env, **WITH_AUDIT})
    me = sign_in(client, world)
    assert [(s["name"], s["audit"]) for s in me["stores"]] == [("team-a-kv-dev", True), ("team-b-kv-dev", False)]
    world.audit_rows = [["2026-10-16T09:30:00.1234567Z", "SecretGet", "OK", "10.1.2.3", "ada@example.test", "https://team-a-kv-dev.vault.azure.net/secrets/db-password/0a1b"]]
    response = client.get("/api/stores/azure-keyvault/team-a-kv-dev/audit")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["events"] == [
        {"time": 1792143000, "operation": "SecretGet", "result": "OK", "caller": "ada@example.test", "ip": "10.1.2.3", "secret": "db-password"}
    ]
    (query,) = [r for r in world.requests if r.url.host == "api.loganalytics.azure.com"]
    assert query.method == "POST" and query.url.path == f"/v1{VAULT_ID}/query" and not query.url.query
    assert json.loads(query.content)["timespan"] == "P30D"
    assert world.entra.token_requests[-1]["scope"] == ["offline_access https://api.loganalytics.io/Data.Read"]
    assert query.headers["authorization"] == f"Bearer at-{world.entra.refreshed + 1}"
    assert client.get("/api/stores/azure-keyvault/team-b-kv-dev/audit").json()["error"] == "audit_not_configured"


def test_no_consent_for_the_audit_log_leaves_the_person_signed_in(world, env):
    client = make_client(world, {**env, **WITH_AUDIT})
    sign_in(client, world)
    world.entra.refuse_scope = "loganalytics"
    response = client.get("/api/stores/azure-keyvault/team-a-kv-dev/audit")
    assert response.status_code == 403
    assert response.json()["error"] == "audit_unavailable" and "AADSTS65001" in response.json()["message"]
    assert client.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets").status_code == 200


def test_soft_delete_and_recover(client, world):
    me = sign_in(client, world)
    vault = world.vaults["team-a-kv-dev"]
    assert client.delete("/api/stores/azure-keyvault/team-a-kv-dev/secrets/db-password", headers=write_headers(me)).status_code == 200
    assert "db-password" in vault.deleted
    deleted = client.get("/api/stores/azure-keyvault/team-a-kv-dev/deleted").json()["secrets"]
    assert [d["name"] for d in deleted] == ["db-password"] and deleted[0]["purge_at"]
    # The name stays taken while the secret is recoverable.
    again = client.post("/api/stores/azure-keyvault/team-a-kv-dev/secrets", headers=write_headers(me), json={"name": "db-password", "value": "x"})
    assert again.status_code == 409
    assert client.post("/api/stores/azure-keyvault/team-a-kv-dev/deleted/db-password/recover", headers=write_headers(me)).status_code == 200
    assert "db-password" in vault.secrets


def test_another_replica_redeems_the_refresh_token(client, world, env):
    sign_in(client, world)
    other = make_client(world, env)
    other.cookies = client.cookies
    assert other.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets").status_code == 200
    assert world.entra.refreshed == 1
    assert world.vault_requests()[-1].headers["authorization"] == "Bearer at-2"
    # The refresh asks for the vault scope again, with the app's own credential.
    refresh = world.entra.token_requests[-1]
    assert refresh["grant_type"] == ["refresh_token"] and "client_assertion" in refresh


def test_a_token_the_vault_rejects_is_refreshed_once(client, world):
    sign_in(client, world)
    world.vaults["team-a-kv-dev"].valid = {"at-2"}
    assert client.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets").status_code == 200
    assert world.entra.refreshed == 1


def test_a_revoked_refresh_token_signs_the_person_out(client, world, env):
    sign_in(client, world)
    world.entra.refuse_refresh = True
    other = make_client(world, env)
    other.cookies = client.cookies
    response = other.get("/api/stores/azure-keyvault/team-a-kv-dev/secrets")
    assert response.status_code == 401
    assert response.json()["error"] == "signed_out"
