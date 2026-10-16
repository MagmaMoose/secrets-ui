import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from conftest import FakeHashiVault, make_client, sign_in, write_headers
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from secrets_ui.app import create_app
from secrets_ui.config import ConfigError, load_config

STORES = [
    {"name": "team-a-vault-dev", "label": "Team A dev", "mount": "secret", "path": "dev/team-a"},
    {"name": "team-b-vault-dev", "mount": "secret", "path": "dev/team-b"},
]
BASE = "/api/stores/hashicorp-vault/team-a-vault-dev"


@pytest.fixture
def vault_env(env):
    return {
        **env,
        "SECRETS_UI_PROVIDERS": "azure-keyvault,hashicorp-vault",
        "SECRETS_UI_HASHICORP_VAULT_ADDR": "https://vault.example.test:8200",
        "SECRETS_UI_HASHICORP_VAULT_STORES": json.dumps(STORES),
    }


@pytest.fixture
def hashi(world):
    world.hashi = FakeHashiVault(world.entra, folders={"team-a-vault-dev": "dev/team-a/", "team-b-vault-dev": "dev/team-b/"})
    world.hashi.put("dev/team-a/db", {"password": "s3cr3t-db"})
    world.hashi.put("dev/team-a/app/config", {"username": "app", "password": "s3cr3t-app"})
    world.hashi.put("dev/team-b/other", {"value": "not-yours"})
    return world.hashi


@pytest.fixture
def vclient(world, vault_env, hashi):
    return make_client(world, vault_env)


def vault_requests(world):
    return [r for r in world.requests if r.url.host == "vault.example.test"]


def test_a_vault_store_shows_when_a_role_names_it(vclient, world):
    me = sign_in(vclient, world)
    vault = [s for s in me["stores"] if s["provider"] == "hashicorp-vault"]
    assert vault == [
        {"provider": "hashicorp-vault", "name": "team-a-vault-dev", "label": "Team A dev", "location": "secret/dev/team-a on https://vault.example.test:8200", "audit": False}
    ]
    provider = next(p for p in me["providers"] if p["id"] == "hashicorp-vault")
    assert set(provider["features"]) == {"recover", "versions"} and "JSON object" in provider["value_hint"]
    assert vclient.get("/api/stores/hashicorp-vault/team-b-vault-dev/secrets").json()["error"] == "store_not_allowed"
    assert vault_requests(world) == []


def test_the_person_signs_in_to_vault_with_their_own_id_token(vclient, world, hashi):
    sign_in(vclient, world)
    response = vclient.get(f"{BASE}/secrets")
    assert response.status_code == 200, response.text
    assert [s["name"] for s in response.json()["secrets"]] == ["app/config", "db"]
    assert all("value" not in s and s["updated"] for s in response.json()["secrets"])
    (login,) = hashi.logins
    assert login["role"] == "secrets-ui"
    assert world.entra.token_requests[-1]["scope"] == ["openid profile offline_access"]
    assert all(r.headers["x-vault-token"] == "hvs.1" for r in vault_requests(world)[1:])
    # Folders are listed with a trailing slash, so a policy on <folder>/* covers them.
    assert [r.url.path for r in vault_requests(world)[1:3]] == ["/v1/secret/metadata/dev/team-a/", "/v1/secret/metadata/dev/team-a/app/"]
    # The Vault token is cached: a second listing signs in to nothing.
    assert vclient.get(f"{BASE}/secrets").status_code == 200 and len(hashi.logins) == 1


def test_a_value_is_the_secrets_json_object(vclient, world, caplog):
    me = sign_in(vclient, world)
    with caplog.at_level(logging.INFO):
        response = vclient.post(f"{BASE}/secrets/app/config/reveal", headers=write_headers(me))
    assert response.status_code == 200
    assert json.loads(response.json()["value"]) == {"username": "app", "password": "s3cr3t-app"}
    assert vault_requests(world)[-1].url.path == "/v1/secret/data/dev/team-a/app/config"
    assert "s3cr3t" not in caplog.text and "secret revealed" in caplog.text


def test_create_takes_a_json_object_only(vclient, world, hashi, caplog):
    me = sign_in(vclient, world)
    url = f"{BASE}/secrets"
    assert vclient.post(url, headers=write_headers(me), json={"name": "db", "value": "{}"}).status_code == 409
    with caplog.at_level(logging.INFO):
        created = vclient.post(url, headers=write_headers(me), json={"name": "smtp/relay", "value": '{"password": "hunter2"}'})
    assert created.status_code == 201
    assert hashi.kv["dev/team-a/smtp/relay"][-1]["data"] == {"password": "hunter2"}
    plain = vclient.post(url, headers=write_headers(me), json={"name": "plain", "value": "hunter2"})
    assert plain.status_code == 400 and plain.json()["error"] == "invalid_value" and "hunter2" not in plain.text
    assert "hunter2" not in caplog.text
    refused = vclient.post(url, headers=write_headers(me), json={"name": "x", "value": '{"a": "b"}', "expires": "2030-01-01T00:00:00Z"})
    assert refused.status_code == 400 and refused.json()["error"] == "expiry_not_supported"


@pytest.mark.parametrize("name", ["../team-b/other", "a/../../team-b/other", "./db", "a//b", "db/"])
def test_a_name_cannot_leave_the_stores_folder(vclient, world, name):
    me = sign_in(vclient, world)
    response = vclient.post(f"{BASE}/secrets", headers=write_headers(me), json={"name": name, "value": '{"a": "b"}'})
    assert response.status_code == 400 and response.json()["error"] == "invalid_name"
    assert [r.url.path for r in vault_requests(world)] == ["/v1/auth/jwt/login"]


def test_delete_moves_the_secret_to_deleted_and_recover_brings_it_back(vclient, world, hashi):
    me = sign_in(vclient, world)
    assert vclient.delete(f"{BASE}/secrets/db", headers=write_headers(me)).status_code == 200
    assert hashi.kv["dev/team-a/db"][-1]["deletion_time"]
    assert [s["name"] for s in vclient.get(f"{BASE}/secrets").json()["secrets"]] == ["app/config"]
    deleted = vclient.get(f"{BASE}/deleted").json()["secrets"]
    assert [d["name"] for d in deleted] == ["db"] and deleted[0]["deleted"] and deleted[0]["purge_at"] is None
    assert vclient.post(f"{BASE}/deleted/db/recover", headers=write_headers(me)).status_code == 200
    assert [s["name"] for s in vclient.get(f"{BASE}/secrets").json()["secrets"]] == ["app/config", "db"]


def test_versions_newest_first_and_an_old_one_revealed(vclient, world):
    me = sign_in(vclient, world)
    assert vclient.post(f"{BASE}/secrets/db/versions", headers=write_headers(me), json={"value": '{"password": "rotated"}'}).status_code == 201
    versions = vclient.get(f"{BASE}/secrets/db/versions").json()["versions"]
    assert [(v["version"], v["current"], v["state"]) for v in versions] == [("2", True, "enabled"), ("1", False, "enabled")]
    old = vclient.post(f"{BASE}/secrets/db/reveal", headers=write_headers(me), json={"version": "1"})
    assert json.loads(old.json()["value"]) == {"password": "s3cr3t-db"}
    assert vault_requests(world)[-1].url.params["version"] == "1"
    assert vclient.post(f"{BASE}/secrets/db/reveal", headers=write_headers(me), json={"version": "1 OR 1"}).status_code == 400
    vclient.delete(f"{BASE}/secrets/db", headers=write_headers(me))
    assert vclient.get(f"{BASE}/secrets/db/versions").json()["versions"][0]["state"] == "deleted"


def test_restore_writes_the_old_data_as_a_new_version_with_check_and_set(vclient, world, hashi):
    me = sign_in(vclient, world)
    assert vclient.post(f"{BASE}/secrets/db/versions", headers=write_headers(me), json={"value": '{"password": "rotated"}'}).status_code == 201
    response = vclient.post(f"{BASE}/secrets/db/restore", headers=write_headers(me), json={"version": "1"})
    assert response.status_code == 200, response.text
    assert [v["data"] for v in hashi.kv["dev/team-a/db"]] == [{"password": "s3cr3t-db"}, {"password": "rotated"}, {"password": "s3cr3t-db"}]
    write = [r for r in vault_requests(world) if r.method == "POST" and r.url.path.startswith("/v1/secret/data/")][-1]
    assert json.loads(write.content)["options"] == {"cas": 2}


def test_attributes_vault_does_not_have_are_refused(vclient, world):
    me = sign_in(vclient, world)
    response = vclient.patch(f"{BASE}/secrets/db", headers=write_headers(me), json={"enabled": False})
    assert response.status_code == 400 and response.json()["error"] == "enable_not_supported"


def test_a_revoked_vault_token_signs_in_to_vault_again(vclient, world, hashi):
    sign_in(vclient, world)
    assert vclient.get(f"{BASE}/secrets").status_code == 200
    hashi.tokens.clear()
    assert vclient.get(f"{BASE}/secrets").status_code == 200
    assert len(hashi.logins) == 2


def test_vault_refusing_the_login_says_why(vclient, world, hashi, vault_env):
    sign_in(vclient, world)
    other = make_client(world, {**vault_env, "SECRETS_UI_HASHICORP_VAULT_AUTH_ROLE": "nope"})
    other.cookies = vclient.cookies
    response = other.get(f"{BASE}/secrets")
    assert response.status_code == 400 and "could not be found" in response.json()["message"]
    assert hashi.logins == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"SECRETS_UI_HASHICORP_VAULT_STORES": ""}, "must list the stores"),
        ({"SECRETS_UI_HASHICORP_VAULT_STORES": json.dumps([{"name": "a", "mount": "secret", "path": "../b"}])}, "folder path"),
        ({"SECRETS_UI_HASHICORP_VAULT_STORES": json.dumps([{"name": "a"}])}, "KV v2 mount"),
        ({"SECRETS_UI_HASHICORP_VAULT_STORES": json.dumps([{"name": "a b", "mount": "secret"}])}, "app role"),
        ({"SECRETS_UI_HASHICORP_VAULT_ADDR": "http://vault.example.test:8200"}, "https"),  # DevSkim: ignore DS137138 - asserts http is refused
        ({"SECRETS_UI_HASHICORP_VAULT_ADDR": "https://vault.example.test/v1"}, "no path"),
        ({"SECRETS_UI_HASHICORP_VAULT_AUTH_MOUNT": "../sys"}, "AUTH_MOUNT"),
        ({"SECRETS_UI_HASHICORP_VAULT_CA_FILE": "/nonexistent/ca.pem"}, "CA_FILE"),
    ],
)
def test_broken_vault_settings_fail_startup(vault_env, change, message):
    with pytest.raises(ConfigError, match=message):
        load_config({**vault_env, **change})


def test_a_private_ca_for_vault_loads_and_garbage_does_not(vault_env, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cfg = load_config({**vault_env, "SECRETS_UI_HASHICORP_VAULT_CA_FILE": str(ca)})
    assert cfg.hashicorp_vault is not None and cfg.hashicorp_vault.ca_file == ca
    create_app(cfg)
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("not a certificate")
    with pytest.raises(ConfigError, match="CA_FILE"):
        load_config({**vault_env, "SECRETS_UI_HASHICORP_VAULT_CA_FILE": str(garbage)})
