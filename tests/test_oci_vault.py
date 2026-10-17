import base64
import json
import logging

import pytest
from conftest import OCI_BUNDLES, OCI_DOMAIN, FakeOci, make_client, sign_in, write_headers

from secrets_ui.config import ConfigError, load_config

COMPARTMENT = "ocid1.compartment.oc1..aaaateam"
VAULT = "ocid1.vault.oc1.eu-amsterdam-1.aaaavault"
KEY = "ocid1.key.oc1.eu-amsterdam-1.aaaavault.aaaakey"
STORES = [
    {"name": "team-a-oci-dev", "label": "Team A (OCI)", "compartment": COMPARTMENT, "vault": VAULT, "key": KEY},
    {"name": "team-b-oci-dev", "compartment": COMPARTMENT, "vault": VAULT, "key": KEY},
]
BASE = "/api/stores/oci-vault/team-a-oci-dev"


@pytest.fixture
def oci_env(env):
    return {
        **env,
        "SECRETS_UI_PROVIDERS": "azure-keyvault,oci-vault",
        "SECRETS_UI_OCI_REGION": "eu-amsterdam-1",
        "SECRETS_UI_OCI_DOMAIN_URL": f"https://{OCI_DOMAIN}",
        "SECRETS_UI_OCI_CLIENT_ID": "oci-app",
        "SECRETS_UI_OCI_CLIENT_SECRET": "oci-secret",
        "SECRETS_UI_OCI_STORES": json.dumps(STORES),
    }


@pytest.fixture
def oci(world):
    world.oci = FakeOci(world.entra)
    world.oci.put("db-password", "first", "s3cr3t-db")
    world.oci.put("smtp", "relay-password")
    return world.oci


@pytest.fixture
def oclient(world, oci_env, oci):
    return make_client(world, oci_env)


def test_an_oci_store_shows_when_a_role_names_it(oclient, world):
    me = sign_in(oclient, world)
    assert [(s["name"], s["label"], s["location"]) for s in me["stores"] if s["provider"] == "oci-vault"] == [("team-a-oci-dev", "Team A (OCI)", VAULT)]
    assert oclient.get("/api/stores/oci-vault/team-b-oci-dev/secrets").json()["error"] == "store_not_allowed"


def test_the_person_gets_an_oci_session_token_for_their_own_id_token(oclient, world, oci):
    sign_in(oclient, world)
    response = oclient.get(f"{BASE}/secrets")
    assert response.status_code == 200, response.text
    assert [s["name"] for s in response.json()["secrets"]] == ["db-password", "smtp"]
    (exchange,) = oci.exchanges
    assert exchange["requested_token_type"] == ["urn:oci:token-type:oci-upst"] and exchange["subject_token_type"] == ["jwt"]
    assert exchange["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"] and exchange["public_key"]
    # Every call was signed with the key the session token is bound to (the fake answers 401 otherwise).
    listing = [c for c in oci.calls if c.method == "GET"]
    assert all(c.url.params["compartmentId"] == COMPARTMENT and c.url.params["vaultId"] == VAULT for c in listing)
    assert oclient.get(f"{BASE}/secrets").status_code == 200 and len(oci.exchanges) == 1


def test_reveal_decodes_the_bundle_and_never_logs_it(oclient, world, oci, caplog):
    me = sign_in(oclient, world)
    with caplog.at_level(logging.INFO):
        response = oclient.post(f"{BASE}/secrets/db-password/reveal", headers=write_headers(me))
    assert response.status_code == 200 and response.json() == {"value": "s3cr3t-db"}
    assert [c for c in oci.calls if c.url.host == OCI_BUNDLES][-1].url.path.endswith("/secretbundles/ocid1.vaultsecret.oc1.eu-amsterdam-1.0001")
    assert "s3cr3t" not in caplog.text


def test_create_goes_into_the_stores_vault_with_its_key_and_a_new_version_updates(oclient, world, oci):
    me = sign_in(oclient, world)
    assert oclient.post(f"{BASE}/secrets", headers=write_headers(me), json={"name": "smtp", "value": "x"}).status_code == 409
    created = oclient.post(f"{BASE}/secrets", headers=write_headers(me), json={"name": "api-token", "value": "tok"})
    assert created.status_code == 201, created.text
    new = next(s for s in oci.secrets.values() if s["name"] == "api-token")
    assert new["created_with"] == {"compartmentId": COMPARTMENT, "vaultId": VAULT, "keyId": KEY}
    assert base64.b64decode(new["versions"][0]["content"]) == b"tok"
    assert oclient.post(f"{BASE}/secrets/smtp/versions", headers=write_headers(me), json={"value": "rotated"}).status_code == 201
    assert len(next(s for s in oci.secrets.values() if s["name"] == "smtp")["versions"]) == 2


def test_versions_and_restore_point_the_secret_back_without_moving_a_value(oclient, world, oci):
    me = sign_in(oclient, world)
    versions = oclient.get(f"{BASE}/secrets/db-password/versions").json()["versions"]
    assert [(v["version"], v["current"]) for v in versions] == [("2", True), ("1", False)]
    assert oclient.post(f"{BASE}/secrets/db-password/reveal", headers=write_headers(me), json={"version": "1"}).json() == {"value": "first"}
    assert oclient.post(f"{BASE}/secrets/db-password/restore", headers=write_headers(me), json={"version": "1"}).status_code == 200
    put = [c for c in oci.calls if c.method == "PUT"][-1]
    assert json.loads(put.content) == {"currentVersionNumber": 1}
    assert oclient.post(f"{BASE}/secrets/db-password/reveal", headers=write_headers(me)).json() == {"value": "first"}


def test_delete_schedules_deletion_and_recover_cancels_it(oclient, world, oci):
    me = sign_in(oclient, world)
    assert oclient.delete(f"{BASE}/secrets/smtp", headers=write_headers(me)).status_code == 200
    assert [s["name"] for s in oclient.get(f"{BASE}/secrets").json()["secrets"]] == ["db-password"]
    deleted = oclient.get(f"{BASE}/deleted").json()["secrets"]
    assert [d["name"] for d in deleted] == ["smtp"] and deleted[0]["purge_at"]
    assert oclient.post(f"{BASE}/deleted/smtp/recover", headers=write_headers(me)).status_code == 200
    assert [s["name"] for s in oclient.get(f"{BASE}/secrets").json()["secrets"]] == ["db-password", "smtp"]


def test_a_refused_token_exchange_says_why(oclient, world, oci_env):
    sign_in(oclient, world)
    other = make_client(world, {**oci_env, "SECRETS_UI_OCI_CLIENT_SECRET": "wrong"})
    other.cookies = oclient.cookies
    response = other.get(f"{BASE}/secrets")
    assert response.status_code == 403 and "token exchange" in response.json()["message"]


def test_a_kustomize_example_reads_the_secret_by_name(oclient, world):
    sign_in(oclient, world)
    manifest = oclient.get(f"{BASE}/secrets/db-password/external-secret").json()["files"]["externalsecret.yaml"]
    assert "name: team-a-oci-dev" in manifest and "secretKey: DB_PASSWORD" in manifest and "key: db-password" in manifest


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"SECRETS_UI_OCI_STORES": ""}, "must list the stores"),
        ({"SECRETS_UI_OCI_STORES": json.dumps([{**STORES[0], "vault": "ocid1.key.oc1.x.y"}])}, "OCID of its vault"),
        ({"SECRETS_UI_OCI_STORES": json.dumps([{**STORES[0], "key": ""}])}, "OCID of its key"),
        ({"SECRETS_UI_OCI_REGION": "amsterdam"}, "SECRETS_UI_OCI_REGION"),
        ({"SECRETS_UI_OCI_DOMAIN_URL": "http://idcs.example.com"}, "https"),  # DevSkim: ignore DS137138 - asserts http is refused
        ({"SECRETS_UI_OCI_CLIENT_SECRET": ""}, "SECRETS_UI_OCI_CLIENT_ID"),
    ],
)
def test_broken_oci_settings_fail_startup(oci_env, change, message):
    with pytest.raises(ConfigError, match=message):
        load_config({**oci_env, **change})
