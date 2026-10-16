import json
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import GOOGLE_CLIENT, ORIGIN, FakeGoogle, FakeHashiVault, make_client

from secrets_ui.config import ConfigError, load_config

STORES = [{"name": "team-a-vault-dev", "mount": "secret", "path": "dev/team-a"}, {"name": "team-b-vault-dev", "mount": "secret", "path": "dev/team-b"}]


@pytest.fixture
def google_env(env):
    base = {k: v for k, v in env.items() if not k.startswith("AZURE_") and not k.startswith("SECRETS_UI_AZURE_")}
    return {
        **base,
        "SECRETS_UI_SIGN_IN": "google",
        "GOOGLE_CLIENT_ID": GOOGLE_CLIENT,
        "GOOGLE_CLIENT_SECRET": "google-secret",
        "SECRETS_UI_GOOGLE_DOMAINS": "example.test",
        "SECRETS_UI_PROVIDERS": "hashicorp-vault",
        "SECRETS_UI_HASHICORP_VAULT_ADDR": "https://vault.example.test:8200",
        "SECRETS_UI_HASHICORP_VAULT_STORES": json.dumps(STORES),
    }


@pytest.fixture
def google(world):
    world.google = FakeGoogle(groups=["team-a-vault-dev@example.test", "everyone@example.test", "team-b-vault-dev@elsewhere.test"])
    world.hashi = FakeHashiVault(
        world.google, folders={"team-a-vault-dev": "dev/team-a/"}, audience=GOOGLE_CLIENT, issuer="https://accounts.google.com"
    )
    world.hashi.put("dev/team-a/db", {"password": "s3cr3t-db"})
    return world.google


@pytest.fixture
def gclient(world, google_env, google):
    return make_client(world, google_env)


def google_sign_in(client, google, *, code="good-code"):
    login = client.get("/auth/login")
    assert login.status_code == 302
    url = urlsplit(login.headers["location"])
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    google.challenge, google.nonce = query["code_challenge"], query["nonce"]
    return url, query, client.get("/auth/callback", params={"code": code, "state": query["state"]})


def test_the_sign_in_goes_to_google_for_the_workspace_with_consent_and_offline_access(gclient, google):
    assert gclient.get("/auth/provider").json() == {"id": "google", "name": "Google"}
    url, query, _ = google_sign_in(gclient, google)
    assert f"{url.scheme}://{url.netloc}{url.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
    assert query["client_id"] == GOOGLE_CLIENT and query["redirect_uri"] == f"{ORIGIN}/auth/callback"
    assert query["scope"].split() == ["openid", "email", "profile", "https://www.googleapis.com/auth/cloud-identity.groups.readonly"]
    assert (query["access_type"], query["prompt"], query["hd"], query["code_challenge_method"]) == ("offline", "consent", "example.test", "S256")


def test_stores_come_from_the_persons_groups_in_the_workspace(gclient, google):
    _, _, callback = google_sign_in(gclient, google)
    assert callback.status_code == 303 and callback.headers["location"] == "/"
    me = gclient.get("/api/me").json()
    assert (me["name"], me["upn"]) == ("Grace Hopper", "grace@example.test")
    # team-b-vault-dev@elsewhere.test is outside the Workspace domains, so it names nothing.
    assert [s["name"] for s in me["stores"]] == ["team-a-vault-dev"]
    assert google.group_queries == ["member_key_id == 'grace@example.test'"] * 3
    code = google.token_requests[0]
    assert code["client_secret"] == ["google-secret"] and "code_verifier" in code


def test_vault_signs_the_person_in_with_a_fresh_google_id_token(gclient, google, world):
    google_sign_in(gclient, google)
    response = gclient.get("/api/stores/hashicorp-vault/team-a-vault-dev/secrets")
    assert response.status_code == 200, response.text
    assert [s["name"] for s in response.json()["secrets"]] == ["db"]
    refresh = google.token_requests[-1]
    # Google takes no scope on a refresh; offline_access is not one of its scopes.
    assert refresh["grant_type"] == ["refresh_token"] and "scope" not in refresh
    assert world.hashi.logins[0]["role"] == "secrets-ui"


@pytest.mark.parametrize("change", [{"hd": None}, {"hd": "elsewhere.test"}, {"email_verified": False}])
def test_an_account_outside_the_workspace_is_refused(gclient, google, change):
    for key, value in change.items():
        setattr(google, key, value)
    _, _, callback = google_sign_in(gclient, google)
    assert "auth_error=" in callback.headers["location"] and "Workspace" in parse_qs(urlsplit(callback.headers["location"]).query)["auth_error"][0]
    assert gclient.get("/api/me").status_code == 401


def test_groups_google_will_not_read_fail_the_sign_in_with_its_reason(gclient, google):
    google.groups_status = 403
    _, _, callback = google_sign_in(gclient, google)
    assert "permission" in parse_qs(urlsplit(callback.headers["location"]).query)["auth_error"][0]
    assert gclient.get("/api/me").status_code == 401


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"GOOGLE_CLIENT_ID": "not-a-client"}, "GOOGLE_CLIENT_ID"),
        ({"GOOGLE_CLIENT_SECRET": ""}, "GOOGLE_CLIENT_SECRET"),
        ({"SECRETS_UI_GOOGLE_DOMAINS": ""}, "SECRETS_UI_GOOGLE_DOMAINS"),
        ({"SECRETS_UI_GOOGLE_DOMAINS": "not a domain"}, "SECRETS_UI_GOOGLE_DOMAINS"),
        ({"SECRETS_UI_PROVIDERS": "azure-keyvault,hashicorp-vault"}, "Entra ID tokens only"),
        ({"SECRETS_UI_SIGN_IN": "okta"}, "entra or google"),
    ],
)
def test_broken_google_settings_fail_startup(google_env, change, message):
    with pytest.raises(ConfigError, match=message):
        load_config({**google_env, **change})


def test_google_sign_in_needs_no_azure_settings(google_env):
    cfg = load_config(google_env)
    assert (cfg.sign_in, cfg.client_id, cfg.google_domains, cfg.tenant_id) == ("google", GOOGLE_CLIENT, ("example.test",), "")
