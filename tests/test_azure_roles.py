import re

import pytest

from secrets_ui.providers.azure_keyvault import is_vault_name, vaults_from_roles

TEAMS = re.compile(r"^(alpha|beta)-keyvault-(dev|tst|acc|prd)$")


def test_only_roles_matching_the_pattern_become_vaults():
    roles = ["alpha-keyvault-dev", "beta-keyvault-prd", "privileged-keyvault-prd", "gamma-keyvault-dev", "admin"]
    assert vaults_from_roles(roles, TEAMS) == ("alpha-keyvault-dev", "beta-keyvault-prd")


def test_a_privileged_vault_stays_out_even_when_its_role_is_assigned():
    assert vaults_from_roles(["privileged-keyvault-prd"], TEAMS) == ()


def test_the_pattern_must_match_the_whole_role():
    assert vaults_from_roles(["alpha-keyvault-dev-old", "x-alpha-keyvault-dev"], TEAMS) == ()


def test_duplicates_collapse_and_the_result_is_sorted():
    assert vaults_from_roles(["beta-keyvault-tst", "alpha-keyvault-acc", "beta-keyvault-tst"], TEAMS) == (
        "alpha-keyvault-acc",
        "beta-keyvault-tst",
    )


@pytest.mark.parametrize("roles", [None, "alpha-keyvault-dev", {"alpha-keyvault-dev": True}, [1, None, ["x"]]])
def test_a_malformed_roles_claim_grants_nothing(roles):
    assert vaults_from_roles(roles, re.compile(".+")) == ()


@pytest.mark.parametrize(
    "role",
    [
        "Alpha-keyvault-dev",  # upper case
        "alpha--keyvault-dev",  # consecutive hyphens
        "alpha-keyvault-dev-",  # trailing hyphen
        "1alpha-keyvault",  # leading digit
        "ab",  # too short
        "a" * 25,  # too long
        "alpha.keyvault.dev",  # dots would change the host
        "alpha-keyvault-dev/../x",
    ],
)
def test_roles_that_are_not_key_vault_names_are_ignored_whatever_the_pattern(role):
    assert not is_vault_name(role)
    assert vaults_from_roles([role], re.compile(".*")) == ()


def test_valid_names():
    assert all(is_vault_name(n) for n in ["kv1", "alpha-keyvault-dev", "a" * 24, "a1-b2-c3"])
