import re

from secrets_ui.providers.azure_keyvault import _AUDIT_QUERY


def test_the_audit_query_reads_guid_columns_as_strings():
    lookups = re.findall(r'column_ifexists\("(\w+_g)"', _AUDIT_QUERY)
    assert lookups and re.findall(r'tostring\(column_ifexists\("(\w+_g)"', _AUDIT_QUERY) == lookups
