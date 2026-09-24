"""Full-width system ID configuration through both web forms."""
import pytest
from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, fetch_entry, login_as)


@pytest.mark.parametrize('admin', [False, True])
@pytest.mark.parametrize('sysid', [0, 255, 256, 0x80000000, 0xFFFFFFFF, -1, 0x100000000])
def test_fc_sysid_range(client, keydb_path, admin, sysid):
    login_as(client, BOB_PORT1 if admin else ALICE_PORT1,
             BOB_PASS if admin else ALICE_PASS)
    url = '/admin/%d' % ALICE_PORT2 if admin else '/me/'
    data = {'name': 'alice', 'fc_sysid': str(sysid), 'submit': 'Save'}
    if admin:
        data.update(port1=str(ALICE_PORT1), port2=str(ALICE_PORT2))
    result = client.post(url, data=data)
    if 0 <= sysid <= 0xFFFFFFFF:
        assert result.status_code == 302
        assert fetch_entry(keydb_path, ALICE_PORT2).fc_sysid == sysid
    else:
        assert result.status_code == 200
        assert fetch_entry(keydb_path, ALICE_PORT2).fc_sysid == 0
