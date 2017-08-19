import pytest
import json
import os
from io import StringIO
from eth_utils import force_bytes
from eth_accounts import private_key_from_keystore, DecryptionError


official_test_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                  'official_keystore_tests.json')
official_tests = json.load(open(official_test_path))


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_official_reading(keystore_dict, password, private_key):
    assert private_key_from_keystore(keystore_dict, force_bytes(password)) == private_key
    with pytest.raises(DecryptionError):
        private_key_from_keystore(keystore_dict, force_bytes(password * 2))


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_official_reading_filelike(keystore_dict, password, private_key):
    f = StringIO(json.dumps(keystore_dict))
    assert private_key_from_keystore(f, force_bytes(password)) == private_key
