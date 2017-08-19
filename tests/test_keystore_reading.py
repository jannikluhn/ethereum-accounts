import pytest
import json
import os
from io import StringIO

from eth_utils import (
    force_bytes,
    is_checksum_address,
    is_same_address,
)

from eth_accounts import (
    address_from_keystore,
    private_key_to_address,
    private_key_from_keystore,
    private_key_to_public_key,
    public_key_from_keystore,
    DecryptionError,
    MissingAddress,
)

official_test_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                  'official_keystore_tests.json')
official_tests = json.load(open(official_test_path))


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_official_reading(keystore_dict, password, private_key):
    # should recover correct private key
    extracted_private_key = private_key_from_keystore(keystore_dict, force_bytes(password))
    assert extracted_private_key == private_key
    # should recover correct public key
    extracted_public_key = public_key_from_keystore(keystore_dict, force_bytes(password))
    assert extracted_public_key == private_key_to_public_key(private_key)
    # should fail with wrong password
    with pytest.raises(DecryptionError):
        private_key_from_keystore(keystore_dict, force_bytes(password * 2))


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_official_reading_filelike(keystore_dict, password, private_key):
    f = StringIO(json.dumps(keystore_dict))
    assert private_key_from_keystore(f, force_bytes(password)) == private_key


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_address_recovery(keystore_dict, password, private_key):
    try:
        address = address_from_keystore(keystore_dict)
    except MissingAddress:
        assert 'address' not in keystore_dict
    else:
        assert is_same_address(address, private_key_to_address(private_key))
        assert is_checksum_address(address)

    address = address_from_keystore(keystore_dict, force_bytes(password))
    assert is_same_address(address, private_key_to_address(private_key))
    assert is_checksum_address(address)
