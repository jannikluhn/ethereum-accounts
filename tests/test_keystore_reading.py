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
    InvalidKeystore,
    MissingAddress,
    UnsupportedKeystore,
)

testdata_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testdata')
valid_test_vector_files = [
    'official_keystore_tests'
    'geth/v2_test_vector.json'
]
failing_test_vector_files = [
    ('geth/v1_test_vector.json', UnsupportedKeystore),
]
plain_valid_keystores = [
    {
        'path': 'geth/very-light-scrypt',
        'password': b'',
        'address': '0x45dea0fb0bba44f4fcf290bba71fd57d7117cbb8',
    },
    {
        'path': 'geth/aaa',
        'password': b'foobar',
        'address': '0xf466859ead1932d743d622cb74fc058882e8648a',
    },
    {
        'path': 'geth/zzz',
        'password': b'foobar',
        'address': '0x289d485d9771714cce91d3393d764e1311907acc',
    },
    {
        'path': 'geth/UTC--2016-03-22T12-57-55.920751759Z--7ef5a6135f1fd6a02593eedc869c6d41d934aef8',
        'password': b'foobar',
        'address': '0x7ef5a6135f1fd6a02593eedc869c6d41d934aef8',
    },
    {
        'path': 'geth/no-address',
        'password': b'foobar',
        'address': '0xf466859ead1932d743d622cb74fc058882e8648a',
    }
]
plain_invalid_keystores = [
    {
        'path': 'geth/garbage',
        'error': InvalidKeystore,
    },
    {
        'path': 'geth/empty',
        'error': InvalidKeystore,
    },
    {
        'path': 'geth/empty',
        'error': InvalidKeystore,
    }
]


@pytest.mark.parametrize('keystore_dict,password,private_key', [
    (d['json'], d['password'], d['priv']) for d in official_tests.values()
])
def test_vector_reading(keystore_dict, password, private_key):
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
