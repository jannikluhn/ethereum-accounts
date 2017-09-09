import pytest
import copy
import json
import os

from eth_utils import (
    add_0x_prefix,
    force_bytes,
    is_checksum_address,
    is_same_address,
)

from eth_accounts import (
    Account,
    DecryptionError,
    InvalidKeystore,
    UnsupportedKeystore,
)

from eth_accounts.validation import validate_keystore


testdata_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testdata')
official_test_vector_path = os.path.join(testdata_directory, 'official_keystore_tests.json')
pbkdf2_keystore_template_path = os.path.join(testdata_directory, 'pbkdf2_keystore_template.json')
scrypt_keystore_template_path = os.path.join(testdata_directory, 'scrypt_keystore_template.json')
parity_keystore_path = os.path.join(testdata_directory, 'parity_keystore.json')
geth_keystore_path = os.path.join(testdata_directory, 'geth_keystore.json')


def test_official_vectors():
    tests = json.load(open(official_test_vector_path))
    for name, test in tests.items():
        keystore = test['json']
        password = force_bytes(test['password'])
        private_key = add_0x_prefix(test['priv'])

        account = Account.from_keystore(keystore, password)
        assert account.private_key == private_key

        assert account.exposed_address is None


def test_parity():
    account = Account.from_keystore(open(parity_keystore_path), b'password')
    target_private_key = '0x2c535b74a0c4b339c669ba5b508b30c90801069b5bc5a1e0ae865e5c4f9e82cd'
    assert account.private_key == target_private_key
    assert account.address == '0xa82293681EA20394156c6b7B4773982Ccdf21aA4'
    assert account.id == '3f9bc902-7b09-f848-d9b5-3d8f925e6df4'


def test_geth():
    account = Account.from_keystore(open(geth_keystore_path), b'password')
    target_private_key = '0x13d39071f135b8a7a5f770172275d7400b3b181fa35227b722670800dd2b2ba9'
    assert account.private_key == target_private_key
    assert account.address == '0xbe43b4967B81e3a14C6CeCac2e1A89B4E681Cab5'
    assert account.id == '02068fb6-1388-45e1-9071-b8a379fd5474'


@pytest.fixture
def pbkdf2_keystore_template():
    with open(pbkdf2_keystore_template_path) as f:
        d = json.load(f)
    return d


@pytest.fixture
def scrypt_keystore_template():
    with open(scrypt_keystore_template_path) as f:
        d = json.load(f)
    return d


def test_account_unlocking_fails_with_wrong_password(pbkdf2_keystore_template):
    wrong_passwords = [b'', b'asdf', b'PASSWORD']
    for password in wrong_passwords:
        with pytest.raises(DecryptionError):
            Account.from_keystore(pbkdf2_keystore_template, password)


def test_account_password_type_checks(pbkdf2_keystore_template):
    invalid_passwords = ['password', 123, None, pbkdf2_keystore_template]
    for password in invalid_passwords:
        with pytest.raises(TypeError):
            Account.from_keystore(pbkdf2_keystore_template, password)


def test_exposed_address(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template, b'password')
    exposed_address = account.exposed_address
    assert is_checksum_address(exposed_address)
    assert is_same_address(exposed_address, pbkdf2_keystore_template['address'])
    assert is_same_address(exposed_address, account.address)
