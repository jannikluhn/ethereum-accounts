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


testdata_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testdata')
official_test_vector_path = os.path.join(testdata_directory, 'official_keystore_tests.json')
pbkdf2_keystore_template_path = os.path.join(testdata_directory, 'pbkdf2_keystore_template.json')
scrypt_keystore_template_path = os.path.join(testdata_directory, 'scrypt_keystore_template.json')


def test_official_vectors():
    tests = json.load(open(official_test_vector_path))
    for name, test in tests.items():
        keystore = test['json']
        password = force_bytes(test['password'])
        private_key = add_0x_prefix(test['priv'])

        account = Account.from_keystore(keystore)
        account.unlock(password)
        assert account.private_key == private_key

        assert account.exposed_address is None


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


def test_account_locked_without_password(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template)
    assert account.is_locked()


def test_account_unlocked_with_password(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template, b'password')
    assert not account.is_locked()


def test_account_unlockable_with_password(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template)
    account.unlock(b'password')
    assert not account.is_locked()


def test_account_unlocking_fails_with_wrong_password(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template)
    wrong_passwords = [b'', b'asdf', b'PASSWORD']
    for password in wrong_passwords:
        with pytest.raises(DecryptionError):
            account.unlock(password)


def test_account_password_type_checks(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template)
    invalid_passwords = ['password', 123, None, pbkdf2_keystore_template]
    for password in invalid_passwords:
        with pytest.raises(TypeError):
            account.unlock(password)


def test_exposed_address(pbkdf2_keystore_template):
    account = Account.from_keystore(pbkdf2_keystore_template)
    exposed_address = account.exposed_address
    assert is_checksum_address(exposed_address)
    assert is_same_address(exposed_address, pbkdf2_keystore_template['address'])


def test_missing_address(pbkdf2_keystore_template):
    pbkdf2_keystore_template.pop('address')
    account = Account.from_keystore(pbkdf2_keystore_template)
    assert account.exposed_address is None


def test_missing_crypto(pbkdf2_keystore_template):
    pbkdf2_keystore_template.pop('crypto')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_missing_version(pbkdf2_keystore_template):
    pbkdf2_keystore_template.pop('version')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_version(pbkdf2_keystore_template):
    valid_versions = [3, '3', ' 3', '3 ', '3\n']
    for version in valid_versions:
        pbkdf2_keystore_template['version'] = version
        Account.from_keystore(pbkdf2_keystore_template)
    invalid_versions = ['', 'three', '3.0', '3.', '-1', '0', -1, 0]
    for version in invalid_versions:
        pbkdf2_keystore_template['version'] = version
        with pytest.raises(InvalidKeystore):
            Account.from_keystore(pbkdf2_keystore_template)
    unsupported_versions = ['1', '2', '4', 2, 1, 4]
    for version in unsupported_versions:
        pbkdf2_keystore_template['version'] = version
        with pytest.raises(UnsupportedKeystore):
            Account.from_keystore(pbkdf2_keystore_template)


def test_unknown_cipher(pbkdf2_keystore_template):
    unkown_ciphers = ['aes-128-ctr'.upper(), 'aes-256-ctr', 'aes-128-cbc', 'des-128-ctr', '']
    for cipher in unkown_ciphers:
        pbkdf2_keystore_template['crypto']['cipher'] = cipher
        with pytest.raises(UnsupportedKeystore):
            Account.from_keystore(pbkdf2_keystore_template)


def test_missing_iv_param(pbkdf2_keystore_template):
    pbkdf2_keystore_template['crypto']['cipherparams'].pop('iv')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_missing_ciphertext(pbkdf2_keystore_template):
    pbkdf2_keystore_template['crypto'].pop('ciphertext')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_missing_kdf(pbkdf2_keystore_template):
    pbkdf2_keystore_template['crypto'].pop('kdf')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_unknown_kdf(pbkdf2_keystore_template):
    unkown_kdfs = ['', 'test', 'SCRYPT', 'PBKDF2']
    for kdf in unkown_kdfs:
        pbkdf2_keystore_template['crypto']['kdf'] = kdf
        with pytest.raises(UnsupportedKeystore):
            Account.from_keystore(pbkdf2_keystore_template)


def test_missing_mac(pbkdf2_keystore_template):
    pbkdf2_keystore_template['crypto'].pop('mac')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_missing_kdf_params(pbkdf2_keystore_template):
    pbkdf2_keystore_template['crypto'].pop('kdfparams')
    with pytest.raises(InvalidKeystore):
        Account.from_keystore(pbkdf2_keystore_template)


def test_missing_pbkdf2_params(pbkdf2_keystore_template):
    params = ['c', 'dklen', 'prf', 'salt']
    for param in params:
        d = copy.deepcopy(pbkdf2_keystore_template)
        d['crypto']['kdfparams'].pop(param)
        with pytest.raises(InvalidKeystore):
            Account.from_keystore(d)


def test_missing_scrypt_params(scrypt_keystore_template):
    params = ['dklen', 'n', 'p', 'r', 'salt']
    for param in params:
        d = copy.deepcopy(scrypt_keystore_template)
        d['crypto']['kdfparams'].pop(param)
        with pytest.raises(InvalidKeystore):
            Account.from_keystore(d)
