import pytest
from io import StringIO
import os
import uuid

from eth_utils import (
    encode_hex,
    is_same_address,
    remove_0x_prefix,
)

from eth_accounts import Account, UnsupportedKeystore
from eth_accounts.kdfs import kdf_param_generators
from eth_accounts.ciphers import cipher_param_generators


def test_validity():
    account = Account.new()
    scrypt_keystore_dict = account.to_keystore_dict(b'password', kdf='scrypt')
    pbkdf2_keystore_dict = account.to_keystore_dict(b'password', kdf='pbkdf2')
    recovered_scrypt_account = Account.from_keystore(scrypt_keystore_dict, b'password')
    recovered_pbkdf2_account = Account.from_keystore(pbkdf2_keystore_dict, b'password')
    assert recovered_scrypt_account.private_key == account.private_key
    assert recovered_pbkdf2_account.private_key == account.private_key


def test_exposed_address():
    account = Account.new()
    keystore_dict_with_address = account.to_keystore_dict(b'password', expose_address=True)
    assert 'address' in keystore_dict_with_address
    assert is_same_address(keystore_dict_with_address['address'], account.address)

    keystore_dict_without_address = account.to_keystore_dict(b'password', expose_address=False)
    assert 'address' not in keystore_dict_without_address


def test_id():
    account = Account.new()
    keystore_dict_with_default_uuid = account.to_keystore_dict(b'password', id=True)
    assert 'id' in keystore_dict_with_default_uuid
    uuid.UUID(keystore_dict_with_default_uuid['id'])  # validates UUID

    custom_uuid = uuid.uuid4()
    keystore_dict_with_custom_uuid = account.to_keystore_dict(b'password', id=custom_uuid)
    assert 'id' in keystore_dict_with_custom_uuid
    assert keystore_dict_with_custom_uuid['id'] == str(custom_uuid)

    keystore_dict_without_uuid = account.to_keystore_dict(b'password', id=None)
    assert 'id' not in keystore_dict_without_uuid


def test_cipher():
    account = Account.new()
    keystore_dict = account.to_keystore_dict(b'password', cipher='aes-128-ctr')
    assert 'cipher' in keystore_dict['crypto']
    assert keystore_dict['crypto']['cipher'] == 'aes-128-ctr'

    with pytest.raises(UnsupportedKeystore):
        account.to_keystore_dict(b'password', cipher='aes-128-cbc')


def test_cipher_params():
    account = Account.new()
    cipher_params = cipher_param_generators['aes-128-ctr']()
    keystore_dict = account.to_keystore_dict(b'password', cipher_params=cipher_params)
    assert keystore_dict['crypto']['cipherparams'] == cipher_params


def test_kdf():
    account = Account.new()
    kdfs = ['scrypt', 'pbkdf2']
    for kdf in kdfs:
        keystore_dict = account.to_keystore_dict(b'password', kdf=kdf)
        assert keystore_dict['crypto']['kdf'] == kdf
    with pytest.raises(UnsupportedKeystore):
        account.to_keystore_dict(b'password', kdf='test')


def test_kdf_params():
    account = Account.new()
    kdf_params = kdf_param_generators['scrypt']()
    keystore_dict = account.to_keystore_dict(b'password', kdf_params=kdf_params)
    assert keystore_dict['crypto']['kdfparams'] == kdf_params

    kdf_param_replacements = {
        'salt': remove_0x_prefix(encode_hex(os.urandom(16))),
    }
    keystore_dict = account.to_keystore_dict(b'password', kdf_params=kdf_param_replacements)
    assert keystore_dict['crypto']['kdfparams']['salt'] == kdf_param_replacements['salt']
    Account.from_keystore(keystore_dict, b'password')  # tests that other params are still there


def test_write_to_file():
    account = Account.new()
    f = StringIO()
    account.to_keystore(f, b'password')
    f.seek(0)
    recovered_account = Account.from_keystore(f, b'password')
    assert recovered_account.private_key == account.private_key
