import pytest

from eth_utils import (
    add_0x_prefix,
    decode_hex,
    remove_0x_prefix,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)

from eth_accounts.ciphers import ciphers
from eth_accounts.kdfs import kdfs
from eth_accounts.validation import validate_keystore
from eth_accounts import (
    InvalidKeystore,
    UnsupportedKeystore,
)

from .fixtures import keystore


def test_template_valid(keystore):
    validate_keystore(keystore)


def test_no_missing_required_fields():
    required_fields = ['crypto', 'version']
    for field in required_fields:
        k = keystore()
        k.pop(field)
        with pytest.raises(InvalidKeystore):
            validate_keystore(k)


def test_optional_fields():
    optional_present = ['id', 'address']
    optional_missing = [
        ('name', 'test'),
        ('meta', 'test')
    ]
    for field in optional_present:
        k = keystore()
        k.pop(field)
        validate_keystore(k)
    for field, value in optional_missing:
        k = keystore()
        k[field] = value
        validate_keystore(k)


def test_no_missing_crypto_fields():
    required_fields = ['cipher', 'cipherparams', 'ciphertext', 'kdf', 'kdfparams', 'mac']
    for field in required_fields:
        k = keystore()
        k['crypto'].pop(field)
        with pytest.raises(InvalidKeystore):
            validate_keystore(k)


def test_no_additional_crypto_fields():
    additional_fields = [
        ('test', 'test'),
        ('CIPHER', {})
    ]
    for field, value in additional_fields:
        k = keystore()
        k['crypto'][field] = value
        with pytest.raises(InvalidKeystore):
            validate_keystore(k)


def test_supported_versions(keystore):
    valid_versions = [3]
    for version in valid_versions:
        keystore['version'] = version
        validate_keystore(keystore)


def test_invalid_versions(keystore):
    invalid_versions = [3.0, '3', '3.0', 'three', -1, None, [], {}, [3], {3: 3}]
    for version in invalid_versions:
        keystore['version'] = version
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_unsupported_versions(keystore):
    unsupported_versions = [1, 2, 4]
    for version in unsupported_versions:
        keystore['version'] = version
        with pytest.raises(UnsupportedKeystore):
            validate_keystore(keystore)


def test_valid_addresses(keystore):
    address_template = '0123456789abcdef0123456789abcdef01234567'
    valid_addresses = [
        to_normalized_address(address_template),
        remove_0x_prefix(to_normalized_address(address_template)),
        to_checksum_address(address_template),
        remove_0x_prefix(to_checksum_address(address_template)),
        address_template.upper(),
        add_0x_prefix(address_template.upper())
    ]
    for address in valid_addresses:
        keystore['address'] = address
        validate_keystore(keystore)


def test_invalid_addresses(keystore):
    address_template = '0123456789abcdef0123456789abcdef01234567'
    valid_addresses = [
        address_template[:-2],
        address_template + '89',
        to_canonical_address(address_template),
        'gg' * 20,
        None,
        0,
        {},
        [],
        [address_template]
    ]
    for address in valid_addresses:
        keystore['address'] = address
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_valid_meta(keystore):
    valid_meta = ['', 'test']
    for meta in valid_meta:
        keystore['meta'] = meta
        validate_keystore(keystore)


def test_invalid_meta(keystore):
    invalid_meta = [0, None, {}, [], ['meta'], {'meta': 'meta'}]
    for meta in invalid_meta:
        keystore['meta'] = meta
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_valid_name(keystore):
    valid_names = ['', 'test']
    for name in valid_names:
        keystore['name'] = name
        validate_keystore(keystore)


def test_invalid_name(keystore):
    invalid_names = [0, None, {}, [], ['meta'], {'meta': 'meta'}]
    for name in invalid_names:
        keystore['name'] = name
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_valid_macs(keystore):
    valid_macs = ['0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']
    for mac in valid_macs:
        keystore['crypto']['mac'] = mac
        validate_keystore(keystore)


def test_invalid_macs(keystore):
    mac_template = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    invalid_macs = [
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF',
        mac_template.upper(),
        mac_template[:-2],
        mac_template + '01',
        'gg' * 32,
        add_0x_prefix(mac_template),
        decode_hex(mac_template)
    ]
    for mac in invalid_macs:
        keystore['crypto']['mac'] = mac
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_unsupported_ciphers(keystore):
    unsupported_ciphers = ['', 'test']
    for cipher in unsupported_ciphers:
        assert cipher not in ciphers
        keystore['crypto']['cipher'] = cipher
        with pytest.raises(UnsupportedKeystore):
            validate_keystore(keystore)


def test_invalid_ciphers(keystore):
    invalid_ciphers = [5, None, [], {}]
    for cipher in invalid_ciphers:
        keystore['crypto']['cipher'] = cipher
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_invalid_cipher_params(keystore):
    invalid_params = [5, None, [], 'params']
    for params in invalid_params:
        keystore['crypto']['cipherparams'] = params
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_unsupported_kdfs(keystore):
    unsupported_kdfs = ['', 'test']
    for kdf in unsupported_kdfs:
        assert kdf not in kdfs
        keystore['crypto']['kdf'] = kdf
        with pytest.raises(UnsupportedKeystore):
            validate_keystore(keystore)


def test_invalid_kdfs(keystore):
    invalid_kdfs = [5, None, [], {}]
    for kdf in invalid_kdfs:
        keystore['crypto']['kdf'] = kdf
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)


def test_invalid_kdf_params(keystore):
    invalid_params = [5, None, [], 'params']
    for params in invalid_params:
        keystore['crypto']['kdfparams'] = params
        with pytest.raises(InvalidKeystore):
            validate_keystore(keystore)
