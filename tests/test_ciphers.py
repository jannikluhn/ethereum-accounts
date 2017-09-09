import pytest

from eth_utils import (
    add_0x_prefix,
    decode_hex,
)

from eth_accounts.ciphers import (
    decrypt_aes_128_ctr,
    encrypt_aes_128_ctr,
    generate_aes_128_ctr_params,
    validate_aes_128_ctr,
)
from eth_accounts import InvalidKeystore


def test_valid_aes128ctr_ciphertext(keystore):
    ciphertext_template = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    valid_ciphertexts = [
        ciphertext_template,
        ciphertext_template[:-2]
    ]
    for ciphertext in valid_ciphertexts:
        keystore['crypto']['ciphertext'] = ciphertext
        validate_aes_128_ctr(keystore)


def test_invalid_aes128ctr_ciphertext(keystore):
    ciphertext_template = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    invalid_ciphertexts = [
        ciphertext_template[:-1],
        ciphertext_template + '01',
        'gg' * 32,
        ciphertext_template.upper(),
        add_0x_prefix(ciphertext_template),
        decode_hex(ciphertext_template)
    ]
    for ciphertext in invalid_ciphertexts:
        keystore['crypto']['ciphertext'] = ciphertext
        with pytest.raises(InvalidKeystore):
            validate_aes_128_ctr(keystore)


def test_valid_aes128ctr_cipherparams(keystore):
    valid_params = [{'iv': v} for v in [
        '0123456789abcdef0123456789abcdef'
    ]]
    for params in valid_params:
        keystore['crypto']['cipherparams'] = params
        validate_aes_128_ctr(keystore)


def test_invalid_aes128ctr_cipherparams(keystore):
    iv_template = '0123456789abcdef0123456789abcdef'
    valid_params = [
        {'iv': iv_template + '01'},
        {'iv': iv_template[:-2]},
        {'iv': iv_template.upper()},
        {'iv': add_0x_prefix(iv_template)},
        {'iv': None},
        {'iv': 1},
        {'iv': [iv_template]},
        {},
        {'iv': iv_template, 'vi': iv_template}
    ]
    for params in valid_params:
        keystore['crypto']['cipherparams'] = params
        with pytest.raises(InvalidKeystore):
            validate_aes_128_ctr(keystore)


def test_aes128ctr_param_generation():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    plaintext = '6bc1bee22e409f96e93d7e117393172a'
    for _ in range(100):
        params = generate_aes_128_ctr_params()
        ciphertext = encrypt_aes_128_ctr(plaintext, key, params)
        decrypted = decrypt_aes_128_ctr(ciphertext, key, params)
        assert decrypted == plaintext


def test_aes128ctr_encryption():
    # from Dworkin, M. (2001). Recommendation for block cipher modes of operation. methods and
    # techniques (No. NIST-SP-800-38A). NATIONAL INST OF STANDARDS AND TECHNOLOGY GAITHERSBURG MD
    # COMPUTER SECURITY DIV. ISO 690
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    params = {'iv': 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'}
    plaintext = '6bc1bee22e409f96e93d7e117393172a'
    ciphertext = '874d6191b620e3261bef6864990db6ce'
    encrypted = encrypt_aes_128_ctr(plaintext, key, params)
    assert encrypted == ciphertext


def test_aes128ctr_decryption():
    # from Dworkin, M. (2001). Recommendation for block cipher modes of operation. methods and
    # techniques (No. NIST-SP-800-38A). NATIONAL INST OF STANDARDS AND TECHNOLOGY GAITHERSBURG MD
    # COMPUTER SECURITY DIV. ISO 690
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    params = {'iv': 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'}
    plaintext = '6bc1bee22e409f96e93d7e117393172a'
    ciphertext = '874d6191b620e3261bef6864990db6ce'
    decrypted = decrypt_aes_128_ctr(ciphertext, key, params)
    assert decrypted == plaintext
