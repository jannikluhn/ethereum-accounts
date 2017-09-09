import pytest

from eth_utils import (
    encode_hex,
    force_bytes,
    pad_left,
    remove_0x_prefix,
)

from eth_accounts import InvalidKeystore
from eth_accounts.kdfs import (
    derive_pbkdf2_key,
    derive_scrypt_key,
    generate_pbkdf2_params,
    generate_scrypt_params,
    validate_pbkdf2,
    validate_scrypt,
)

from .fixtures import (
    pbkdf2_keystore,
    scrypt_keystore,
)


def test_missing_scrypt_params():
    required_params = ['dklen', 'r', 'salt', 'p', 'n']
    for param in required_params:
        keystore = scrypt_keystore()
        keystore['crypto']['kdfparams'].pop(param)
        with pytest.raises(InvalidKeystore):
            validate_scrypt(keystore)


def test_additional_scrypt_params():
    additional_params = ['', 'test']
    for param in additional_params:
        keystore = scrypt_keystore()
        keystore['crypto']['kdfparams'][param] = 2
        with pytest.raises(InvalidKeystore):
            validate_scrypt(keystore)


def test_scrypt_param_generation(scrypt_keystore):
    for _ in range(100):
        params = generate_scrypt_params()
        scrypt_keystore['crypto']['kdfparams'] = params
        validate_scrypt(scrypt_keystore)


# from https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-11
@pytest.mark.parametrize(['password', 'salt', 'n', 'r', 'p', 'dklen', 'key'], [
    ['', '', 16, 1, 1, 64,
     '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442'
     'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'],
    ['password', 'NaCl', 1024, 8, 16, 64,
     'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
     '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'],
    ['pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64,
     '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2'
     'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'],
    ['pleaseletmein', 'SodiumChloride', 1048576, 8, 1, 64,
     '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47'
     '8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4']
])
def test_scrypt_vectors(password, salt, n, r, p, dklen, key):
    params = {
        'salt': remove_0x_prefix(encode_hex(force_bytes(salt, 'ascii'))),
        'n': n,
        'r': r,
        'p': p,
        'dklen': dklen
    }
    derived = remove_0x_prefix(derive_scrypt_key(password, params))
    assert key == derived


def test_missing_pbkdf2_params():
    required_params = ['dklen', 'c', 'prf', 'salt']
    for param in required_params:
        keystore = pbkdf2_keystore()
        keystore['crypto']['kdfparams'].pop(param)
        with pytest.raises(InvalidKeystore):
            validate_pbkdf2(keystore)


def test_additional_pbkdf2_params():
    additional_params = ['', 'test']
    for param in additional_params:
        keystore = pbkdf2_keystore()
        keystore['crypto']['kdfparams'][param] = 2
        with pytest.raises(InvalidKeystore):
            validate_pbkdf2(keystore)


def test_pbkdf2_param_generation(pbkdf2_keystore):
    for _ in range(100):
        params = generate_pbkdf2_params()
        pbkdf2_keystore['crypto']['kdfparams'] = params
        validate_pbkdf2(pbkdf2_keystore)


# from https://stackoverflow.com/a/5130543
@pytest.mark.parametrize(['password', 'salt', 'c', 'dklen', 'key'], [
    [b'password', b'salt', 1, 20, '120fb6cffcf8b32c43e7225256c4f837a86548c9'],
    [b'password', b'salt', 2, 20, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8e'],
    [b'password', b'salt', 4096, 20, 'c5e478d59288c841aa530db6845c4c8d962893a0'],
    [b'password', b'salt', 16777216, 20, 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e8'],
    [b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25,
     '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c'],
    [b'pass\0word', b'sa\0lt', 4096, 16, '89b69d0516f829893c696226650a8687']
])
def test_pbkdf2_vectors(password, salt, c, dklen, key):
    params = {
        'salt': remove_0x_prefix(encode_hex(salt)),
        'c': c,
        'dklen': dklen,
        'prf': 'hmac-sha256'
    }
    derived = remove_0x_prefix(derive_pbkdf2_key(password, params))
    assert key == derived
