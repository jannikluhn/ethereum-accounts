from hashlib import pbkdf2_hmac
import json
import os

from eth_utils import (
    decode_hex,
    encode_hex,
    remove_0x_prefix,
)
import jsonschema
import scrypt

from .exceptions import (
    InvalidKeystore,
)


pbkdf2_schema_path = os.path.join(os.path.dirname(__file__), 'schemas/kdf_pbkdf2_schema.json')
scrypt_schema_path = os.path.join(os.path.dirname(__file__), 'schemas/kdf_scrypt_schema.json')
with open(pbkdf2_schema_path) as f:
    pbkdf2_schema = json.load(f)
with open(scrypt_schema_path) as f:
    scrypt_schema = json.load(f)


def validate_pbkdf2(keystore):
    try:
        jsonschema.validate(keystore['crypto'], pbkdf2_schema)
    except jsonschema.ValidationError:
        raise InvalidKeystore('Invalid keystore KDF format')
    # TODO: validate parameter values


def validate_scrypt(keystore):
    try:
        jsonschema.validate(keystore['crypto'], scrypt_schema)
    except jsonschema.ValidationError:
        raise InvalidKeystore('Invalid keystore KDF format')
    # TODO: validate parameter values


def derive_pbkdf2_key(password, params):
    salt = decode_hex(params['salt'])
    dklen = params['dklen']
    iterations = params['c']
    full_key = pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    assert len(full_key) == dklen
    return encode_hex(full_key)


def derive_scrypt_key(password, params):
    salt = decode_hex(params['salt'])
    n = params['n']
    r = params['r']
    p = params['p']
    dklen = params['dklen']
    return encode_hex(scrypt.hash(password, salt, n, r, p, dklen))


def generate_pbkdf2_params():
    return {
        'dklen': 32,
        'c': 10240,
        'prf': 'hmac-sha256',
        'salt': remove_0x_prefix(encode_hex(os.urandom(32))),
    }


def generate_scrypt_params():
    return {
        'dklen': 32,
        'n': 262144,
        'r': 8,
        'p': 1,
        'salt': remove_0x_prefix(encode_hex(os.urandom(32))),
    }


# make the functions accessible by name

kdfs = {
    'pbkdf2': derive_pbkdf2_key,
    'scrypt': derive_scrypt_key,
}

kdf_param_validators = {
    'pbkdf2': validate_pbkdf2,
    'scrypt': validate_scrypt
}

kdf_param_generators = {
    'pbkdf2': generate_pbkdf2_params,
    'scrypt': generate_scrypt_params,
}

assert all(set(d.keys()) == set(kdfs.keys()) for d in [kdf_param_validators, kdf_param_generators])
