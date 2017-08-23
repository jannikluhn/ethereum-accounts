from hashlib import pbkdf2_hmac

from eth_utils import (
    decode_hex,
    is_hex,
)
import scrypt

from .exceptions import (
    InvalidKeystore,
    UnsupportedKeystore,
)


def validate_pbkdf2_params(kdf_params):
    """Ensure that all parameters for PBKDF2 are provided and that they are valid."""
    required_kdf_params = {
        'prf': 'pseudorandom function',
        'c': 'iteration number',
        'salt': 'salt value',
        'dklen': 'key length'
    }
    for key, name in required_kdf_params.items():
        if key not in kdf_params:
            raise InvalidKeystore('no {} specified'.format(name))
    if kdf_params['prf'] != 'hmac-sha256':
        raise UnsupportedKeystore('unknown pseudorandom function in keystore')
    if not isinstance(kdf_params['c'], int):
        raise InvalidKeystore('PBKDF2 iteration number must be integer')
    if not isinstance(kdf_params['dklen'], int):
        raise InvalidKeystore('PBKDF2 key length must be integer')
    if kdf_params['dklen'] < 32:
        raise InvalidKeystore('PBKDF2 key length must be greater than or equal to 32')
    if not is_hex(kdf_params['salt']):
        raise InvalidKeystore('PBKDF2 salt value must be hex encoded')

    if kdf_params['c'] <= 0:
        raise InvalidKeystore('PBKDF2 iteration number must be positive')
    if kdf_params['dklen'] <= 0:
        raise InvalidKeystore('PBKDF2 key length must be positive')


def validate_scrypt_params(kdf_params):
    """Ensure that all parameters for Scrypt are provided and that they are valid."""
    required_kdf_params = {
        'dklen': 'key length',
        'n': 'cost parameter N',
        'r': 'cost parameter r',
        'p': 'parallelization parameter p',
        'salt': 'salt value',
    }
    for key, name in required_kdf_params.items():
        if key not in kdf_params:
            raise InvalidKeystore('no {} specified'.format(name))
    if not isinstance(kdf_params['dklen'], int):
        raise InvalidKeystore('scrypt key length must be integer')
    if not isinstance(kdf_params['n'], int):
        raise InvalidKeystore('scrypt cost parameter N must be integer')
    if not isinstance(kdf_params['r'], int):
        raise InvalidKeystore('scrypt cost parameter r must be integer')
    if not isinstance(kdf_params['p'], int):
        raise InvalidKeystore('scrypt parallelization parameter p must be integer')
    if not is_hex(kdf_params['salt']):
        raise InvalidKeystore('scrypt salt value must be hex encoded')

    if kdf_params['dklen'] <= 0:
        raise InvalidKeystore('scrypt key length must be positive')
    if kdf_params['n'] < 1 or (kdf_params['n'] & (kdf_params['n'] - 1)) != 0:
        raise InvalidKeystore('scrypt cost parameter N must be positive power of two')
    if kdf_params['p'] <= 0:
        raise InvalidKeystore('scrypt parallelization parameter p must be positive')
    if kdf_params['r'] <= 0:
        raise InvalidKeystore('scrypt cost parameter r must be positive')
    if kdf_params['r'] * kdf_params['p'] >= 2**30:
        raise InvalidKeystore('product of scrypt parameters n and r must be smaller than 2^30')
    if kdf_params['dklen'] >= (2**32 - 1) * 32:
        raise InvalidKeystore('scrypt key length too large')


def derive_pbkdf2_key(password, params):
    salt = decode_hex(params['salt'])
    dklen = params['dklen']
    iterations = params['c']
    full_key = pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    assert len(full_key) == dklen
    return full_key


def derive_scrypt_key(password, params):
    salt = decode_hex(params['salt'])
    n = params['n']
    r = params['r']
    p = params['p']
    dklen = params['dklen']
    return scrypt.hash(password, salt, n, r, p, dklen)


# make the functions accessible by name

kdfs = {
    'pbkdf2': derive_pbkdf2_key,
    'scrypt': derive_scrypt_key,
}

kdf_param_validators = {
    'pbkdf2': validate_pbkdf2_params,
    'scrypt': validate_scrypt_params
}

default_kdf_params = {
    'pbkdf2': {

    },
    'scrypt': {

    }
}

assert set(kdfs.keys()) == set(kdf_param_validators.keys()) == set(default_kdf_params.keys())
