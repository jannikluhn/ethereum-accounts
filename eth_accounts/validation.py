from collections import Mapping

from eth_utils import (
    is_checksum_address,
    is_checksum_formatted_address,
    is_hex,
    is_hex_address,
)

from .exceptions import (
    InvalidKeystore,
    UnsupportedKeystore,
)


def validate_keystore(keystore):
    """Validate a keystore in dictionary format. Superfluous keys are allowed."""
    if 'version' not in keystore:
        raise InvalidKeystore('no version specified')
    version = keystore['version']
    if version != 3:
        message = 'unknown keystore version {} (can only handle 3)'.format(version)
        raise UnsupportedKeystore(message)
    if 'crypto' not in keystore:
        raise InvalidKeystore('no crypto section')

    crypto = keystore['crypto']
    required_crypto_keys = {
        'cipher': 'cipher',
        'cipherparams': 'cipher parameters',
        'ciphertext': 'cipher text',
        'kdf': 'key derivation function',
        'kdfparams': 'key derivation parameters',
        'mac': 'MAC'
    }
    for key, name in required_crypto_keys.items():
        if key not in crypto:
            raise InvalidKeystore('no {} specified'.format(name))

    if crypto['cipher'] != 'aes-128-ctr':
        raise UnsupportedKeystore('unknown cipher in keystore')
    kdf_params = crypto['kdfparams']
    if not isinstance(kdf_params, Mapping):
        raise InvalidKeystore('invalid format of key derivation parameters in keystore')
    if crypto['kdf'] == 'pbkdf2':
        validate_pbkdf2_params(kdf_params)
    elif crypto['kdf'] == 'scrypt':
        validate_scrypt_params(kdf_params)
    else:
        raise UnsupportedKeystore('unknown key derivation function in keystore')

    cipher_params = crypto['cipherparams']
    if not isinstance(cipher_params, Mapping):
        raise InvalidKeystore('invalid format of cipher parameters in keystore')
    if 'iv' not in cipher_params:
        raise InvalidKeystore('no key derivation initialization vector')

    # if address is provided it must be hex encoded and (if ERC55 encoded) the checksum must be
    # correct
    if 'address' in keystore:
        address = keystore['address']
        if not is_hex_address(address):
            raise InvalidKeystore('address specified in invalid format')
        if is_checksum_formatted_address(address) and not is_checksum_address(address):
            raise InvalidKeystore('address has wrong checksum')


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


def validate_password(password):
    """Validate a password.

    Passwords must have the type `bytes`.
    """
    if not isinstance(password, bytes):
        raise TypeError('password must be bytes')
