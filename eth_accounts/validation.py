from collections import Mapping

from eth_utils import (
    is_checksum_address,
    is_checksum_formatted_address,
    is_hex_address,
)

from .exceptions import (
    InvalidKeystore,
    UnsupportedKeystore,
)
from .kdf import (
    kdf_param_validators,
    kdfs,
)


def validate_password(password):
    """Validate a password.

    Passwords must have the type `bytes`.
    """
    if not isinstance(password, bytes):
        raise TypeError('password must be bytes')


def validate_keystore(keystore):
    """Validate a keystore in dictionary format. Superfluous keys are allowed."""
    # version
    if 'version' not in keystore:
        raise InvalidKeystore('no version specified')
    version = keystore['version']
    if isinstance(version, str):
        try:
            int_version = int(version)
        except ValueError:
            message = 'keystore version must be integer or integer representing string'
            raise InvalidKeystore(message)
    elif isinstance(version, int):
        int_version = version
    else:
        raise InvalidKeystore('keystore version must be either integer or string')
    if int_version <= 0:
        raise InvalidKeystore('keystore version number must be positive')
    if int_version != 3:
        message = 'unknown keystore version {} (can only handle 3)'.format(int_version)
        raise UnsupportedKeystore(message)

    # crypto
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

    # cipher
    if crypto['cipher'] != 'aes-128-ctr':
        raise UnsupportedKeystore('unknown cipher in keystore')
    cipher_params = crypto['cipherparams']
    if not isinstance(cipher_params, Mapping):
        raise InvalidKeystore('invalid format of cipher parameters in keystore')
    if 'iv' not in cipher_params:
        raise InvalidKeystore('no key derivation initialization vector')

    # kdf
    kdf = crypto['kdf']
    if kdf not in kdfs:
        raise UnsupportedKeystore('unknown key derivation function in keystore')
    kdf_params = crypto['kdfparams']
    if not isinstance(kdf_params, Mapping):
        raise InvalidKeystore('invalid format of key derivation parameters in keystore')
    validate = kdf_param_validators[kdf]
    validate(kdf_params)

    # address
    if 'address' in keystore:
        address = keystore['address']
        if not is_hex_address(address):
            raise InvalidKeystore('address specified in invalid format')
        if is_checksum_formatted_address(address) and not is_checksum_address(address):
            raise InvalidKeystore('address has wrong checksum')
