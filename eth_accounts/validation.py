from collections import Mapping

from eth_utils import (
    is_0x_prefixed,
    is_checksum_address,
    is_checksum_formatted_address,
    is_hex,
    is_hex_address,
)

from .ciphers import (
    ciphers,
    cipher_param_validators,
)
from .exceptions import (
    InvalidKeystore,
    UnsupportedKeystore,
)
from .kdfs import (
    kdf_param_validators,
    kdfs,
)


def validate_keystore(keystore):
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
    cipher = crypto['cipher']
    if cipher not in ciphers:
        raise UnsupportedKeystore('unknown cipher in keystore')
    cipher_params = crypto['cipherparams']
    if not isinstance(cipher_params, Mapping):
        raise InvalidKeystore('invalid format of cipher parameters in keystore')
    validate_cipher_params = cipher_param_validators[cipher]
    validate_cipher_params(cipher_params)

    # kdf
    kdf = crypto['kdf']
    if kdf not in kdfs:
        raise UnsupportedKeystore('unknown key derivation function in keystore')
    kdf_params = crypto['kdfparams']
    if not isinstance(kdf_params, Mapping):
        raise InvalidKeystore('invalid format of key derivation parameters in keystore')
    validate_kdf_params = kdf_param_validators[kdf]
    validate_kdf_params(kdf_params)

    # MAC
    if not is_hex(crypto['mac']):
        raise InvalidKeystore('MAC must be hex encoded')
    if is_0x_prefixed(crypto['mac']):
        raise InvalidKeystore('MAC must not have 0x prefix')

    # address
    if 'address' in keystore:
        address = keystore['address']
        if not is_hex_address(address):
            raise InvalidKeystore('address must be hex encoded')
        if is_0x_prefixed(address):
            raise InvalidKeystore('address must not have 0x prefix')
        if is_checksum_formatted_address(address) and not is_checksum_address(address):
            raise InvalidKeystore('address must have correct or no checksum')
