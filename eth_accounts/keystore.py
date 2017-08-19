from collections import Mapping
from hashlib import pbkdf2_hmac
from io import IOBase
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter
from eth_utils import (
    encode_hex,
    decode_hex,
    is_hex,
    remove_0x_prefix,
    keccak
)
import scrypt

from .exceptions import (
    DecryptionError,
    InvalidKeystore,
    UnsupportedKeystore,
)
from .utils import (
    private_key_to_public_key,
)


def parse_keystore(keystore):
    if isinstance(keystore, Mapping):
        keystore_dict = keystore
    elif isinstance(keystore, IOBase):
        keystore_dict = json.load(keystore)
    else:
        try:
            keystore_dict = json.loads(keystore)
        except TypeError:
            raise TypeError('expected mapping, file-like object, or string')
    validate_keystore(keystore_dict)
    return keystore_dict


def validate_keystore(keystore):
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


def validate_pbkdf2_params(kdf_params):
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
    if not isinstance(password, bytes):
        raise TypeError('password must be bytes')


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


def decrypt_aes_ctr(ciphertext, key, params):
    iv = int.from_bytes(decode_hex(params['iv']), byteorder='big')
    counter = Counter.new(128, initial_value=iv, allow_wraparound=True)
    decryptor = AES.new(key, mode=AES.MODE_CTR, counter=counter)
    private_key = decryptor.decrypt(ciphertext)
    return private_key


def calculate_mac(ciphertext, key):
    return keccak(key[16:32] + ciphertext)


def private_key_from_keystore(keystore, password):
    """Extract the private key from a keystore.

    :param keystore: the keystore, either as a file-like object, a dictionary or a JSON string
    :param password: the password that unlocks the keystore
    :returns: the hex encoded private key without `'0x'`-prefix
    """
    keystore_dict = parse_keystore(keystore)
    validate_password(password)

    # derive key
    kdf_params = keystore_dict['crypto']['kdfparams']
    if keystore_dict['crypto']['kdf'] == 'pbkdf2':
        key = derive_pbkdf2_key(password, kdf_params)
    elif keystore_dict['crypto']['kdf'] == 'scrypt':
        key = derive_scrypt_key(password, kdf_params)
    else:
        assert False  # checked during validation

    # validate MAC
    ciphertext = decode_hex(keystore_dict['crypto']['ciphertext'])
    mac = calculate_mac(ciphertext, key)
    if mac != decode_hex(keystore_dict['crypto']['mac']):
        raise DecryptionError('MAC mismatch')

    # decrypt private key
    params = keystore_dict['crypto']['cipherparams']
    private_key = decrypt_aes_ctr(ciphertext, key[:16], params)
    return remove_0x_prefix(encode_hex(private_key))


def public_key_from_keystore(keystore, password):
    """Extract the public key from a keystore.

    :param keystore: the keystore, either as a file-like object, a dictionary or a JSON string
    :param password: the password that unlocks the keystore
    :returns: the hex encoded, '0x'-prefixed public key
    """
    private_key = private_key_from_keystore(keystore, password)
    public_key = private_key_to_public_key(private_key)
    return public_key


def address_from_keystore(keystore):
    """Extract the address from a keystore.

    :param keystore: the keystore, either as a file-like object, a dictionary or a JSON string
    :returns: the hex encoded, '0x'-prefixed address
    """
    pass


def save_keystore(private_key, password, file):
    """Save a private key to a keystore file.

    :param private_key: the private key to save
    :param password: the password used to lock the keystore
    :param file: a writable file-like object to which the keystore will be written
    """
    pass


def build_keystore_dict(private_key, password):
    """Generate a dictionary representing a keystore holding a private key.

    :param private_key: the private key to save
    :param password: the password used to lock the keystore
    :param file: a writable file-like object to which the keystore will be written
    :returns: a dictionary representing the keystore
    """
    pass


def sign(private_key, message, hash=True):
    """Sign a message using a private key.

    :param private_key: the private key that should be used to sign the message
    :param message: the message to sign
    :param hash: if true, the message will be hashed before signing it
    :returns: the hex encoded, '0x'-prefixed signature
    """
    pass


def sign_transaction(private_key, transaction_dict):
    """Sign an Ethereum transaction.

    :param private_key: the private key that should be used to sign the transaction
    :param transaction_dict: the transaction as a dictionary
    :returns: the hex encoded, '0x'-prefixed signature
    """
    pass


def sign_ethereum_message(private_key, message):
    """Create an Ethereum specific signature.

    This function replicates the behavior of the standard JSON RPC command `eth_sign`.

    :param private_key: the private key that should be used to sign the message
    :param message: the message to sign
    :returns: the hex encoded, '0x'-prefixed signature
    """
    pass


def verify_signature(signature, message, address):
    """Verify that a message has been signed by the owner of an account.

    :param signature: the signature to verify
    :param message: the message that has been signed
    :param address: the address of the assumed owner
    :returns: `True` or `False`
    """


# todo:


def private_key_from_mnemoic(private_key, phrase):
    pass


def random_private_key():
    pass
