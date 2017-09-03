import os

from Crypto.Cipher import AES
from Crypto.Util import Counter
from eth_utils import (
    decode_hex,
    encode_hex,
    is_0x_prefixed,
    is_hex,
    remove_0x_prefix,
)

from .exceptions import InvalidKeystore


def encrypt_aes_128_ctr(private_key, key, params):
    iv = int.from_bytes(decode_hex(params['iv']), byteorder='big')
    counter = Counter.new(128, initial_value=iv, allow_wraparound=True)
    cipher = AES.new(decode_hex(key), mode=AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(decode_hex(private_key))
    return remove_0x_prefix(encode_hex(ciphertext))


def decrypt_aes_128_ctr(ciphertext, key, params):
    iv = int.from_bytes(decode_hex(params['iv']), byteorder='big')
    counter = Counter.new(128, initial_value=iv, allow_wraparound=True)
    cipher = AES.new(decode_hex(key), mode=AES.MODE_CTR, counter=counter)
    private_key = cipher.decrypt(decode_hex(ciphertext))
    return remove_0x_prefix(encode_hex(private_key))


def validate_aes_128_ctr_params(params):
    if 'iv' not in params:
        raise InvalidKeystore('no cipher initialization vector')
    if not is_hex(params['iv']):
        raise InvalidKeystore('cipher initialization vector must be hex encoded')
    if is_0x_prefixed(params['iv']):
        raise InvalidKeystore('cipher initialization vector must not have 0x prefix')


def generate_aes_128_ctr_params():
    return {
        'iv': remove_0x_prefix(encode_hex(os.urandom(16))),
    }


ciphers = ['aes-128-ctr']

encryptors = {
    'aes-128-ctr': encrypt_aes_128_ctr,
}

decryptors = {
    'aes-128-ctr': decrypt_aes_128_ctr,
}

cipher_param_validators = {
    'aes-128-ctr': validate_aes_128_ctr_params,
}

cipher_param_generators = {
    'aes-128-ctr': generate_aes_128_ctr_params,
}


assert all(set(d.keys()) == set(ciphers) for d in
           [encryptors, decryptors, cipher_param_validators, cipher_param_generators])
