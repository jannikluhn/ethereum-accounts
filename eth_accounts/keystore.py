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
    keccak,
    remove_0x_prefix,
    to_checksum_address,
)
import scrypt

from .exceptions import (
    AccountLocked,
    DecryptionError,
    MissingAddress,
)
from .utils import (
    normalize_private_key,
    private_key_to_address,
    private_key_to_public_key,
)
from .validation import (
    validate_keystore,
    validate_password,
)


class Account(object):
    """An externally controlled Ethereum account."""

    def __init__(self):
        self._private_key = None
        self._public_key = None
        self._address = None
        self._locked = True

    @classmethod
    def from_private_key(cls, private_key):
        account = cls()
        account._private_key = normalize_private_key(private_key)
        account.unlock()  # trigger derivation of public key and address

    @classmethod
    def from_keystore(cls, keystore, password=None):
        return KeystoreAccount(keystore, password)

    @classmethod
    def from_mnemoic(cls, phrase):
        pass

    @property
    def private_key(self):
        if not self._locked:
            return self._private_key
        else:
            raise AccountLocked('Cannot access private key of locked account')

    @property
    def public_key(self):
        if self._public_key is None:
            try:
                private_key = self.private_key
            except AccountLocked:
                raise AccountLocked('Cannot derive public key of locked account')
            else:
                self._public_key = private_key_to_public_key(private_key)
        return self._public_key

    @property
    def address(self):
        # TODO: check keystore for address
        if self._address is None:
            try:
                private_key = self.private_key
            except AccountLocked:
                raise AccountLocked('Cannot derive address of locked account')
            else:
                self._address = private_key_to_address(private_key)
        return self._address

    def unlock(self):
        self._locked = False
        # force derivation of public key and address
        self.public_key
        self.address

    def lock(self):
        self._locked = True

    def is_locked(self):
        return self._locked

    def to_keystore(self, f, password):
        pass

    def to_keystore_dict(self):
        pass


class KeystoreAccount(Account):

    def __init__(self, keystore, password=None):
        super().__init__()
        self.keystore_dict = parse_keystore(keystore)
        if password is not None:
            self.unlock(password)

    def unlock(self, password):
        self._extract_private_key(password)
        self._locked = False

    def lock(self):
        self._private_key = None
        self._locked = True

    @property
    def exposed_address(self):
        try:
            return to_checksum_address(self.keystore_dict['address'])
        except KeyError:
            raise MissingAddress('no address in keystore')

    def _extract_private_key(self, password):
        validate_password(password)
        key = self._derive_key(password)
        self._validate_mac(key)
        ciphertext = decode_hex(self.keystore_dict['crypto']['ciphertext'])
        params = self.keystore_dict['crypto']['cipherparams']
        self._private_key = encode_hex(decrypt_aes_ctr(ciphertext, key[:16], params))

    def _derive_key(self, password):
        kdf_params = self.keystore_dict['crypto']['kdfparams']
        kdf = self.keystore_dict['crypto']['kdf']
        if kdf == 'pbkdf2':
            key = derive_pbkdf2_key(password, kdf_params)
        elif kdf == 'scrypt':
            key = derive_scrypt_key(password, kdf_params)
        else:
            assert False  # checked during validation
        return key

    def _validate_mac(self, key):
        ciphertext = decode_hex(self.keystore_dict['crypto']['ciphertext'])
        mac = keccak(key[16:32] + ciphertext)
        if mac != decode_hex(self.keystore_dict['crypto']['mac']):
            raise DecryptionError('MAC mismatch')

    def _decrypt_private_key(self, key):
        ciphertext = decode_hex(self.keystore_dict['crypto']['ciphertext'])
        params = self.keystore_dict['crypto']['']
        private_key = decrypt_aes_ctr(ciphertext, key[:16], params)
        return private_key


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
