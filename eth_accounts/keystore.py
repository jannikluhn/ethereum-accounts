from collections import Mapping
from io import IOBase
import json

from eth_utils import (
    decode_hex,
    encode_hex,
    keccak,
    to_checksum_address,
)

from .ciphers import (
    cipher_param_validators,
    ciphers,
    decryptors,
)
from .exceptions import (
    AccountLocked,
    DecryptionError,
    UnsupportedKeystore,
)
from .kdfs import (
    kdf_param_validators,
    kdfs,
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
        """Create an account based on a private key.

        The returned account will be unlocked.

        :param private_key: the private key, either as byte string or hex encoded (with or without
                            `'0z'`-prefix)
        :returns: the created and unlocked account
        """
        account = cls()
        account._private_key = normalize_private_key(private_key)
        account.unlock()  # trigger derivation of public key and address

    @classmethod
    def from_keystore(cls, keystore, password=None):
        """Load an account from a keystore.

        If a password is provided, the keystore will be unlocked, otherwise it will stay locked.

        :param keystore: the keystore, either as a readable file, a dictionary, or a JSON encoded
                         string
        :param password: the keystore's password or `None`
        """
        return KeystoreAccount(keystore, password)

    @classmethod
    def from_mnemoic(cls, phrase):
        pass

    @property
    def private_key(self):
        """The account's private key in hex encoded, `'0x'`-prefixed form..

        The private key is only accessible for unlocked accounts.

        :raises `AccountLocked`: if the account is locked
        """
        if not self._locked:
            return self._private_key
        else:
            raise AccountLocked('Cannot access private key of locked account')

    @property
    def public_key(self):
        """The account's public key in hex encoded, `'0x'`-prefixed form.

        The public key is only accessible after the accound is unlocked for the first time, but
        remains so when being locked again.

        :raises `AccountLocked`: if the account has never been unlocked
        """
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
        """The account's address in hex encoded, `'0x'`-prefixed form.

        The address is only accessible after the accound is unlocked for the first time, but
        remains so when being locked again.

        Note that this is independent from the address contained as plain text in the keystore
        file. To access this use `Account.exposed_address`.

        :raises `AccountLocked`: if the account has never been unlocked
        """
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
        """Unlock the account.

        :param password: (only for keystore accounts) the password decrypting the keystore
        """
        self._locked = False
        # force derivation of public key and address
        self.public_key
        self.address

    def lock(self):
        """Lock the account prohibiting access to the private key."""
        self._locked = True

    def is_locked(self):
        """Check if the account is locked.

        :returns: `True` or `False`
        """
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
            return None

    def _extract_private_key(self, password):
        validate_password(password)
        key = self._derive_key(password)
        self._validate_mac(key)
        self._private_key = self._decrypt_private_key(key)

    def _derive_key(self, password):
        kdf = self.keystore_dict['crypto']['kdf']
        kdf_params = self.keystore_dict['crypto']['kdfparams']
        assert kdf in kdfs  # checked during validation
        key = kdfs[kdf](password, kdf_params)
        return key

    def _validate_mac(self, key):
        ciphertext = decode_hex(self.keystore_dict['crypto']['ciphertext'])
        mac = calculate_mac(key, ciphertext)
        if mac != decode_hex(self.keystore_dict['crypto']['mac']):
            raise DecryptionError('MAC mismatch')

    def _decrypt_private_key(self, key):
        cipher = self.keystore_dict['crypto']['cipher']
        ciphertext = decode_hex(self.keystore_dict['crypto']['ciphertext'])
        assert cipher in ciphers  # checked during validation
        params = self.keystore_dict['crypto']['cipherparams']
        decrypt = decryptors[cipher]
        private_key = decrypt(ciphertext, key[:16], params)
        return encode_hex(private_key)


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


def calculate_mac(key, ciphertext):
    return keccak(key[16:32] + ciphertext)
