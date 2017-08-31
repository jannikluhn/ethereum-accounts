from collections import Mapping
from io import IOBase
import json
from uuid import uuid4

from cytoolz.dicttoolz import (
    assoc,
)
from eth_utils import (
    decode_hex,
    encode_hex,
    is_hex,
    is_same_address,
    keccak,
    to_checksum_address,
)
import rlp

from .ciphers import (
    cipher_param_generators,
    cipher_param_validators,
    ciphers,
    decryptors,
    encryptors,
)
from .exceptions import (
    AccountLocked,
    DecryptionError,
    UnsupportedKeystore,
)
from .kdfs import (
    kdf_param_generators,
    kdf_param_validators,
    kdfs,
)
from .utils import (
    normalize_private_key,
    private_key_to_address,
    private_key_to_public_key,
    random_private_key,
    Transaction,
)
from .signing import (
    sign_message,
    sign_transaction,
    verify_signature,
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
    def new(cls):
        """Create an account based on a newly generated random private key.

        The returned account will be unlocked.

        :returns: the created and unlocked account
        """
        private_key = random_private_key()
        return Account.from_private_key(private_key)

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
        return account

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

    def request_unlock(self):
        """Call this method to request unlocking of the account (e.g. to trigger user input).

        Each unlock request should be followed by a lock request once the account's private key is
        not needed any longer.

        :returns: a unique request id
        """
        # TODO
        # should call unlock callbacks (that by default just unlock)
        # what happens if account is already unlocked?
        # what happens if unlocking fails?

    def request_lock(self, request_id):
        """Call this method to request locking of the account (after an earlier unlock request).

        :param request_id: """
        # TODO
        # should call lock callbacks (that by default just lock)

    def is_locked(self):
        """Check if the account is locked.

        :returns: `True` or `False`
        """
        return self._locked

    def to_keystore(self, f, password, expose_address=True, uuid=True, kdf='scrypt',
                    kdf_params=None, cipher='aes-128-ctr', cipher_params=None, pretty=True):
        d = self.to_keystore_dict(password, expose_address, uuid, kdf, kdf_params,
                                  cipher, cipher_params)
        indent = 4 if pretty else None
        json.dump(d, f, indent=indent)

    def to_keystore_dict(self, password, expose_address=True, uuid=True, kdf='scrypt',
                         kdf_params=None, cipher='aes-128-ctr', cipher_params=None):
        private_key = self.private_key

        if kdf not in kdfs:
            raise UnsupportedKeystore('{} kdf not supported'.format(kdf))
        kdf_params = {**kdf_param_generators[kdf](), **(kdf_params or {})}

        if cipher not in ciphers:
            raise UnsupportedKeystore('{} cipher not supported'.format(kdf))
        cipher_params = {**cipher_param_generators[cipher](), **(cipher_params or {})}

        validate_kdf_params = kdf_param_validators[kdf]
        validate_kdf_params(kdf_params)
        validate_cipher_params = cipher_param_validators[cipher]
        validate_cipher_params(cipher_params)

        key = kdfs[kdf](password, kdf_params)
        ciphertext = encryptors[cipher](private_key, key[:32 + 2], cipher_params)
        mac = calculate_mac(key, ciphertext)

        keystore_dict = {
            'version': '3',
            'crypto': {
                'cipher': cipher,
                'cipherparams': cipher_params,
                'kdf': kdf,
                'kdfparams': kdf_params,
                'mac': mac,
                'ciphertext': ciphertext,
            },
        }

        if expose_address:
            keystore_dict['address'] = self.address

        if uuid is True:
            keystore_dict['id'] = str(uuid4())
            # TODO: find out correct format, should include timestamp
        elif uuid is not None:
            keystore_dict['id'] = str(uuid)

        return keystore_dict

    def sign_message(self, message, hash=True, encoding='iso-8859-1'):
        return sign_message(message, self.private_key, hash, encoding)

    def sign_transaction(self, transaction, network_id):
        return sign_transaction(transaction, self.private_key, network_id)

    def is_signer(self, signature, message, hash=True, encoding='iso-8859-1'):
        return verify_signature(signature, message, self.address, hash=hash, encoding=encoding)

    def local_signing_middleware(self, make_request, web3):
        """Creates a Web3 middleware that signs transactions originating from this account."""
        def middleware(method, params):
            def ignore():
                response = make_request(method, params)
                return response

            if self.is_locked():
                return ignore()

            if method != 'eth_sendTransaction':
                return ignore()

            transaction = params[0]
            if 'from' not in transaction:
                return ignore()
            sender = transaction['from']
            if not is_same_address(sender, self.address):
                return ignore()

            if 'gas' in transaction:
                gas = transaction['gas']
            else:
                gas = web3.eth.estimateGas(transaction)

            # construct raw transaction
            network_id = int(web3.net.version)
            transaction_object = Transaction(
                transaction.get('nonce', web3.eth.getTransactionCount(sender)),
                transaction.get('gasPrice', web3.eth.gasPrice),
                transaction.get('gas', gas),
                decode_hex(transaction.get('to', '0x')),
                transaction.get('value', 0),
                decode_hex(transaction.get('data', '0x')),
                0,
                0,
                0
            )
            self.sign_transaction(transaction_object, network_id)
            raw_transaction_hex = encode_hex(rlp.encode(transaction_object))
            return make_request('eth_sendRawTransaction', [raw_transaction_hex])

        return middleware

    def __repr__(self):
        object_id = hex(id(self))
        try:
            address = self.address[:4 + 2] + '...'
        except AccountLocked:
            address = 'unknown'
        return '<Account at {} (address: {})>'.format(object_id, address)


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
        ciphertext = self.keystore_dict['crypto']['ciphertext']
        mac = calculate_mac(key, ciphertext)
        if decode_hex(mac) != decode_hex(self.keystore_dict['crypto']['mac']):
            raise DecryptionError('MAC mismatch')

    def _decrypt_private_key(self, key):
        cipher = self.keystore_dict['crypto']['cipher']
        ciphertext = self.keystore_dict['crypto']['ciphertext']
        assert cipher in ciphers  # checked during validation
        params = self.keystore_dict['crypto']['cipherparams']
        decrypt = decryptors[cipher]
        private_key = decrypt(ciphertext, key[:32 + 2], params)
        return normalize_private_key(private_key)


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
    return encode_hex(keccak(decode_hex(key)[16:32] + decode_hex(ciphertext)))
