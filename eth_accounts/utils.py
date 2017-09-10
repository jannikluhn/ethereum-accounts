import rlp
from rlp.sedes import big_endian_int, binary, Binary

from coincurve import PrivateKey
from eth_utils import (
    add_0x_prefix,
    big_endian_to_int,
    decode_hex,
    encode_hex,
    is_bytes,
    is_hex,
    is_integer,
    is_text,
    keccak,
    remove_0x_prefix,
    to_checksum_address,
)

PRIVATE_KEY_SIZE = 32


def random_private_key():
    """Generate a random private key.

    .. note::

        `os.urandom` (via the coincurve package) is used to generate randomness.
    """
    return add_0x_prefix(PrivateKey().to_hex())


def private_key_to_public_key(private_key):
    """Calculate the public key corresponding to a given private key."""
    private_key = normalize_private_key(private_key)
    private_key_object = PrivateKey.from_hex(remove_0x_prefix(private_key))
    public_key_object = private_key_object.public_key
    return encode_hex(public_key_object.format(compressed=False))


def private_key_to_address(private_key):
    """Calculate the address corresponding to a given private key."""
    private_key = normalize_private_key(private_key)
    public_key = private_key_to_public_key(private_key)
    address = public_key_to_address(public_key)
    return address


def public_key_to_address(public_key):
    """Calculate the address corresponding to a given public key."""
    public_key = normalize_public_key(public_key)
    public_key_hash = keccak(decode_hex(public_key)[1:])
    address = to_checksum_address(public_key_hash[12:])
    return address


def normalize_private_key(private_key):
    # convert to int
    if is_integer(private_key):
        pass
    elif is_bytes(private_key):
        private_key = big_endian_to_int(private_key)
    elif is_text(private_key):
        if not is_hex(private_key):
            raise ValueError('Private key must be hex encoded if of type string')
        private_key = big_endian_to_int(decode_hex(private_key))
    else:
        raise TypeError('Private key must be either bytes, integer, or hex encoded string')
    # check if valid and convert to hex
    try:
        private_key = PrivateKey.from_int(private_key)
    except (ValueError, OverflowError):
        raise ValueError('Private key out of allowed range')
    return add_0x_prefix(private_key.to_hex())


def normalize_public_key(public_key):
    if is_bytes(public_key):
        public_key = encode_hex(public_key)
    elif is_text(public_key):
        if not is_hex(public_key):
            raise ValueError('Public key must be hex encoded if of type string')
        public_key = add_0x_prefix(public_key).lower()
    else:
        raise TypeError('Public key must be either bytes or hex encoded string')
    if len(public_key) != 2 + 65 * 2:
        raise ValueError('Public keys must be 65 bytes long (uncompressed format is used)')
    return public_key


def normalize_message(message):
    if is_bytes(message):
        return message
    elif is_text(message):
        if not is_hex(message):
            raise ValueError('Message must be hex encoded if of type string')
        return decode_hex(message)
    else:
        raise TypeError('Message must be either bytes or hex encoded string')


def normalize_signature(signature):
    if is_bytes(signature):
        signature = encode_hex(signature)
    elif is_text(signature):
        if not is_hex(signature):
            raise ValueError('signature must be hex encoded if of type string')
        signature = add_0x_prefix(signature).lower()
    else:
        raise TypeError('Signature must be either bytes or hex encoded string')
    if len(signature) != 2 + 65 * 2:
        raise ValueError('Signature must be 65 bytes long')
    return signature


def normalize_password(password):
    if is_bytes(password):
        return password
    else:
        raise TypeError('password must be bytes')


class Transaction(rlp.Serializable):

    fields = [
        ('nonce', big_endian_int),
        ('gasprice', big_endian_int),
        ('startgas', big_endian_int),
        ('to', Binary.fixed_length(20, allow_empty=True)),
        ('value', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]


UnsignedTransaction = Transaction.exclude(['v', 'r', 's'])
