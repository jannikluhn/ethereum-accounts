import rlp
from rlp.sedes import big_endian_int, binary, Binary

from coincurve import PrivateKey
from eth_utils import (
    add_0x_prefix,
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_bytes,
    is_hex,
    is_integer,
    is_text,
    keccak,
    remove_0x_prefix,
    to_checksum_address,
)


def random_private_key():
    """Generate a random private key.

    `os.urandom` (via the coincurve package) is used to generate randomness.

    :returns: a random hex encoded `'0x'` prefixed private key.
    """
    return add_0x_prefix(PrivateKey().to_hex())


def private_key_to_public_key(private_key):
    """Calculate the public key corresponding to a given private key.

    :param private_key: the private key, either hex encoded (with or without `'0x'`-prefix) or as
                        bytes
    :returns: the hex encoded, `'0x'`-prefixed public key
    """
    private_key = normalize_private_key(private_key)
    private_key_object = PrivateKey.from_hex(remove_0x_prefix(private_key))
    public_key_object = private_key_object.public_key
    return encode_hex(public_key_object.format(compressed=False))


def private_key_to_address(private_key):
    """Calculate the address corresponding to a given private key.

    :param private_key: the private key, either hex encoded (with or without `'0x'`-prefix) or as
                        bytes
    :returns: the hex encoded, `'0x'`-prefixed, checksummed address
    """
    private_key = normalize_private_key(private_key)
    public_key = private_key_to_public_key(private_key)
    address = public_key_to_address(public_key)
    return address


def public_key_to_address(public_key):
    """Calculate the address corresponding to a given public key.

    :param public_key: the public key, either as bytes or hex encoded string (with or without
                       `'0x'`-prefix)
    :returns: the hex encoded, `'0x'`-prefixed, checksummed address
    """
    public_key = normalize_public_key(public_key)
    public_key_hash = keccak(decode_hex(public_key)[1:])
    address = to_checksum_address(public_key_hash[12:])
    return address


def normalize_private_key(private_key):
    if is_integer(private_key):
        if private_key <= 0:
            raise ValueError('Private key out of allowed range')
        private_key_hex = encode_hex(int_to_big_endian(private_key))
    elif is_bytes(private_key):
        private_key_hex = encode_hex(private_key)
    elif is_text(private_key):
        if not is_hex(private_key):
            raise ValueError('Private key must be hex encoded if of type string')
        private_key_hex = add_0x_prefix(private_key).lower()
    else:
        raise TypeError('Private key must be either bytes, integer, or hex encoded string')
    try:
        PrivateKey.from_hex(remove_0x_prefix(private_key_hex))
    except ValueError:
        raise ValueError('Private key out of allowed range')
    return private_key_hex


def normalize_public_key(public_key):
    if is_bytes(public_key):
        return encode_hex(public_key)
    elif is_text(public_key):
        if not is_hex(public_key):
            raise ValueError('Public key must be hex encoded if of type string')
        return add_0x_prefix(public_key).lower()
    else:
        raise TypeError('Public key must be either bytes or hex encoded string')


def normalize_signature(signature):
    if is_bytes(signature):
        return encode_hex(signature)
    elif is_text(signature):
        if not is_hex(signature):
            raise ValueError('signature must be hex encoded if of type string')
        return add_0x_prefix(signature).lower()
    else:
        raise TypeError('Signature must be either bytes or hex encoded string')


class Transaction(rlp.Serializable):

    fields = [
        ('nonce', big_endian_int),
        ('gasprice', big_endian_int),
        ('startgas', big_endian_int),
        ('to', Binary.fixed_length(20)),
        ('value', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]


UnsignedTransaction = Transaction.exclude(['v', 'r', 's'])
