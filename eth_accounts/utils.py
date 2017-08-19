from coincurve import PrivateKey
from eth_utils import (
    decode_hex,
    encode_hex,
    is_hex,
    keccak,
    remove_0x_prefix,
    to_checksum_address,
)


def random_private_key():
    """Generate a random private key.

    `os.urandom` (via the coincurve package) is used to generate randomness.

    :returns: a random hex encoded private key without `'0x'`-prefix.
    """
    return PrivateKey().to_hex()


def private_key_to_public_key(private_key):
    """Calculate the public key corresponding to a given private key.

    :param private_key: the private key, either hex encoded (with or without `'0x'`-prefix) or as
                        bytes
    :returns: the hex encoded
    """
    if not is_hex(private_key):
        private_key = encode_hex(private_key)
    private_key_object = PrivateKey.from_hex(remove_0x_prefix(private_key))
    public_key_object = private_key_object.public_key
    return encode_hex(public_key_object.format(compressed=False))


def private_key_to_address(private_key):
    """Calculate the address corresponding to a given private key.

    :param private_key: the private key, either hex encoded (with or without `'0x'`-prefix) or as
                        bytes
    :returns: the hex encoded
    """
    public_key = private_key_to_public_key(private_key)
    public_key_hash = keccak(decode_hex(public_key)[1:])
    address = to_checksum_address(public_key_hash[12:])
    return address
