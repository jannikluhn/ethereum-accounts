from coincurve import (
    PrivateKey,
    PublicKey,
)

import rlp

from eth_utils import (
    big_endian_to_int,
    decode_hex,
    encode_hex,
    force_bytes,
    keccak,
    int_to_big_endian,
    is_same_address,
    remove_0x_prefix,
)

from .utils import (
    normalize_private_key,
    normalize_signature,
    public_key_to_address,
)


def sign_message(message, private_key, hash=True, encoding='iso-8859-1'):
    """Sign a message using a private key.

    :param private_key: the hex encoded private key that should be used to sign the message
    :param message: the hex encoded message to sign
    :param hash: if true, the message will be hashed before signing it
    :returns: the hex encoded, '0x'-prefixed signature
    """
    private_key = normalize_private_key(private_key)
    message = force_bytes(message, encoding)

    if hash:
        to_sign = keccak(message)
    else:
        to_sign = message

    private_key_object = PrivateKey.from_hex(remove_0x_prefix(private_key))
    signature = private_key_object.sign_recoverable(to_sign, hasher=None)
    return encode_hex(signature)


def recover_signer(signature, message, hash=True, encoding='iso-8859-1'):
    """Return the address corresponding to the private key that has signed a message."""
    signature = normalize_signature(signature)
    message = force_bytes(message, encoding)
    if hash:
        message = keccak(message)
    public_key_object = PublicKey.from_signature_and_message(decode_hex(signature), message,
                                                             hasher=None)
    return public_key_to_address(public_key_object.format(compressed=False))


def verify_signature(signature, message, address, hash=True, encoding='iso-8859-1'):
    """Verify that a message has been signed by the owner of an account.

    :param signature: the signature to verify
    :param message: the message that has been signed
    :param address: the address of the assumed owner
    :param hash: if `True` it is assumed that the message has been hashed before signing it
    :param encoding: if the message is passed in form of a string, it is decoded according to this
                     encoding
    :returns: `True` or `False`
    """
    signer = recover_signer(signature, message, hash, encoding)
    return is_same_address(signer, address)


def prepare_ethereum_message(message, encoding='iso-8859-1'):
    message = force_bytes(message, encoding)
    to_hash = b'\x19Ethereum Signed Message:\n' + int_to_big_endian(len(message)) + message
    return to_hash


def sign_transaction(transaction, private_key, network_id):
    transaction.v = network_id
    transaction.r = 0
    transaction.s = 0
    transaction_rlp = rlp.encode(transaction)
    v, r, s = get_vrs(sign_message(transaction_rlp, private_key))
    transaction.v = v + network_id * 2 + 35
    transaction.r = r
    transaction.s = s


def get_vrs(signature):
    signature = decode_hex(normalize_signature(signature))
    r = signature[:32]
    s = signature[32:64]
    v = signature[64:]
    return tuple(big_endian_to_int(x) for x in [v, r, s])
