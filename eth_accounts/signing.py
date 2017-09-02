from coincurve import (
    PrivateKey,
    PublicKey,
)

import rlp

from eth_utils import (
    big_endian_to_int,
    decode_hex,
    encode_hex,
    keccak,
    int_to_big_endian,
    remove_0x_prefix,
)

from .utils import (
    normalize_message,
    normalize_private_key,
    normalize_signature,
    public_key_to_address,
)


def sign_message(message, private_key, hash=True):
    """Sign a message using a private key.

    :param private_key: the private key that should be used to sign the message
    :param message: message to sign
    :param hash: if true, the message will be hashed before signing it
    :returns: the created signature
    """
    private_key = normalize_private_key(private_key)
    message = normalize_message(message)
    if hash:
        to_sign = keccak(message)
    else:
        to_sign = message
    private_key_object = PrivateKey.from_hex(remove_0x_prefix(private_key))
    signature = private_key_object.sign_recoverable(to_sign, hasher=None)
    return encode_hex(signature)


def recover_signer(signature, message, hash=True):
    """Return the address corresponding to the private key that has signed a message.

    :param signature: the signature to check
    :param message: the message that has been signed
    :param hash: true if the message has been hashed before it was signed, otherwise false
    """
    signature = normalize_signature(signature)
    message = normalize_message(message)
    if hash:
        message = keccak(message)
    public_key_object = PublicKey.from_signature_and_message(decode_hex(signature), message,
                                                             hasher=None)
    return public_key_to_address(public_key_object.format(compressed=False))


def prepare_ethereum_message(message):
    message = normalize_message(message)
    to_hash = b'\x19Ethereum Signed Message:\n' + bytes(str(len(message)), 'ascii') + message
    return to_hash


def sign_transaction(transaction, private_key, network_id):
    """Sign a transaction with a private key.

    .. warning::

        This method overwrites any potentially already existing signature.

    :param transaction: the transaction to sign as an :class:`rlp.Serializable` object
    :param private_key: the private key to sign with
    :param int network_id: the id of the target network
    :returns: the signed transaction
    """
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


def recover_sender(transaction, network_id):
    pass
