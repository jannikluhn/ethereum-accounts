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
