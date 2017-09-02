Signatures
==========

The purpose of Ethereum accounts is to sign messages. Most generally, this task is fulfilled by
:meth:`Account.sign_message` which either takes the message as bytes or hex encoded:

    >>> signature = account.sign_message(b'do it')
    >>> signature
    '0xdc1b25b5085ee83fcabed1c08902e42755aa94eb4f89c1c5def1b995911218014c3dc5ce9d5ec7f1b481a07a7bbab1abed7b30c1411f4e9728be50e9a1054f0000'
    >>> from eth_utils import encode_hex
    >>> assert account.sign_message(encode_hex(b'do it')) == signature

Commonly, the message is hashed before signing. If you'd like you can do this by yourself:

    >>> from eth_utils import keccak
    >>> hashed_message = keccak(b'do it')
    >>> assert signature == account.sign_message(hashed_message, hash=False)

In some cases, human readable text is to be signed. Instead of passing it directly (where it would
be interpreted as hex and hopefully lead to an exception), encode it first:

    >>> import codecs
    >>> message = codecs.encode('Drö Chönösön möt döm Köntröböss', 'utf-8')
    >>> signature = account.sign_message(message)

To subsequently validate a signature two methods are available: :meth:`Account.is_signer` checks
if the account has signed the message and :func:`recover_signer` returns the signer's address.

    >>> from eth_accounts import recover_signer
    >>> from eth_utils import is_same_address
    >>> assert account.is_signer(signature, message)
    >>> assert is_same_address(recover_signer(signature, message), account.address)

Following the signing function, here ``hash=False`` can be specified as well.

Often, not arbitrary messages but Ethereum transactions are to be signed. Of this,
:meth:`Account.sign_transaction` takes care. It expects the unsigned transaction to be passed as
`RLP-serializable object <https://github.com/ethereum/pyrlp>`_, implemented for example in
`pyethereum <https://github.com/ethereum/pyethereum>`_ or in a basic form in this package. Finally,
due to replay protection according to `EIP-155
<https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md>`_ the target network id has to be
specified:

    >>> from eth_accounts import Transaction
    >>> from eth_utils import decode_hex
    >>> tx = Transaction(
    ...     nonce=0,
    ...     gasprice=30 * 10**9,
    ...     startgas=21000,
    ...     to=decode_hex('0x' + 20 * '00'),
    ...     value=10**18,
    ...     data=b'',
    ...     v=0, r=0, s=0  # the signature to calculate
    ... )
    >>> account.sign_transaction(tx, network_id=1)  # main net
    >>> tx.v, tx.r, tx.s
    (37, 58532937890638004285825567298708718952681745693284428409123298183772432557576, 801127928671903595963053020012875996438042864362744490000919671501425252166)

Validating the signer of a transaction is faciliated by :meth:`Account.is_sender` and
:func:`recover_sender`:

    >>> assert account.is_sender(tx, network_id=1)
    >>> from eth_accounts import recover_sender
    >>> assert is_same_address(recover_sender(tx, network_id=1), account.address)
