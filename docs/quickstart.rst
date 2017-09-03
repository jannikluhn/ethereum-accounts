Quickstart
==========

Installation
------------

::

    $ pip install ethereum-accounts


Account creation
----------------

    >>> from eth_accounts import Account
    >>> account = Account.from_private_key('0xff')
    >>> with open('tests/testdata/pbkdf2_keystore_template.json') as f:
    ...     another_account = Account.from_keystore(f, b'password')
    ...
    >>> third_account = Account.new()  # with random private key

    >>> account.private_key
    '0x00000000000000000000000000000000000000000000000000000000000000ff'
    >>> account.address
    '0x5044a80bD3eff58302e638018534BbDA8896c48A'



Message signing
---------------

    >>> from eth_accounts import prepare_ethereum_message, recover_signer
    >>> message = prepare_ethereum_message(b'Do it.')
    >>> signature = account.sign_message(message)

    >>> recover_signer(signature, message)
    '0x5044a80bD3eff58302e638018534BbDA8896c48A'
    >>> account.is_signer(signature, message)
    True


Web3 integration
----------------

    >>> from web3 import Web3
    >>> web3 = Web3(Web3.RPCProvider())
    >>> web3.add_middleware(account.local_signing_middleware)
    >>> web3.eth.sendTransaction({
    ...     'from': account.address,
    ...     'to': another_account.address,
    ...     'value': 100
    ... })  # will be signed locally and subsequently sent to the node
