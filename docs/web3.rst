Web3 Integration
================

Typically, accounts are managed by Ethereum clients such as Geth and Parity. Transaction templates
are sent to them via RPC calls (``eth_sendTransaction``), where they are signed them distributed to
the network. However, often this is not desired, especially if the client is remote and cannot be
trusted (e.g., Infura's publicly accessible nodes).

As an alternative, transactions can be created and signed locally and then sent via
``eth_sendRawTransaction``. To simplify this progress significantly, this package provides
middleware to `web3.py <https://github.com/pipermerriam/web3.py>`_, the canonical Python package
for communication with Ethereum nodes.

First, the middleware has to be registered:

>>> from web3 import Web3
>>> web3 = Web3()
>>> web3.add_middleware(account.local_signing_middleware)

Now, web3 can be used as usual, but all transactions originating from the account are signed
locally:

>>> web3.eth.sendTransaction({'from': account.address, 'to': '0x' + '00' * 20, value: 10**18})
>>> contract = web3.eth.contract(address=address, abi=abi)
>>> contract.transact({'from': account.adderss}).vote()

To extend this to other accounts, add them as middlewares as well:

>>> for account in [Account.new() for _ in range(10)]:
...     web3.add_midleware(account)

If for the specified sender no local signing middleware is registered, it goes through to the
remote node unmodified.
