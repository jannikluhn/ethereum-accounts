Web3 Integration
================

Typically, accounts are managed by Ethereum clients such as Geth and Parity. Transaction templates
are sent to them via RPC calls (``eth_sendTransaction``), where they are signed and subsequently
distributed to the network. However, often this is not desired, especially if the client is remote
and cannot be trusted (e.g., Infura's publicly accessible nodes).

As an alternative, transactions can be created and signed locally and then sent via
``eth_sendRawTransaction``. To simplify this progress, this package provides middleware for
`web3.py <https://github.com/pipermerriam/web3.py>`_, the canonical Python package for
communication with Ethereum nodes.

In order to use this feature, the middleware has to be registered first:

    >>> from web3 import Web3
    >>> web3 = Web3(Web3.RPCProvider())
    >>> web3.add_middleware(account.local_signing_middleware)

Now, web3 can be used as usual, but all transactions originating from the account are signed
locally:

    >>> from eth_utils import denoms
    >>> other_account = Account.from_private_key('0xaa')
    >>> web3.eth.sendTransaction({
    ...     'from': account.address,
    ...     'to': other_account.address,
    ...     'value': 10 * denoms.finney
    ... })
    '0xcb34b55f681a226b994cee10553978952ff82f5bc731a97131ce2b361e42ad75'
    >>> web3.eth.getBalance(other_account.address) / denoms.finney
    10.0

    >>> token_contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    >>> token_contract.transact({'from': account.address}).transfer(other_account.address, 100000)
    '0xde029a35e40809757ddd22a98a0e62da419e4f791eed20846a1eedad42a93c46'
    >>> token_contract.call().balanceOf(other_account.address)
    100000

To extend this to other accounts, add them as middlewares as well:

    >>> for account in [Account.new() for _ in range(10)]:
    ...     web3.add_midleware(account)

If for the specified sender no local signing middleware is registered, it goes through to the
remote node unmodified.
