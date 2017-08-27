# Ethereum Accounts

This is a Python library for working with Ethereum accounts. Its main features are keystore import
and export, as well as message and transaction signing. Seemless integration into
[web3.py](https://github.com/pipermerriam/web3.py) using its middleware API allows sending
transactions even if the RPC node does not manage the user's private keys.

## Installation

```Python
pip install ethereum-accounts
```

## Documentation

Start with the examples below to get a first impression. Subsequently, find more extensive docs
[here](#).

## Demo

### Account creation
```Python
In [1]: from eth_accounts import Account

In [2]: account = Account.new()  # with newly generated private key

In [3]: account.private_key, account.address
Out[3]:
('0xbfe1666eff25ea9929ec61d3e4a80395af9361b3f77cf52f044ef8df58fa257d',
 '0x89193d7Df9990e69F248751fA18d7DE7B855B25b')

In [4]: other_account = Account.from_private_key('0xabababababababababababababababababababababababababab
   ...: abababababab')

In [5]: third_account = Account.from_keystore('keystore.json')
```

## Message signing

```Python
In [6]: from eth_accounts import prepare_ethereum_message, recover_signer

In [7]: message = prepare_ethereum_message(b'Do it.'); print(message)
b'\x19Ethereum Signed Message:\n\x06Do it.'

In [8]: signature = account.sign_message(message); print(signature)
0x60df6f3983822a535d542abccbfb864a5aeebd9eac391b0bd22baeb86daf30ef1df2564c85aeb745f280eb82d5e5fc9d0b2276e5095656a2de6a0fd7249905f701

In [9]: recover_signer(signature, message)
Out[9]: '0x89193d7Df9990e69F248751fA18d7DE7B855B25b'

In [10]: account.is_signer(signature, message)
Out[10]: True
```


### Web3 integration

```Python
In [11]: from web3 import Web3, RPCProvider

In [12]: web3 = Web3(RPCProvider())

In [13]: web3.add_middleware(account.local_signing_middleware)

In [14]: web3.eth.sendTransaction({
             'from': account.address,
             'to': other_account.address,
             'value': 100
         })  # will be signed locally and subsequently sent to the node
```
