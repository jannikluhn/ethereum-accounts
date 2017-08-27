import pytest

from web3 import (
    EthereumTesterProvider,
    RPCProvider,
    Web3
)

from eth_accounts import (
    Account,
)


@pytest.fixture
def web3():
    #provider = EthereumTesterProvider()
    provider = RPCProvider('localhost', 8545)
    web3 = Web3(provider)
    return web3


@pytest.fixture
def account(web3):
    account = Account.from_private_key(1)
    import pudb.b
    web3.eth.sendTransaction({'to': account.address, 'value': 100})
    return account


def test_middleware(web3, account):
    private_key = '0x4646464646464646464646464646464646464646464646464646464646464646'
    account = Account.from_private_key(private_key)
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F',
        'to': '0x3535353535353535353535353535353535353535',
        'value': 10**18,
        'gas': 21000,
        'gasPrice': 20 * 10**9,
        'data': b'',
        'nonce': 9
    })
