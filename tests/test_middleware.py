import pytest

from web3 import (
    EthereumTesterProvider,
    Web3
)

from eth_accounts import (
    Account,
    construct_local_signing_middleware,
)

@pytest.fixture
def web3():
    provider = EthereumTesterProvider()
    web3 = Web3(provider)
    return web3


@pytest.fixture
def account(web3):
    account = Account.from_private_key(1)
    web3.eth.sendTransaction({'to': account.address, 'value': 100})
    return account


def test_middleware(web3, account):
    account = Account.from_private_key('0x4646464646464646464646464646464646464646464646464646464646464646')
    middleware = construct_local_signing_middleware(account)
    web3.add_middleware(middleware)
    web3.eth.sendTransaction({
        'from': '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F',
        'to': '0x3535353535353535353535353535353535353535',
        'value': 10**18,
        'gas': 21000,
        'gasPrice': 20 * 10**9,
        'data': b'',
        'nonce': 9
    })
