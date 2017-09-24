import pytest

from eth_utils import (
    decode_hex,
    is_hex,
)
import rlp
from web3 import Web3
from web3.exceptions import CannotHandleRequest
from web3.providers import BaseProvider

from eth_accounts import Account
from eth_accounts.utils import Transaction


class CallbackProvider(BaseProvider):

    def __init__(self, raw_tx_callback=None, send_tx_callback=None, other_callback=None):
        self.raw_tx_callback = raw_tx_callback
        self.send_tx_callback = send_tx_callback
        self.other_callback = other_callback
        self.raw_tx_received = False
        self.other_received = False
        self.send_tx_received = False

    def make_request(self, method, params):
        if method == 'eth_sendRawTransaction':
            assert len(params) == 1
            raw_tx_hex = params[0]
            assert is_hex(raw_tx_hex) and raw_tx_hex.startswith('0x')
            tx = rlp.decode(decode_hex(raw_tx_hex), Transaction)
            if self.raw_tx_callback:
                self.raw_tx_callback(tx)
            self.raw_tx_received = True
            return {'result': True}
        elif method == 'eth_sendTransaction':
            assert len(params) == 1
            if self.send_tx_callback:
                self.send_tx_callback(params[0])
            self.send_tx_received = True
            return {'result': True}
        else:
            if self.other_callback:
                self.other_callback(method, params)
            self.other_received = True
            raise CannotHandleRequest()


@pytest.fixture
def tester_provider():
    return Web3.EthereumTesterProvider()


@pytest.fixture
def account():
    return Account.from_private_key(1)


@pytest.fixture
def other_account():
    return Account.from_private_key(2)


def test_tx_gasprice(tester_provider, account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.gasprice != 123 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0,
        'gasPrice': 123
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    gasprice = web3.eth.gasPrice
    callback_provider = CallbackProvider(lambda tx: pytest.fail()
                                         if tx.gasprice != gasprice else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received


def test_tx_value(tester_provider, account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.value != 123 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.eth.blockNumber
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0,
        'value': 123
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.value != 0 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received


def test_tx_data(tester_provider, account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.data != b'\xff' else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0,
        'data': '0xff'
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.data != b'' else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received


def test_tx_receiver(tester_provider, account, other_account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail()
                                         if tx.to != decode_hex(other_account.address) else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0,
        'to': other_account.address
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.to != b'' else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received


def test_tx_nonce(tester_provider, account, other_account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.nonce != 5 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0,
        'nonce': 5
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    # TODO: sent some transactions so that default nonce isn't 0 (requires tester to understand
    # replay protected transactions, or this package to be able to send classical transactions)
    nonce = 0
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.nonce != nonce else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received


def test_tx_sender(tester_provider, account, other_account):
    web3 = Web3([tester_provider])
    network_id = int(web3.version.network)

    # explicit sender
    callback_provider = CallbackProvider(lambda tx: pytest.fail()
                                         if not account.is_sender(tx, network_id) else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    # implicit sender from default account
    callback_provider = CallbackProvider(lambda tx: pytest.fail()
                                         if not account.is_sender(tx, network_id) else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.eth.defaultAccount = account.address
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 0
    })
    assert callback_provider.raw_tx_received
    assert not callback_provider.send_tx_received

    # explicit unknown sender
    callback_provider = CallbackProvider(pytest.fail)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': other_account.address,
        'gas': 21000
    })
    assert not callback_provider.raw_tx_received
    assert callback_provider.send_tx_received

    # implicit unknown sender
    callback_provider = CallbackProvider(pytest.fail)
    web3 = Web3([callback_provider, tester_provider])
    web3.eth.defaultAccount = other_account.address
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'gas': 21000
    })
    assert not callback_provider.raw_tx_received
    assert callback_provider.send_tx_received


@pytest.mark.xfail(reason='web3 estimates gas automatically')
def test_tx_gas(tester_provider, account):
    callback_provider = CallbackProvider(lambda tx: pytest.fail()
                                         if tx.startgas != 21123 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'gas': 21123
    })
    assert callback_provider.raw_tx_received

    # should estimate something if no gas is provided
    callback_provider = CallbackProvider(lambda tx: pytest.fail() if tx.nonce > 21000 else None)
    web3 = Web3([callback_provider, tester_provider])
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction({
        'from': account.address,
        'data': b'\xff\xaa\xff'
    })
    assert callback_provider.raw_tx_received
