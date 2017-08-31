import pytest

from eth_utils import (
    decode_hex,
    encode_hex,
    is_hex,
    is_same_address,
)
import rlp
from toolz import dissoc
from web3 import Web3
from web3.exceptions import CannotHandleRequest
from web3.providers import BaseProvider

from eth_accounts import (
    Account,
)
from eth_accounts.utils import Transaction


class RawTransactionValidator(BaseProvider):
    middlewares = []

    def __init__(self, validator):
        super().__init__()
        self.validator = validator

    def make_request(self, method, params):
        if method == 'eth_sendRawTransaction':
            assert len(params) == 1
            raw_tx_hex = params[0]
            assert is_hex(raw_tx_hex) and raw_tx_hex.startswith('0x')
            tx = rlp.decode(decode_hex(raw_tx_hex), Transaction)
            self.validator(tx)
            return {'result': True}
        else:
            raise CannotHandleRequest()

    def isConnected(self):
        return True


@pytest.fixture
def tester_provider():
    return Web3.EthereumTesterProvider()


@pytest.fixture
def validating_provider(transaction_dict, tester_provider):
    web3 = Web3(tester_provider)

    def validate(tx):
        transaction_dict.setdefault('from', web3.eth.defaultAccount)
        sender = web3.eth.getTransactionCount(transaction_dict['from'])
        transaction_dict.setdefault('nonce', sender)
        transaction_dict.setdefault('to', '0x')
        transaction_dict.setdefault('value', 0)
        transaction_dict.setdefault('gasPrice', web3.eth.gasPrice)
        transaction_dict.setdefault('data', '0x')

        assert tx.nonce == transaction_dict['nonce']
        assert tx.to == b'' or is_same_address(tx.to, transaction_dict['to'])
        assert tx.value == transaction_dict['value']
        if 'gas' in transaction_dict:
            assert tx.startgas == transaction_dict['gas']
        else:
            assert tx.startgas >= 21000  # should estimate something useful
        assert tx.gasprice == transaction_dict['gasPrice']
        assert encode_hex(tx.data) == transaction_dict['data']
    provider = RawTransactionValidator(validate)
    return provider


@pytest.fixture
def web3(validating_provider, tester_provider):
    web3 = Web3([validating_provider, tester_provider])
    return web3


@pytest.fixture
def account(web3):
    return Account.from_private_key(1)


@pytest.fixture
def other_account():
    return Account.from_private_key(2)


@pytest.fixture
def transaction_dict():
    return {
        'from': Account.from_private_key(1).address,
        'to': Account.from_private_key(2).address,
        'value': 1,
        'gas': 2,
        'gasPrice': 3,
        'data': '0xaabbcc',
        'nonce': 4
    }


@pytest.mark.parametrize('transaction_dict', [
    transaction_dict(),
    dissoc(transaction_dict(), 'nonce'),
    dissoc(transaction_dict(), 'to'),
    dissoc(transaction_dict(), 'value'),
    dissoc(transaction_dict(), 'gasPrice'),
    dissoc(transaction_dict(), 'gas'),
    dissoc(transaction_dict(), 'data'),
])
def test_defaults(web3, account, other_account, transaction_dict):
    web3.add_middleware(account.local_signing_middleware)
    web3.eth.sendTransaction(transaction_dict)
