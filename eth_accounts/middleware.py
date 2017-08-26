from cytoolz.dicttoolz import (
    assoc,
)
from eth_utils import (
    decode_hex,
    encode_hex,
    is_same_address,
)
import rlp

from .signing import (
    sign_transaction,
)
from .utils import (
    Transaction,
)


def construct_local_signing_middleware(account):

    def local_signing_middleware(make_request, web3):
        def middleware(method, params):

            def ignore():
                response = make_request(method, params)
                return response

            if account.is_locked():
                return ignore()

            if method != 'eth_sendTransaction':
                return ignore()

            transaction = params[0]
            if 'from' not in transaction:
                return ignore()
            sender = transaction['from']
            if not is_same_address(sender, account.address):
                return ignore()

            assert 'gas' in transaction  # TODO: handled by another middleware?
            assert 'gasPrice' in transaction  # TODO: default to something?

            if 'to' not in transaction:
                assoc(transaction, 'to', '0x')
            if 'value' not in transaction:
                assoc(transaction, 'value', 0)
            if 'data' not in transaction:
                assoc(transaction, 'data', '0x')
            if 'nonce' not in transaction:
                assoc(transaction, 'data', web3.eth.getTransactionCount(sender))

            # construct raw transaction
            network_id = 1  # TODO: wait for next version of web3.py to implement this
            # network_id = web3.net.version
            transaction_object = Transaction(
                transaction.get('nonce'),
                transaction.get('gasPrice'),
                transaction.get('gas'),
                decode_hex(transaction.get('to', '0x')),
                transaction.get('value', 0),
                decode_hex(transaction.get('data', '0x')),
                0,
                0,
                0
            )
            sign_transaction(transaction_object, account.private_key, network_id)
            raw_transaction_hex = encode_hex(rlp.encode(transaction_object))
            return make_request('eth_sendRawTransaction', [raw_transaction_hex])



        return middleware
    return local_signing_middleware
