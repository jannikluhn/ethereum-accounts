import pytest
import rlp

from eth_utils import (
    decode_hex,
    encode_hex,
    is_same_address,
    keccak,
    remove_0x_prefix,
)

from eth_accounts import (
    Account,
    prepare_ethereum_message,
    recover_sender,
    recover_signer,
    sign_message,
)
from eth_accounts.utils import (
    Transaction
)


@pytest.fixture
def account():
    return Account.from_private_key(1)


def test_sign_message(account):
    message = b'test'
    target = ('0xbb958903eb2617ebb142d54c20df2c4eb46159e2c717b0240037336418cb8ed3'
              '59f4d1342c037dd7bec0deacdbba00fac2fa9f50a51865bbe474bc706175675e00')

    signature = sign_message(message, account.private_key)
    assert signature == target
    assert account.sign_message(message) == target

    assert sign_message(encode_hex(message), account.private_key) == signature
    assert sign_message(remove_0x_prefix(encode_hex(message)), account.private_key) == signature

    # manual hashing
    message_hash = keccak(message)
    signature = sign_message(message_hash, account.private_key, hash=False)
    assert signature == target


def test_signer_recovery(account):
    message = b'test'
    signature = sign_message(message, account.private_key)
    signer = recover_signer(signature, message)
    assert is_same_address(signer, account.address)
    assert account.is_signer(signature, message)


def test_ethereum_message_preparation():
    message = b'test'
    ethereum_message = prepare_ethereum_message(message)
    assert ethereum_message == b'\x19Ethereum Signed Message:\n4test'
    assert prepare_ethereum_message(encode_hex(message)) == ethereum_message
    assert prepare_ethereum_message(remove_0x_prefix(encode_hex(message))) == ethereum_message


def test_sign_transaction(account):
    tx = Transaction(0, 1, 2, bytes(20), 3, b'\ff', 0, 0, 0)
    account.sign_transaction(tx, 14)
    v, r, s = tx.v, tx.r, tx.s
    assert v != 0 and r != 0 and s != 0
    assert account.is_sender(tx, 14)
    recovered_sender = recover_sender(tx, 14)
    assert is_same_address(recovered_sender, account.address)
    with pytest.raises(ValueError):
        recover_sender(tx, 13)
    account.sign_transaction(tx, 13)
    assert (v, r, s) != (tx.v, tx.r, tx.s)


def test_invalid_signatures(account):
    txs = [rlp.decode(decode_hex(rlp_data), Transaction) for rlp_data in [
        # ttFrontier
        '0xf865030182520894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a825544847fffffffa098ff92120155'
        '4726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c18'
        '20f9231f98a962b210e3ac2452a3',
        '0xf85f030182520894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a801ca098ff921201554726367d2be8'
        'c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c1820f9231f98a9'
        '62b210e3ac2452a3',
        '0xf8638080830f424094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffffffffffffffff'
        'ffffffffffffffffffffffffffffffffffffffffffffffffa0badf00d70ec28c94a3b55ec771bcbc70778d6ee0'
        'b51ca7ea9514594c861b1884',
        # ttEIP158
        '0xf869030182520894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a82554488ffffffffffffff1ca098ff'
        '921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8095f789dd4c743'
        'dfe42c1820f9231f98a962b210e3ac2452a3',
        '0xf865030182520894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a825544847fffffffa098ff92120155'
        '4726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c18'
        '20f9231f98a962b210e3ac2452a3',
        '0xf8638080830f424094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffffffffffffffff'
        'ffffffffffffffffffffffffffffffffffffffffffffffffa0badf00d70ec28c94a3b55ec771bcbc70778d6ee0'
        'b51ca7ea9514594c861b1884'
    ]]
    for tx in txs:
        with pytest.raises(ValueError):
            recover_sender(tx, 1)
    tx = Transaction(0, 1, 2, bytes(20), 3, b'\ff', 0, 0, 0)
    account.sign_transaction(tx, 1)
    with pytest.raises(ValueError):
        recover_sender(tx, 42)
