import pytest

from eth_utils import (
    encode_hex,
    is_same_address,
    keccak,
    remove_0x_prefix,
)

from eth_accounts import (
    Account,
    prepare_ethereum_message,
    recover_signer,
    sign_message,
)


@pytest.fixture
def account():
    return Account.from_private_key(1)


def test_sign(account):
    message = b'test'
    target = ('0xbb958903eb2617ebb142d54c20df2c4eb46159e2c717b0240037336418cb8ed3'
              '59f4d1342c037dd7bec0deacdbba00fac2fa9f50a51865bbe474bc706175675e00')

    signature = sign_message(message, account.private_key)
    assert signature == target

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


def test_ethereum_message_preparation(account):
    message = b'test'
    ethereum_message = prepare_ethereum_message(message)
    assert ethereum_message == b'\x19Ethereum Signed Message:\n4test'
    assert prepare_ethereum_message(encode_hex(message)) == ethereum_message
    assert prepare_ethereum_message(remove_0x_prefix(encode_hex(message))) == ethereum_message
