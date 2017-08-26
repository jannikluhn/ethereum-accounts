import pytest

from eth_utils import (
    is_same_address,
    keccak
)

from eth_accounts import (
    Account,
    get_vrs,
    prepare_ethereum_message,
    recover_signer,
    sign,
    verify_signature,
)


@pytest.fixture
def account():
    return Account.from_private_key(1)


def test_sign(account):
    message = b'test'
    target = ('0xbb958903eb2617ebb142d54c20df2c4eb46159e2c717b0240037336418cb8ed3'
              '59f4d1342c037dd7bec0deacdbba00fac2fa9f50a51865bbe474bc706175675e00')

    signature = sign(message, account.private_key)
    assert signature == target

    # manual hashing
    message_hash = keccak(message)
    signature = sign(message_hash, account.private_key, hash=False)
    assert signature == target


def test_verification(account):
    message = b'test'
    signature = sign(message, account.private_key)
    assert verify_signature(signature, message, account.address)


def test_signer_recovery(account):
    message = b'test'
    signature = sign(message, account.private_key)
    signer = recover_signer(signature, message)
    assert is_same_address(signer, account.address)


def test_ethereum_message_preparation(account):
    message = b'test'
    target = ('0xfe28833983d6faa0715c7e8c3873c725ddab6fa5bf84d40e780676e463e6bea2'
              '0fc6aea97dc273a98eb26b0914e224c8dd5c615ceaab69ddddcf9b0ae3de0e371c')
    ethereum_message = prepare_ethereum_message(message)
    signature = sign(ethereum_message, account.private_key)
    assert signature == target


def test_vrs(account):
    message = b'test'
    signature = sign(message, account.private_key)
    v, r, s = get_vrs(signature)
    assert False  # TODO: target?
