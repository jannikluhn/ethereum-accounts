import pytest

from eth_utils import (
    is_checksum_address,
    is_same_address,
)

from eth_accounts import Account
from eth_accounts.utils import (
    private_key_to_address,
    private_key_to_public_key,
    random_private_key,
)


def test_new():
    account = Account.new()
    assert is_checksum_address(account.address)
    assert account.private_key is not None
    assert account.public_key == private_key_to_public_key(account.private_key)
    assert is_same_address(account.address, private_key_to_address(account.private_key))


def test_from_private_key():
    private_key = random_private_key()
    account = Account.from_private_key(private_key)
    assert account.public_key == private_key_to_public_key(private_key)
    assert account.address == private_key_to_address(private_key)
