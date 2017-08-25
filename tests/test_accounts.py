import pytest

from eth_accounts import Account, random_private_key


def test_equality():
    private_key1 = random_private_key()
    private_key2 = random_private_key()
    account1 = Account.from_private_key(private_key1)
    account2a = Account.from_private_key(private_key2)
    account2b = Account.from_private_key(private_key2)
    assert account1 == account1
    assert account1 != account2a
    assert account1 != account2b
    assert account2a == account2b
    assert account1 != private_key1
    account1.lock()
    with pytest.raises(ValueError):
        account1 == account2a
    with pytest.raises(ValueError):
        account2a == account1
    account1.unlock()
