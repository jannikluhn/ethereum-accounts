import pytest

from ethereum.utils import (
    privtoaddr,
    privtopub,
)

from eth_utils import (
    add_0x_prefix,
    encode_hex,
    decode_hex,
    is_0x_prefixed,
    is_checksum_address,
    is_hex,
    is_same_address,
)

from eth_accounts import (
    random_private_key,
    private_key_to_address,
    private_key_to_public_key,
)


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_random_private_key(key):
    assert not is_0x_prefixed(key)
    assert is_hex(key)
    assert len(key) == 64


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_private_key_to_public_key(key):
    # tests against pyethereum
    reference = encode_hex(privtopub(decode_hex(key)))
    public_key = private_key_to_public_key(key)
    assert is_0x_prefixed(public_key)
    assert is_hex(public_key)
    assert len(public_key) == 130 + 2
    assert public_key == reference
    assert private_key_to_public_key(decode_hex(key)) == reference
    assert private_key_to_public_key(add_0x_prefix(key)) == reference


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_private_key_to_address(key):
    # tests against pyethereum
    reference = encode_hex(privtoaddr(decode_hex(key)))
    address = private_key_to_address(key)
    assert is_0x_prefixed(address)
    assert is_hex(address)
    assert len(address) == 40 + 2
    assert is_same_address(address, reference)
    assert is_same_address(private_key_to_address(decode_hex(key)), reference)
    assert is_same_address(private_key_to_address(add_0x_prefix(key)), reference)
    assert is_checksum_address(address)
