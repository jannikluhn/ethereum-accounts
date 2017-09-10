import pytest

from ethereum.utils import (
    privtoaddr,
    privtopub,
)

from eth_utils import (
    remove_0x_prefix,
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
    public_key_to_address,
)
from eth_accounts.utils import (
    normalize_message,
    normalize_password,
    normalize_private_key,
    normalize_public_key,
    normalize_signature,
)


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_random_private_key(key):
    assert is_hex(key)
    assert is_0x_prefixed(key)
    assert len(key) == 64 + 2


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
    assert private_key_to_public_key(remove_0x_prefix(key)) == reference


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_private_key_to_address(key):
    # tests against pyethereum
    reference = encode_hex(privtoaddr(decode_hex(key)))
    address = private_key_to_address(key)
    assert is_0x_prefixed(address)
    assert is_checksum_address(address)
    assert is_same_address(address, reference)
    assert is_same_address(private_key_to_address(decode_hex(key)), reference)
    assert is_same_address(private_key_to_address(remove_0x_prefix(key)), reference)


@pytest.mark.parametrize('key', [random_private_key() for _ in range(100)])
def test_public_key_to_address(key):
    # tests against pyethereum
    public_key = encode_hex(privtopub(decode_hex(key)))
    reference = privtoaddr(decode_hex(key))
    address = public_key_to_address(public_key)
    assert is_0x_prefixed(address)
    assert is_checksum_address(address)
    assert is_same_address(address, reference)
    assert is_same_address(public_key_to_address(decode_hex(public_key)), reference)
    assert is_same_address(public_key_to_address(remove_0x_prefix(public_key)), reference)


@pytest.mark.parametrize(('input', 'output', 'error'), [
    ('0x0000000000000000000000000000000000000000000000000000000000000000', None, ValueError),
    ('0x0000000000000000000000000000000000000000000000000000000000000001', None, None),
    ('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', None, None),
    ('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', None, ValueError),
    ('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'.upper(),
     '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', None),
    ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', None),
    (-1, None, ValueError),
    (0, None, ValueError),
    (1, '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140,
     '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
     None),
    (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, None, ValueError),
    ('0x01', '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    ('0x000000000000000000000000000000000000000000000000000000000000000001',
     '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    (b'\0', None, ValueError),
    (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', None, ValueError),
    (b'\x01', '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
     '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
     '0x0000000000000000000000000000000000000000000000000000000000000001', None),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba'
     b'\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06A@',
     '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', None),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba'
     b'\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06AA', None, ValueError),
    (None, None, TypeError),
    (1.0, None, TypeError),
    ([], None, TypeError)
])
def test_private_key_normalization(input, output, error):
    if error is None:
        if output is None:
            output = input
        assert output == normalize_private_key(input)
    else:
        with pytest.raises(error):
            normalize_private_key(input)


@pytest.mark.parametrize(['input', 'output', 'error'], [
    ('0x0000000000000000000000000000000000000000000000000000000000000000'
     '000000000000000000000000000000000000000000000000000000000000000000', None, None),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, None),
    ('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
     'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, ValueError),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, ValueError),
    (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
     '0x0000000000000000000000000000000000000000000000000000000000000000'
     '000000000000000000000000000000000000000000000000000000000000000000',
     None),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
     '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
     None, ValueError),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
     b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
     None, ValueError),
    (None, None, TypeError),
    (5, None, TypeError),
    (5.0, None, TypeError),
    ([], None, TypeError)
])
def test_public_key_normalization(input, output, error):
    if error is None:
        if output is None:
            output = input
        assert output == normalize_public_key(input)
    else:
        with pytest.raises(error):
            normalize_public_key(input)


@pytest.mark.parametrize(['input', 'output', 'error'], [
    (b'', None, None),
    (b'password', None, None),
    ('password', None, TypeError),
    (None, None, TypeError),
    (5, None, TypeError),
    (5.0, None, TypeError),
    ([], None, TypeError),
    ([b'password'], None, TypeError)
])
def test_password_normalization(input, output, error):
    if error is None:
        if output is None:
            output = input
        assert output == normalize_password(input)
    else:
        with pytest.raises(error):
            normalize_password(input)


@pytest.mark.parametrize(['input', 'output', 'error'], [
    (b'', None, None),
    (b'message', None, None),
    ('0xabcd', b'\xab\xcd', None),
    ('abcd', b'\xab\xcd', None),
    ('0xAbCd', b'\xab\xcd', None),
    (None, None, TypeError),
    (5, None, TypeError),
    (5.0, None, TypeError),
    ([], None, TypeError),
    ([b'message'], None, TypeError)
])
def test_message_normalization(input, output, error):
    if error is None:
        if output is None:
            output = input
        assert output == normalize_message(input)
    else:
        with pytest.raises(error):
            normalize_message(input)


@pytest.mark.parametrize(['input', 'output', 'error'], [
    ('0x0000000000000000000000000000000000000000000000000000000000000000'
     '000000000000000000000000000000000000000000000000000000000000000000', None, None),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, None),
    ('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
     'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, ValueError),
    ('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None, ValueError),
    (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
     '0x0000000000000000000000000000000000000000000000000000000000000000'
     '000000000000000000000000000000000000000000000000000000000000000000',
     None),
     (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
      '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', None),
     (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
      None, ValueError),
     (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
      b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
      None, ValueError),
     (None, None, TypeError),
     (5, None, TypeError),
     (5.0, None, TypeError),
     ([], None, TypeError)
])
def test_signature_normalization(input, output, error):
    if error is None:
        if output is None:
            output = input
        assert output == normalize_signature(input)
    else:
        with pytest.raises(error):
            normalize_signature(input)
