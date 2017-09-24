Encoding conventions
====================

First things first, we follow web3.py's `conventions
<https://web3py.readthedocs.io/en/latest/conventions.html>`_: We call strings either bytes
or text, depending on if they are binary (``b'test'``) or unicode (``u'test'`` or simply
``'test'``).

In general, `ethereum-accounts` returns data in consistent formats. On the other hand, it tries
to be as forgiving as possible when it comes to accepting data, but only if it can do so
unambigiously. If this is not possible, it raises an exception (typically a :exc:`ValueError` or
:exc:`TypeError`).

The return format of private keys, public keys, addresses, messages, and signatures is hex encoded
with a ``'0x'``-prefix. In addition, private keys are left-padded with zeros to a length of 32
bytes (or 64 characters + 2 for the prefix). Case is always lower, with the exception of addresses
which are checksummed according to `EIP-55
<https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md>`_.

The objects listed above are interpreted correctly when giving in one of the following formats:

1) hex encoded text (with or without ``'0x'``-prefix, case insensitive, not necessarily padded to
   the correct length, but of even length)
2) as bytes (not necessarily padded)

Private keys can also be specified as integers. If addresses are not all lower case, they are
interpreted as EIP-55-checksummed and rejected if the checksum is wrong.

Finally, passwords must always be given as bytes to avoid any decoding ambiguities.
