Encoding conventions
====================

First things first, we follow web3.py's `conventions
<https://web3py.readthedocs.io/en/latest/conventions.html>`_: We call strings either bytes
or text, depending if they are binary (``b'test'``) or unicode (``u'test'`` or simply ``'test'``).

In general, `ethereum-accounts` returns data in a consistent formats that is mostly human readable.
On the other hand, it tries to be as forgiving as possible when it comes to accepting data, but
only if it can do so unambigiously. If this is not possible, it raises exceptions.

This package deals mainly with five different kinds of string representable data:


Private keys
------------

Private keys are returned in all lower case, hex encoded form with a `'0x'`-prefix. This format is
less commonly used the Ethereum community than the unprefixed one, but it is more consistent with
other hex encoded data representations. Most parsers should condone it anyways. Furthermore,
private keys will be left padded with zeros to a length of 32 bytes (or 64 characters + 2 for the
prefix). Example::

  '0x0000000000000000000000000000000000000000000000000000000000aabbcc'

On the other hand, private keys are recognized in three different formats, discussed in the
following.

1) hex encoded text (with or without ``'0x'``-prefix, case insensitive, not necessarily padded, but
   of even length)
2) as bytes (not necessaryly padded)
3) as integer

Examples::

  '00aabbcc'
  b'\0\xaa\xbb\xcc'
  11189196

.. note::

  secp256k1, the elliptic curve employed by Ethereum, restricts private keys to a certain range:
  They must be between 1 (inclusive) and roughly 1.15 * 10^77.


Public keys
-----------


Addresses
---------

Addresses will always be returned hex encoded, `'0x'`-prefixed and EIP55-checksummed format.


Messaages
---------

Messages must be provided either as bytes or hex encoded text. They are output as bytes.


Signatures
----------

Signatures are `'0x'`-prefixed, hex encoded and all lowercase, but can also be provided without
prefix or any-case, as well as as bytes.
